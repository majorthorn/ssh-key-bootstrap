package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"vibe-ssh-lift/providers"
)

// TestNormalizeHost verifies ports/default handling across host inputs.
func TestNormalizeHost(testContext *testing.T) {
	testContext.Parallel()

	testCases := []struct {
		name             string
		inputHost        string
		defaultPort      int
		expectedHostPort string
		expectError      bool
	}{
		{"hostOnly", "example.com", 22, "example.com:22", false},
		{"withPort", "host:2222", 22, "host:2222", false},
		{"ipv6", "[2001:db8::1]", 2022, "[2001:db8::1]:2022", false},
		{"empty", "   ", 22, "", true},
	}

	for _, testCase := range testCases {
		testCase := testCase
		testContext.Run(testCase.name, func(subTestContext *testing.T) {
			subTestContext.Parallel()

			actualHostPort, normalizeErr := normalizeHost(testCase.inputHost, testCase.defaultPort)
			if testCase.expectError {
				if normalizeErr == nil {
					subTestContext.Fatalf("expected error")
				}
				return
			}

			if normalizeErr != nil {
				subTestContext.Fatalf("unexpected error: %v", normalizeErr)
			}

			if actualHostPort != testCase.expectedHostPort {
				subTestContext.Fatalf("got %q want %q", actualHostPort, testCase.expectedHostPort)
			}
		})
	}
}

// TestResolveHostsNoInput asserts error when no host sources are provided.
func TestResolveHostsNoInput(testContext *testing.T) {
	testContext.Parallel()

	if _, resolveErr := resolveHosts("", "", 22); resolveErr == nil {
		testContext.Fatalf("expected error without hosts")
	}
}

// TestDefaultSecretProvidersRegistered guards the side-effect provider bootstrap wiring.
func TestDefaultSecretProvidersRegistered(testContext *testing.T) {
	testContext.Parallel()

	if len(providers.DefaultProviders()) == 0 {
		testContext.Fatalf("expected at least one registered default secret provider")
	}
}

// TestValidateOptionsPasswordSecretRefResolves ensures secret refs can hydrate password input.
func TestValidateOptionsPasswordSecretRefResolves(testContext *testing.T) {
	testContext.Parallel()

	originalResolver := resolvePasswordFromSecretRef
	resolvePasswordFromSecretRef = func(secretRef string) (string, error) {
		if secretRef != "bw://ssh-prod-password" {
			testContext.Fatalf("unexpected secret ref: %q", secretRef)
		}
		return "resolved-password", nil
	}
	testContext.Cleanup(func() { resolvePasswordFromSecretRef = originalResolver })

	programOptions := &options{
		Port:              defaultSSHPort,
		TimeoutSec:        defaultTimeoutSeconds,
		PasswordSecretRef: "bw://ssh-prod-password",
	}
	if validateErr := validateOptions(programOptions); validateErr != nil {
		testContext.Fatalf("validate options: %v", validateErr)
	}
	if programOptions.Password != "resolved-password" {
		testContext.Fatalf("password was not resolved from secret ref")
	}
}

// TestValidateOptionsPasswordSecretRefConflict ensures direct password and secret refs are mutually exclusive.
func TestValidateOptionsPasswordSecretRefConflict(testContext *testing.T) {
	testContext.Parallel()

	programOptions := &options{
		Port:              defaultSSHPort,
		TimeoutSec:        defaultTimeoutSeconds,
		Password:          "plaintext",
		PasswordSecretRef: "bw://ssh-prod-password",
	}
	if validateErr := validateOptions(programOptions); validateErr == nil {
		testContext.Fatalf("expected conflict error")
	}
}

// TestExtractSingleKey validates that only one non-comment key line is kept.
func TestExtractSingleKey(testContext *testing.T) {
	testContext.Parallel()

	testCases := []struct {
		name                 string
		inputKeyText         string
		expectError          bool
		expectedExtractedKey string
	}{
		{"single", "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIE", false, "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIE"},
		{"multi", "ssh-ed25519 A\nssh-ed25519 B", true, ""},
		{"empty", "  \n# comment", true, ""},
	}

	for _, testCase := range testCases {
		testCase := testCase
		testContext.Run(testCase.name, func(subTestContext *testing.T) {
			extractedKey, extractErr := extractSingleKey(testCase.inputKeyText)
			if testCase.expectError {
				if extractErr == nil {
					subTestContext.Fatalf("expected error")
				}
				return
			}
			if extractErr != nil {
				subTestContext.Fatalf("unexpected error: %v", extractErr)
			}
			if extractedKey != testCase.expectedExtractedKey {
				subTestContext.Fatalf("got %q want %q", extractedKey, testCase.expectedExtractedKey)
			}
		})
	}
}

// TestResolveHosts ensures combined sources deduplicate, normalize, and sort hosts.
func TestResolveHosts(testContext *testing.T) {
	testContext.Parallel()

	actualHosts, resolveErr := resolveHosts("hostC", "hostA,hostB:2222,hostA", 22)
	if resolveErr != nil {
		testContext.Fatalf("resolve hosts: %v", resolveErr)
	}

	expectedHosts := []string{"hostA:22", "hostB:2222", "hostC:22"}
	if !reflect.DeepEqual(actualHosts, expectedHosts) {
		testContext.Fatalf("got %v want %v", actualHosts, expectedHosts)
	}
}

// TestResolvePublicKeyInline ensures inline key text is parsed and validated.
func TestResolvePublicKeyInline(testContext *testing.T) {
	testContext.Parallel()

	inlinePublicKey := generateTestKey(testContext)
	resolvedPublicKey, resolveErr := resolvePublicKey(inlinePublicKey)
	if resolveErr != nil {
		testContext.Fatalf("resolve inline key: %v", resolveErr)
	}
	if resolvedPublicKey == "" {
		testContext.Fatalf("empty key")
	}
}

// TestResolvePublicKeyFile ensures file-based keys are read and validated.
func TestResolvePublicKeyFile(testContext *testing.T) {
	testContext.Parallel()

	publicKeyFileContent := generateTestKey(testContext)
	tempDirectory := testContext.TempDir()
	publicKeyPath := filepath.Join(tempDirectory, "key.pub")
	if writeErr := os.WriteFile(publicKeyPath, []byte(publicKeyFileContent), 0o600); writeErr != nil {
		testContext.Fatalf("write key: %v", writeErr)
	}

	resolvedPublicKey, resolveErr := resolvePublicKey(publicKeyPath)
	if resolveErr != nil {
		testContext.Fatalf("resolve file key: %v", resolveErr)
	}
	if resolvedPublicKey == "" {
		testContext.Fatalf("empty key")
	}
}

// TestResolvePublicKeyMissingInput ensures missing key input is rejected.
func TestResolvePublicKeyMissingInput(testContext *testing.T) {
	testContext.Parallel()

	if _, resolveErr := resolvePublicKey(""); resolveErr == nil {
		testContext.Fatalf("expected error when key input is empty")
	}
}

// TestResolvePublicKeyInvalidInputPaths validates non-key and malformed file cases.
func TestResolvePublicKeyInvalidInputPaths(testContext *testing.T) {
	testContext.Parallel()

	testContext.Run("missing file", func(subTestContext *testing.T) {
		_, resolveErr := resolvePublicKey("/definitely/missing/public-key.pub")
		if resolveErr == nil {
			subTestContext.Fatalf("expected missing-file error")
		}
		if !strings.Contains(resolveErr.Error(), "expected a public key or readable file path") {
			subTestContext.Fatalf("unexpected error: %v", resolveErr)
		}
	})

	testContext.Run("invalid key in file", func(subTestContext *testing.T) {
		tempDirectory := subTestContext.TempDir()
		invalidPublicKeyPath := filepath.Join(tempDirectory, "invalid.pub")
		if writeErr := os.WriteFile(invalidPublicKeyPath, []byte("not-a-public-key\n"), 0o600); writeErr != nil {
			subTestContext.Fatalf("write invalid key file: %v", writeErr)
		}

		_, resolveErr := resolvePublicKey(invalidPublicKeyPath)
		if resolveErr == nil {
			subTestContext.Fatalf("expected invalid-key parse error")
		}
		if !strings.Contains(resolveErr.Error(), "invalid public key in file") {
			subTestContext.Fatalf("unexpected error: %v", resolveErr)
		}
	})
}

// TestParsePublicKeyFromRawInputInvalid ensures malformed authorized key strings fail validation.
func TestParsePublicKeyFromRawInputInvalid(testContext *testing.T) {
	testContext.Parallel()

	_, parseErr := parsePublicKeyFromRawInput("not-an-authorized-key")
	if parseErr == nil {
		testContext.Fatalf("expected parse error")
	}
	if !strings.Contains(parseErr.Error(), "invalid public key format") {
		testContext.Fatalf("unexpected error: %v", parseErr)
	}
}

// TestNormalizeLF ensures CRLF and CR are normalized before remote script execution.
func TestNormalizeLF(testContext *testing.T) {
	testContext.Parallel()

	rawValue := "line1\r\nline2\rline3\n"
	normalizedValue := normalizeLF(rawValue)
	expectedValue := "line1\nline2\nline3\n"
	if normalizedValue != expectedValue {
		testContext.Fatalf("got %q want %q", normalizedValue, expectedValue)
	}
}

// TestNormalizeHostInvalidPort validates host:port parsing failures.
func TestNormalizeHostInvalidPort(testContext *testing.T) {
	testContext.Parallel()

	_, normalizeErr := normalizeHost("host:not-a-number", 22)
	if normalizeErr == nil {
		testContext.Fatalf("expected invalid port error")
	}
	if !strings.Contains(normalizeErr.Error(), "invalid port") {
		testContext.Fatalf("unexpected error: %v", normalizeErr)
	}
}

// TestResolveHostsInvalidEntry ensures invalid server entries are rejected early.
func TestResolveHostsInvalidEntry(testContext *testing.T) {
	testContext.Parallel()

	_, resolveErr := resolveHosts("", "good-host,bad-host:not-a-port", 22)
	if resolveErr == nil {
		testContext.Fatalf("expected invalid server error")
	}
	if !strings.Contains(resolveErr.Error(), "invalid server") {
		testContext.Fatalf("unexpected error: %v", resolveErr)
	}
}

// TestEnsureKnownHostsFile verifies path creation and file initialization behavior.
func TestEnsureKnownHostsFile(testContext *testing.T) {
	testContext.Parallel()

	testContext.Run("creates parent directories and file", func(subTestContext *testing.T) {
		knownHostsPath := filepath.Join(subTestContext.TempDir(), "nested", "known_hosts")
		if ensureErr := ensureKnownHostsFile(knownHostsPath); ensureErr != nil {
			subTestContext.Fatalf("ensureKnownHostsFile() error = %v", ensureErr)
		}
		fileInfo, statErr := os.Stat(knownHostsPath)
		if statErr != nil {
			subTestContext.Fatalf("stat known_hosts: %v", statErr)
		}
		if fileInfo.IsDir() {
			subTestContext.Fatalf("known_hosts path %q should be a file", knownHostsPath)
		}
	})

	testContext.Run("returns error for directory path", func(subTestContext *testing.T) {
		knownHostsDir := subTestContext.TempDir()
		ensureErr := ensureKnownHostsFile(knownHostsDir)
		if ensureErr == nil {
			subTestContext.Fatalf("expected ensureKnownHostsFile() error for directory path")
		}
	})
}

// TestAppendKnownHost validates successful append and invalid target errors.
func TestAppendKnownHost(testContext *testing.T) {
	testContext.Parallel()

	hostPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))

	testContext.Run("appends entry to known_hosts", func(subTestContext *testing.T) {
		knownHostsPath := filepath.Join(subTestContext.TempDir(), "known_hosts")
		if appendErr := appendKnownHost(knownHostsPath, "example.com:22", hostPublicKey); appendErr != nil {
			subTestContext.Fatalf("appendKnownHost() error = %v", appendErr)
		}

		knownHostsBytes, readErr := os.ReadFile(knownHostsPath)
		if readErr != nil {
			subTestContext.Fatalf("read known_hosts: %v", readErr)
		}
		knownHostsContent := string(knownHostsBytes)
		if !strings.Contains(knownHostsContent, "example.com") {
			subTestContext.Fatalf("known_hosts missing hostname: %q", knownHostsContent)
		}
	})

	testContext.Run("errors when known_hosts path is a directory", func(subTestContext *testing.T) {
		knownHostsDir := subTestContext.TempDir()
		appendErr := appendKnownHost(knownHostsDir, "example.com:22", hostPublicKey)
		if appendErr == nil {
			subTestContext.Fatalf("expected appendKnownHost() error")
		}
	})
}

// TestAddAuthorizedKeyScriptLFOnly guards against carriage returns in remote shell commands.
func TestAddAuthorizedKeyScriptLFOnly(testContext *testing.T) {
	testContext.Parallel()

	if strings.Contains(normalizeLF(addAuthorizedKeyScript), "\r") {
		testContext.Fatalf("remote script contains carriage return")
	}
}

// TestApplyDotEnvConfigFile validates .env parsing and merge behavior.
func TestApplyDotEnvConfigFile(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := `
# comment
SERVER=env-host
SERVERS=env-a,env-b
export USER=env-user
PASSWORD='env password'
PASSWORD_SECRET_REF=bw://ssh-prod-password
KEY="ssh-ed25519 AAAAENV"
PORT=2300 # inline comment
TIMEOUT=40
INSECURE_IGNORE_HOST_KEY=true
KNOWN_HOSTS=~/.ssh/env_known_hosts
`
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		testContext.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		EnvFile:               dotEnvPath,
		Server:                "existing-host",
		InsecureIgnoreHostKey: false,
	}

	if _, applyErr := applyDotEnvConfigFileWithMetadata(programOptions); applyErr != nil {
		testContext.Fatalf("apply .env config: %v", applyErr)
	}

	if programOptions.Server != "env-host" {
		testContext.Fatalf("server not loaded from .env config")
	}
	if programOptions.User != "env-user" {
		testContext.Fatalf("user not loaded from .env config")
	}
	if programOptions.Password != "env password" {
		testContext.Fatalf("password not loaded from .env config")
	}
	if programOptions.PasswordSecretRef != "bw://ssh-prod-password" {
		testContext.Fatalf("password secret ref not loaded from .env config")
	}
	if programOptions.KeyInput != "ssh-ed25519 AAAAENV" {
		testContext.Fatalf("key input not loaded from .env config")
	}
	if programOptions.Port != 2300 {
		testContext.Fatalf("port not loaded from .env config")
	}
	if programOptions.TimeoutSec != 40 {
		testContext.Fatalf("timeout not loaded from .env config")
	}
	if !programOptions.InsecureIgnoreHostKey {
		testContext.Fatalf("insecure mode not loaded from .env config")
	}
}

// TestApplyConfigFiles allows explicit .env loading without interactive review.
func TestApplyConfigFiles(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "USER=env-user\nPASSWORD=env-password\nSERVER=env-host\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		testContext.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		EnvFile: dotEnvPath,
	}

	if applyErr := applyConfigFiles(programOptions, bufio.NewReader(strings.NewReader(""))); applyErr != nil {
		testContext.Fatalf("apply config files: %v", applyErr)
	}

	if programOptions.User != "env-user" {
		testContext.Fatalf("user not loaded from .env config")
	}
	if programOptions.Password != "env-password" {
		testContext.Fatalf("password not loaded from .env config")
	}
	if programOptions.Server != "env-host" {
		testContext.Fatalf("server not loaded from .env config")
	}
}

// TestApplyDotEnvConfigFileInvalidPort validates numeric conversion errors in .env input.
func TestApplyDotEnvConfigFileInvalidPort(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "PORT=not-a-number\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		testContext.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{EnvFile: dotEnvPath}
	_, applyErr := applyDotEnvConfigFileWithMetadata(programOptions)
	if applyErr == nil {
		testContext.Fatalf("expected invalid PORT error")
	}
	if !strings.Contains(applyErr.Error(), "PORT") {
		testContext.Fatalf("expected PORT error message, got %v", applyErr)
	}
}

// TestBuildHostKeyCallbackUnknownHostAccepted verifies unknown hosts can be trusted once and persisted.
func TestBuildHostKeyCallbackUnknownHostAccepted(testContext *testing.T) {
	tempDirectory := testContext.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))

	originalPrompter := confirmUnknownHost
	promptCalls := 0
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		promptCalls++
		return true, nil
	}
	testContext.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		testContext.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if callbackErr := hostKeyCallback("example.com:22", remoteAddress, hostPublicKey); callbackErr != nil {
		testContext.Fatalf("accept unknown host: %v", callbackErr)
	}
	if callbackErr := hostKeyCallback("example.com:22", remoteAddress, hostPublicKey); callbackErr != nil {
		testContext.Fatalf("re-validate trusted host: %v", callbackErr)
	}

	if promptCalls != 1 {
		testContext.Fatalf("expected 1 trust prompt, got %d", promptCalls)
	}

	knownHostsBytes, readErr := os.ReadFile(knownHostsPath)
	if readErr != nil {
		testContext.Fatalf("read known_hosts: %v", readErr)
	}
	knownHostsContent := string(knownHostsBytes)
	if !strings.Contains(knownHostsContent, "example.com") || !strings.Contains(knownHostsContent, hostPublicKey.Type()) {
		testContext.Fatalf("known_hosts missing trusted entry: %q", knownHostsContent)
	}
}

// TestBuildHostKeyCallbackUnknownHostRejected verifies rejected hosts are not stored.
func TestBuildHostKeyCallbackUnknownHostRejected(testContext *testing.T) {
	tempDirectory := testContext.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))

	originalPrompter := confirmUnknownHost
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		return false, nil
	}
	testContext.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		testContext.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, hostPublicKey)
	if callbackErr == nil {
		testContext.Fatalf("expected rejection error")
	}
	if !strings.Contains(callbackErr.Error(), "rejected by user") {
		testContext.Fatalf("unexpected error: %v", callbackErr)
	}
}

// TestBuildHostKeyCallbackMismatchSkipsPrompt verifies mismatched known keys fail without trust prompt.
func TestBuildHostKeyCallbackMismatchSkipsPrompt(testContext *testing.T) {
	tempDirectory := testContext.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	existingPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))
	newPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))

	if appendErr := appendKnownHost(knownHostsPath, "example.com:22", existingPublicKey); appendErr != nil {
		testContext.Fatalf("seed known_hosts: %v", appendErr)
	}

	originalPrompter := confirmUnknownHost
	promptCalls := 0
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		promptCalls++
		return true, nil
	}
	testContext.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		testContext.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, newPublicKey)
	if callbackErr == nil {
		testContext.Fatalf("expected mismatch error")
	}
	if promptCalls != 0 {
		testContext.Fatalf("expected no prompt for mismatched host key, got %d", promptCalls)
	}
}

// TestBuildHostKeyCallbackUnknownHostPromptError verifies prompt failures propagate.
func TestBuildHostKeyCallbackUnknownHostPromptError(testContext *testing.T) {
	tempDirectory := testContext.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(testContext, generateTestKey(testContext))

	originalPrompter := confirmUnknownHost
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		return false, errors.New("prompt failed")
	}
	testContext.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		testContext.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, hostPublicKey)
	if callbackErr == nil {
		testContext.Fatalf("expected prompt failure")
	}
	if !strings.Contains(callbackErr.Error(), "prompt failed") {
		testContext.Fatalf("unexpected error: %v", callbackErr)
	}
}

// TestBuildHostKeyCallbackInvalidKnownHostsFile ensures malformed known_hosts content fails callback setup.
func TestBuildHostKeyCallbackInvalidKnownHostsFile(testContext *testing.T) {
	tempDirectory := testContext.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	if writeErr := os.WriteFile(knownHostsPath, []byte("invalid known hosts line\n"), 0o600); writeErr != nil {
		testContext.Fatalf("seed malformed known_hosts file: %v", writeErr)
	}

	_, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr == nil {
		testContext.Fatalf("expected known_hosts parse error")
	}
	if !strings.Contains(callbackErr.Error(), "load known_hosts") {
		testContext.Fatalf("unexpected error: %v", callbackErr)
	}
}

func parsePublicKeyFromAuthorizedLine(testContext *testing.T, authorizedLine string) ssh.PublicKey {
	testContext.Helper()

	publicKey, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if parseErr != nil {
		testContext.Fatalf("parse authorized key: %v", parseErr)
	}
	return publicKey
}

// generateTestKey synthesizes a valid ed25519 public key for authorized_keys usage.
func generateTestKey(testContext *testing.T) string {
	testContext.Helper()

	generatedPublicKey, _, generateErr := ed25519.GenerateKey(rand.Reader)
	if generateErr != nil {
		testContext.Fatalf("generate key: %v", generateErr)
	}

	sshPublicKey, wrapErr := ssh.NewPublicKey(generatedPublicKey)
	if wrapErr != nil {
		testContext.Fatalf("wrap key: %v", wrapErr)
	}

	return string(ssh.MarshalAuthorizedKey(sshPublicKey))
}
