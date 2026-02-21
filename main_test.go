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
	"sync"
	"testing"

	"ssh-key-bootstrap/providers"

	"golang.org/x/crypto/ssh"
)

// TestNormalizeHost verifies ports/default handling across host inputs.
func TestNormalizeHost(t *testing.T) {
	t.Parallel()

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
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actualHostPort, normalizeErr := normalizeHost(testCase.inputHost, testCase.defaultPort)
			if testCase.expectError {
				if normalizeErr == nil {
					t.Fatalf("expected error")
				}
				return
			}

			if normalizeErr != nil {
				t.Fatalf("unexpected error: %v", normalizeErr)
			}

			if actualHostPort != testCase.expectedHostPort {
				t.Fatalf("got %q want %q", actualHostPort, testCase.expectedHostPort)
			}
		})
	}
}

// TestResolveHostsNoInput asserts error when no host sources are provided.
func TestResolveHostsNoInput(t *testing.T) {
	t.Parallel()

	if _, resolveErr := resolveHosts("", "", 22); resolveErr == nil {
		t.Fatalf("expected error without hosts")
	}
}

// TestDefaultSecretProvidersRegistered guards the side-effect provider bootstrap wiring.
func TestDefaultSecretProvidersRegistered(t *testing.T) {
	t.Parallel()

	if len(providers.DefaultProviders()) == 0 {
		t.Fatalf("expected at least one registered default secret provider")
	}
}

// TestValidateOptionsPasswordSecretRefResolves ensures secret refs can hydrate password input.
func TestValidateOptionsPasswordSecretRefResolves(t *testing.T) {
	t.Parallel()

	originalResolver := resolvePasswordFromSecretRef
	resolvePasswordFromSecretRef = func(secretRef string) (string, error) {
		if secretRef != "bw://ssh-prod-password" {
			t.Fatalf("unexpected secret ref: %q", secretRef)
		}
		return "resolved-password", nil
	}
	t.Cleanup(func() { resolvePasswordFromSecretRef = originalResolver })

	programOptions := &options{
		Port:              defaultSSHPort,
		TimeoutSec:        defaultTimeoutSeconds,
		PasswordSecretRef: "bw://ssh-prod-password",
	}
	if validateErr := validateOptions(programOptions); validateErr != nil {
		t.Fatalf("validate options: %v", validateErr)
	}
	if programOptions.Password != "resolved-password" {
		t.Fatalf("password was not resolved from secret ref")
	}
}

// TestValidateOptionsPasswordSecretRefConflict ensures direct password and secret refs are mutually exclusive.
func TestValidateOptionsPasswordSecretRefConflict(t *testing.T) {
	t.Parallel()

	programOptions := &options{
		Port:              defaultSSHPort,
		TimeoutSec:        defaultTimeoutSeconds,
		Password:          "plaintext",
		PasswordSecretRef: "bw://ssh-prod-password",
	}
	if validateErr := validateOptions(programOptions); validateErr == nil {
		t.Fatalf("expected conflict error")
	}
}

// TestExtractSingleKey validates that only one non-comment key line is kept.
func TestExtractSingleKey(t *testing.T) {
	t.Parallel()

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
		t.Run(testCase.name, func(t *testing.T) {
			extractedKey, extractErr := extractSingleKey(testCase.inputKeyText)
			if testCase.expectError {
				if extractErr == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if extractErr != nil {
				t.Fatalf("unexpected error: %v", extractErr)
			}
			if extractedKey != testCase.expectedExtractedKey {
				t.Fatalf("got %q want %q", extractedKey, testCase.expectedExtractedKey)
			}
		})
	}
}

// TestResolveHosts ensures combined sources deduplicate, normalize, and sort hosts.
func TestResolveHosts(t *testing.T) {
	t.Parallel()

	actualHosts, resolveErr := resolveHosts("hostC", "hostA,hostB:2222,hostA", 22)
	if resolveErr != nil {
		t.Fatalf("resolve hosts: %v", resolveErr)
	}

	expectedHosts := []string{"hostA:22", "hostB:2222", "hostC:22"}
	if !reflect.DeepEqual(actualHosts, expectedHosts) {
		t.Fatalf("got %v want %v", actualHosts, expectedHosts)
	}
}

// TestResolvePublicKeyInline ensures inline key text is parsed and validated.
func TestResolvePublicKeyInline(t *testing.T) {
	t.Parallel()

	inlinePublicKey := generateTestKey(t)
	resolvedPublicKey, resolveErr := resolvePublicKey(inlinePublicKey)
	if resolveErr != nil {
		t.Fatalf("resolve inline key: %v", resolveErr)
	}
	if resolvedPublicKey == "" {
		t.Fatalf("empty key")
	}
}

// TestResolvePublicKeyFile ensures file-based keys are read and validated.
func TestResolvePublicKeyFile(t *testing.T) {
	t.Parallel()

	publicKeyFileContent := generateTestKey(t)
	tempDirectory := t.TempDir()
	publicKeyPath := filepath.Join(tempDirectory, "key.pub")
	if writeErr := os.WriteFile(publicKeyPath, []byte(publicKeyFileContent), 0o600); writeErr != nil {
		t.Fatalf("write key: %v", writeErr)
	}

	resolvedPublicKey, resolveErr := resolvePublicKey(publicKeyPath)
	if resolveErr != nil {
		t.Fatalf("resolve file key: %v", resolveErr)
	}
	if resolvedPublicKey == "" {
		t.Fatalf("empty key")
	}
}

// TestResolvePublicKeyMissingInput ensures missing key input is rejected.
func TestResolvePublicKeyMissingInput(t *testing.T) {
	t.Parallel()

	if _, resolveErr := resolvePublicKey(""); resolveErr == nil {
		t.Fatalf("expected error when key input is empty")
	}
}

// TestResolvePublicKeyInvalidInputPaths validates non-key and malformed file cases.
func TestResolvePublicKeyInvalidInputPaths(t *testing.T) {
	t.Parallel()

	t.Run("missing file", func(t *testing.T) {
		_, resolveErr := resolvePublicKey("/definitely/missing/public-key.pub")
		if resolveErr == nil {
			t.Fatalf("expected missing-file error")
		}
		if !strings.Contains(resolveErr.Error(), "expected a public key or readable file path") {
			t.Fatalf("unexpected error: %v", resolveErr)
		}
	})

	t.Run("invalid key in file", func(t *testing.T) {
		tempDirectory := t.TempDir()
		invalidPublicKeyPath := filepath.Join(tempDirectory, "invalid.pub")
		if writeErr := os.WriteFile(invalidPublicKeyPath, []byte("not-a-public-key\n"), 0o600); writeErr != nil {
			t.Fatalf("write invalid key file: %v", writeErr)
		}

		_, resolveErr := resolvePublicKey(invalidPublicKeyPath)
		if resolveErr == nil {
			t.Fatalf("expected invalid-key parse error")
		}
		if !strings.Contains(resolveErr.Error(), "invalid public key in file") {
			t.Fatalf("unexpected error: %v", resolveErr)
		}
	})
}

// TestParsePublicKeyFromRawInputInvalid ensures malformed authorized key strings fail validation.
func TestParsePublicKeyFromRawInputInvalid(t *testing.T) {
	t.Parallel()

	_, parseErr := parsePublicKeyFromRawInput("not-an-authorized-key")
	if parseErr == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(parseErr.Error(), "invalid public key format") {
		t.Fatalf("unexpected error: %v", parseErr)
	}
}

// TestNormalizeLF ensures CRLF and CR are normalized before remote script execution.
func TestNormalizeLF(t *testing.T) {
	t.Parallel()

	rawValue := "line1\r\nline2\rline3\n"
	normalizedValue := normalizeLF(rawValue)
	expectedValue := "line1\nline2\nline3\n"
	if normalizedValue != expectedValue {
		t.Fatalf("got %q want %q", normalizedValue, expectedValue)
	}
}

// TestNormalizeHostInvalidPort validates host:port parsing failures.
func TestNormalizeHostInvalidPort(t *testing.T) {
	t.Parallel()

	_, normalizeErr := normalizeHost("host:not-a-number", 22)
	if normalizeErr == nil {
		t.Fatalf("expected invalid port error")
	}
	if !strings.Contains(normalizeErr.Error(), "invalid port") {
		t.Fatalf("unexpected error: %v", normalizeErr)
	}
}

// TestResolveHostsInvalidEntry ensures invalid server entries are rejected early.
func TestResolveHostsInvalidEntry(t *testing.T) {
	t.Parallel()

	_, resolveErr := resolveHosts("", "good-host,bad-host:not-a-port", 22)
	if resolveErr == nil {
		t.Fatalf("expected invalid server error")
	}
	if !strings.Contains(resolveErr.Error(), "invalid server") {
		t.Fatalf("unexpected error: %v", resolveErr)
	}
}

// TestEnsureKnownHostsFile verifies path creation and file initialization behavior.
func TestEnsureKnownHostsFile(t *testing.T) {
	t.Parallel()

	t.Run("creates parent directories and file", func(t *testing.T) {
		knownHostsPath := filepath.Join(t.TempDir(), "nested", "known_hosts")
		if ensureErr := ensureKnownHostsFile(knownHostsPath); ensureErr != nil {
			t.Fatalf("ensureKnownHostsFile() error = %v", ensureErr)
		}
		fileInfo, statErr := os.Stat(knownHostsPath)
		if statErr != nil {
			t.Fatalf("stat known_hosts: %v", statErr)
		}
		if fileInfo.IsDir() {
			t.Fatalf("known_hosts path %q should be a file", knownHostsPath)
		}
	})

	t.Run("returns error for directory path", func(t *testing.T) {
		knownHostsDir := t.TempDir()
		ensureErr := ensureKnownHostsFile(knownHostsDir)
		if ensureErr == nil {
			t.Fatalf("expected ensureKnownHostsFile() error for directory path")
		}
	})
}

// TestAppendKnownHost validates successful append and invalid target errors.
func TestAppendKnownHost(t *testing.T) {
	t.Parallel()

	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	t.Run("appends entry to known_hosts", func(t *testing.T) {
		knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
		if appendErr := appendKnownHost(knownHostsPath, "example.com:22", hostPublicKey); appendErr != nil {
			t.Fatalf("appendKnownHost() error = %v", appendErr)
		}

		knownHostsBytes, readErr := os.ReadFile(knownHostsPath)
		if readErr != nil {
			t.Fatalf("read known_hosts: %v", readErr)
		}
		knownHostsContent := string(knownHostsBytes)
		if !strings.Contains(knownHostsContent, "example.com") {
			t.Fatalf("known_hosts missing hostname: %q", knownHostsContent)
		}
	})

	t.Run("errors when known_hosts path is a directory", func(t *testing.T) {
		knownHostsDir := t.TempDir()
		appendErr := appendKnownHost(knownHostsDir, "example.com:22", hostPublicKey)
		if appendErr == nil {
			t.Fatalf("expected appendKnownHost() error")
		}
	})
}

// TestAddAuthorizedKeyScriptLFOnly guards against carriage returns in remote shell commands.
func TestAddAuthorizedKeyScriptLFOnly(t *testing.T) {
	t.Parallel()

	if strings.Contains(normalizeLF(addAuthorizedKeyScript), "\r") {
		t.Fatalf("remote script contains carriage return")
	}
}

// TestApplyDotEnvConfigFile validates .env parsing and merge behavior.
func TestApplyDotEnvConfigFile(t *testing.T) {
	t.Parallel()

	tempDirectory := t.TempDir()
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
		t.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		EnvFile:               dotEnvPath,
		Server:                "existing-host",
		InsecureIgnoreHostKey: false,
	}

	if _, applyErr := applyDotEnvConfigFileWithMetadata(programOptions); applyErr != nil {
		t.Fatalf("apply .env config: %v", applyErr)
	}

	if programOptions.Server != "env-host" {
		t.Fatalf("server not loaded from .env config")
	}
	if programOptions.User != "env-user" {
		t.Fatalf("user not loaded from .env config")
	}
	if programOptions.Password != "env password" {
		t.Fatalf("password not loaded from .env config")
	}
	if programOptions.PasswordSecretRef != "bw://ssh-prod-password" {
		t.Fatalf("password secret ref not loaded from .env config")
	}
	if programOptions.KeyInput != "ssh-ed25519 AAAAENV" {
		t.Fatalf("key input not loaded from .env config")
	}
	if programOptions.Port != 2300 {
		t.Fatalf("port not loaded from .env config")
	}
	if programOptions.TimeoutSec != 40 {
		t.Fatalf("timeout not loaded from .env config")
	}
	if !programOptions.InsecureIgnoreHostKey {
		t.Fatalf("insecure mode not loaded from .env config")
	}
}

// TestApplyConfigFiles allows explicit .env loading without interactive review.
func TestApplyConfigFiles(t *testing.T) {
	t.Parallel()

	tempDirectory := t.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "USER=env-user\nPASSWORD=env-password\nSERVER=env-host\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		t.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		EnvFile: dotEnvPath,
	}

	if applyErr := applyConfigFiles(programOptions, bufio.NewReader(strings.NewReader(""))); applyErr != nil {
		t.Fatalf("apply config files: %v", applyErr)
	}

	if programOptions.User != "env-user" {
		t.Fatalf("user not loaded from .env config")
	}
	if programOptions.Password != "env-password" {
		t.Fatalf("password not loaded from .env config")
	}
	if programOptions.Server != "env-host" {
		t.Fatalf("server not loaded from .env config")
	}
}

// TestApplyDotEnvConfigFileInvalidPort validates numeric conversion errors in .env input.
func TestApplyDotEnvConfigFileInvalidPort(t *testing.T) {
	t.Parallel()

	tempDirectory := t.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "PORT=not-a-number\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		t.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{EnvFile: dotEnvPath}
	_, applyErr := applyDotEnvConfigFileWithMetadata(programOptions)
	if applyErr == nil {
		t.Fatalf("expected invalid PORT error")
	}
	if !strings.Contains(applyErr.Error(), "PORT") {
		t.Fatalf("expected PORT error message, got %v", applyErr)
	}
}

// TestBuildHostKeyCallbackUnknownHostAccepted verifies unknown hosts can be trusted once and persisted.
func TestBuildHostKeyCallbackUnknownHostAccepted(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	originalPrompter := confirmUnknownHost
	promptCalls := 0
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		promptCalls++
		return true, nil
	}
	t.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		t.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if callbackErr := hostKeyCallback("example.com:22", remoteAddress, hostPublicKey); callbackErr != nil {
		t.Fatalf("accept unknown host: %v", callbackErr)
	}
	if callbackErr := hostKeyCallback("example.com:22", remoteAddress, hostPublicKey); callbackErr != nil {
		t.Fatalf("re-validate trusted host: %v", callbackErr)
	}

	if promptCalls != 1 {
		t.Fatalf("expected 1 trust prompt, got %d", promptCalls)
	}

	knownHostsBytes, readErr := os.ReadFile(knownHostsPath)
	if readErr != nil {
		t.Fatalf("read known_hosts: %v", readErr)
	}
	knownHostsContent := string(knownHostsBytes)
	if !strings.Contains(knownHostsContent, "example.com") || !strings.Contains(knownHostsContent, hostPublicKey.Type()) {
		t.Fatalf("known_hosts missing trusted entry: %q", knownHostsContent)
	}
}

// TestBuildHostKeyCallbackUnknownHostConcurrent verifies concurrent unknown-host checks prompt once and persist safely.
func TestBuildHostKeyCallbackUnknownHostConcurrent(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	originalPrompter := confirmUnknownHost
	promptCalls := 0
	var promptGuard sync.Mutex
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		promptGuard.Lock()
		promptCalls++
		promptGuard.Unlock()
		return true, nil
	}
	t.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		t.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	const parallelCalls = 24
	errorsCh := make(chan error, parallelCalls)
	var waitGroup sync.WaitGroup
	for range parallelCalls {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errorsCh <- hostKeyCallback("example.com:22", remoteAddress, hostPublicKey)
		}()
	}
	waitGroup.Wait()
	close(errorsCh)

	for callbackErr := range errorsCh {
		if callbackErr != nil {
			t.Fatalf("concurrent callback error: %v", callbackErr)
		}
	}

	if promptCalls != 1 {
		t.Fatalf("expected 1 trust prompt, got %d", promptCalls)
	}

	knownHostsBytes, readErr := os.ReadFile(knownHostsPath)
	if readErr != nil {
		t.Fatalf("read known_hosts: %v", readErr)
	}
	knownHostsContent := string(knownHostsBytes)
	if strings.Count(knownHostsContent, "example.com") != 1 {
		t.Fatalf("expected one trusted entry, got content: %q", knownHostsContent)
	}
}

// TestBuildHostKeyCallbackUnknownHostRejected verifies rejected hosts are not stored.
func TestBuildHostKeyCallbackUnknownHostRejected(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	originalPrompter := confirmUnknownHost
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		return false, nil
	}
	t.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		t.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, hostPublicKey)
	if callbackErr == nil {
		t.Fatalf("expected rejection error")
	}
	if !strings.Contains(callbackErr.Error(), "rejected by user") {
		t.Fatalf("unexpected error: %v", callbackErr)
	}
}

// TestBuildHostKeyCallbackMismatchSkipsPrompt verifies mismatched known keys fail without trust prompt.
func TestBuildHostKeyCallbackMismatchSkipsPrompt(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	existingPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))
	newPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	if appendErr := appendKnownHost(knownHostsPath, "example.com:22", existingPublicKey); appendErr != nil {
		t.Fatalf("seed known_hosts: %v", appendErr)
	}

	originalPrompter := confirmUnknownHost
	promptCalls := 0
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		promptCalls++
		return true, nil
	}
	t.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		t.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, newPublicKey)
	if callbackErr == nil {
		t.Fatalf("expected mismatch error")
	}
	if promptCalls != 0 {
		t.Fatalf("expected no prompt for mismatched host key, got %d", promptCalls)
	}
}

// TestBuildHostKeyCallbackUnknownHostPromptError verifies prompt failures propagate.
func TestBuildHostKeyCallbackUnknownHostPromptError(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	hostPublicKey := parsePublicKeyFromAuthorizedLine(t, generateTestKey(t))

	originalPrompter := confirmUnknownHost
	confirmUnknownHost = func(hostname, path string, key ssh.PublicKey) (bool, error) {
		return false, errors.New("prompt failed")
	}
	t.Cleanup(func() { confirmUnknownHost = originalPrompter })

	hostKeyCallback, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr != nil {
		t.Fatalf("build host key callback: %v", callbackErr)
	}

	remoteAddress := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	callbackErr = hostKeyCallback("example.com:22", remoteAddress, hostPublicKey)
	if callbackErr == nil {
		t.Fatalf("expected prompt failure")
	}
	if !strings.Contains(callbackErr.Error(), "prompt failed") {
		t.Fatalf("unexpected error: %v", callbackErr)
	}
}

// TestBuildHostKeyCallbackInvalidKnownHostsFile ensures malformed known_hosts content fails callback setup.
func TestBuildHostKeyCallbackInvalidKnownHostsFile(t *testing.T) {
	tempDirectory := t.TempDir()
	knownHostsPath := filepath.Join(tempDirectory, "known_hosts")
	if writeErr := os.WriteFile(knownHostsPath, []byte("invalid known hosts line\n"), 0o600); writeErr != nil {
		t.Fatalf("seed malformed known_hosts file: %v", writeErr)
	}

	_, callbackErr := buildHostKeyCallback(false, knownHostsPath)
	if callbackErr == nil {
		t.Fatalf("expected known_hosts parse error")
	}
	if !strings.Contains(callbackErr.Error(), "load known_hosts") {
		t.Fatalf("unexpected error: %v", callbackErr)
	}
}

func parsePublicKeyFromAuthorizedLine(t *testing.T, authorizedLine string) ssh.PublicKey {
	t.Helper()

	publicKey, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if parseErr != nil {
		t.Fatalf("parse authorized key: %v", parseErr)
	}
	return publicKey
}

// generateTestKey synthesizes a valid ed25519 public key for authorized_keys usage.
func generateTestKey(t *testing.T) string {
	t.Helper()

	generatedPublicKey, _, generateErr := ed25519.GenerateKey(rand.Reader)
	if generateErr != nil {
		t.Fatalf("generate key: %v", generateErr)
	}

	sshPublicKey, wrapErr := ssh.NewPublicKey(generatedPublicKey)
	if wrapErr != nil {
		t.Fatalf("wrap key: %v", wrapErr)
	}

	return string(ssh.MarshalAuthorizedKey(sshPublicKey))
}
