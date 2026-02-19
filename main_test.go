package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"vibe-ssh-lift/secrets"
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

	if _, resolveErr := resolveHosts("", "", "", 22); resolveErr == nil {
		testContext.Fatalf("expected error without hosts")
	}
}

// TestDefaultSecretProvidersRegistered guards the side-effect provider bootstrap wiring.
func TestDefaultSecretProvidersRegistered(testContext *testing.T) {
	testContext.Parallel()

	if len(secrets.DefaultProviders()) == 0 {
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
		port:              defaultSSHPort,
		timeoutSec:        defaultTimeoutSeconds,
		passwordSecretRef: "bw://ssh-prod-password",
	}
	if validateErr := validateOptions(programOptions); validateErr != nil {
		testContext.Fatalf("validate options: %v", validateErr)
	}
	if programOptions.password != "resolved-password" {
		testContext.Fatalf("password was not resolved from secret ref")
	}
}

// TestValidateOptionsPasswordSecretRefConflict ensures direct password and secret refs are mutually exclusive.
func TestValidateOptionsPasswordSecretRefConflict(testContext *testing.T) {
	testContext.Parallel()

	programOptions := &options{
		port:              defaultSSHPort,
		timeoutSec:        defaultTimeoutSeconds,
		password:          "plaintext",
		passwordSecretRef: "bw://ssh-prod-password",
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

	tempDirectory := testContext.TempDir()
	serverListPath := filepath.Join(tempDirectory, "servers.txt")
	serverListContent := `
# comment line
hostA
hostB:2222
hostA
`

	if writeErr := os.WriteFile(serverListPath, []byte(serverListContent), 0o600); writeErr != nil {
		testContext.Fatalf("write list: %v", writeErr)
	}

	actualHosts, resolveErr := resolveHosts("hostC", "hostA,hostB:2222", serverListPath, 22)
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

// TestResolvePublicKeyMissingInput ensures missing --key input is rejected.
func TestResolvePublicKeyMissingInput(testContext *testing.T) {
	testContext.Parallel()

	if _, resolveErr := resolvePublicKey(""); resolveErr == nil {
		testContext.Fatalf("expected error when key input is empty")
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

// TestAddAuthorizedKeyScriptLFOnly guards against carriage returns in remote shell commands.
func TestAddAuthorizedKeyScriptLFOnly(testContext *testing.T) {
	testContext.Parallel()

	if strings.Contains(normalizeLF(addAuthorizedKeyScript), "\r") {
		testContext.Fatalf("remote script contains carriage return")
	}
}

// TestCanonicalFlagName ensures aliases normalize to config precedence keys.
func TestCanonicalFlagName(testContext *testing.T) {
	testContext.Parallel()

	testCases := map[string]string{
		"host":       "server",
		"s":          "server",
		"hosts-file": "servers-file",
		"k":          "key",
		"j":          "json-file",
		"d":          "env-file",
		"r":          "skip-config-review",
		"i":          "insecure-ignore-host-key",
		"o":          "known-hosts",
		"known":      "known-hosts",
	}

	for input, expected := range testCases {
		actual := canonicalFlagName(input)
		if actual != expected {
			testContext.Fatalf("canonicalFlagName(%q) = %q, want %q", input, actual, expected)
		}
	}
}

// TestApplyJSONConfigFile validates JSON config merge behavior and CLI precedence.
func TestApplyJSONConfigFile(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()
	jsonConfigPath := filepath.Join(tempDirectory, "config.json")
	jsonConfigContent := `{
  "server": "json-host",
  "servers": "json-a,json-b",
  "servers_file": "./json-servers.txt",
  "user": "json-user",
  "password": "json-password",
  "password_secret_ref": "bw://ssh-prod-password",
  "key": "ssh-ed25519 AAAAJSON",
  "port": 2200,
  "timeout": 35,
  "insecure_ignore_host_key": true,
  "known_hosts": "~/.ssh/json_known_hosts"
}`
	if writeErr := os.WriteFile(jsonConfigPath, []byte(jsonConfigContent), 0o600); writeErr != nil {
		testContext.Fatalf("write json config: %v", writeErr)
	}

	programOptions := &options{
		jsonFile:   jsonConfigPath,
		user:       "cli-user",
		port:       2222,
		timeoutSec: defaultTimeoutSeconds,
	}
	providedFlagNames := map[string]bool{
		"user": true,
		"port": true,
	}

	if applyErr := applyJSONConfigFile(programOptions, providedFlagNames); applyErr != nil {
		testContext.Fatalf("apply json config: %v", applyErr)
	}

	if programOptions.user != "cli-user" {
		testContext.Fatalf("user overwritten by json config")
	}
	if programOptions.port != 2222 {
		testContext.Fatalf("port overwritten by json config")
	}
	if programOptions.server != "json-host" {
		testContext.Fatalf("server not loaded from json config")
	}
	if programOptions.password != "json-password" {
		testContext.Fatalf("password not loaded from json config")
	}
	if programOptions.passwordSecretRef != "bw://ssh-prod-password" {
		testContext.Fatalf("password secret ref not loaded from json config")
	}
	if programOptions.keyInput != "ssh-ed25519 AAAAJSON" {
		testContext.Fatalf("key input not loaded from json config")
	}
	if programOptions.timeoutSec != 35 {
		testContext.Fatalf("timeout not loaded from json config")
	}
	if !programOptions.insecureIgnoreHostKey {
		testContext.Fatalf("insecure flag not loaded from json config")
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
SERVERS_FILE=./env-servers.txt
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
		envFile:               dotEnvPath,
		server:                "cli-host",
		insecureIgnoreHostKey: false,
	}
	providedFlagNames := map[string]bool{
		"server":                   true,
		"insecure-ignore-host-key": true,
	}

	if applyErr := applyDotEnvConfigFile(programOptions, providedFlagNames); applyErr != nil {
		testContext.Fatalf("apply .env config: %v", applyErr)
	}

	if programOptions.server != "cli-host" {
		testContext.Fatalf("server overwritten by .env config")
	}
	if programOptions.user != "env-user" {
		testContext.Fatalf("user not loaded from .env config")
	}
	if programOptions.password != "env password" {
		testContext.Fatalf("password not loaded from .env config")
	}
	if programOptions.passwordSecretRef != "bw://ssh-prod-password" {
		testContext.Fatalf("password secret ref not loaded from .env config")
	}
	if programOptions.keyInput != "ssh-ed25519 AAAAENV" {
		testContext.Fatalf("key input not loaded from .env config")
	}
	if programOptions.port != 2300 {
		testContext.Fatalf("port not loaded from .env config")
	}
	if programOptions.timeoutSec != 40 {
		testContext.Fatalf("timeout not loaded from .env config")
	}
	if programOptions.insecureIgnoreHostKey {
		testContext.Fatalf("insecure flag should remain CLI value")
	}
}

// TestApplyConfigFiles ensures both active config sources require interactive selection.
func TestApplyConfigFiles(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()

	jsonConfigPath := filepath.Join(tempDirectory, "config.json")
	jsonConfigContent := `{"user":"json-user","password":"json-password","server":"json-host"}`
	if writeErr := os.WriteFile(jsonConfigPath, []byte(jsonConfigContent), 0o600); writeErr != nil {
		testContext.Fatalf("write json config: %v", writeErr)
	}

	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "USER=env-user\nPASSWORD=env-password\nSERVER=env-host\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		testContext.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		jsonFile: jsonConfigPath,
		envFile:  dotEnvPath,
	}

	applyErr := applyConfigFiles(programOptions, map[string]bool{})
	if applyErr == nil {
		testContext.Fatalf("expected selection error when both config sources are active without an interactive terminal")
	}
}

// TestApplyConfigFilesSkipConfigReviewAllowsNonInteractive ensures config loading can bypass terminal confirmation.
func TestApplyConfigFilesSkipConfigReviewAllowsNonInteractive(testContext *testing.T) {
	testContext.Parallel()

	tempDirectory := testContext.TempDir()
	dotEnvPath := filepath.Join(tempDirectory, ".env")
	dotEnvContent := "USER=env-user\nPASSWORD=env-password\nSERVER=env-host\n"
	if writeErr := os.WriteFile(dotEnvPath, []byte(dotEnvContent), 0o600); writeErr != nil {
		testContext.Fatalf("write .env config: %v", writeErr)
	}

	programOptions := &options{
		envFile:               dotEnvPath,
		skipConfigReview:      true,
		insecureIgnoreHostKey: false,
	}

	if applyErr := applyConfigFiles(programOptions, map[string]bool{}); applyErr != nil {
		testContext.Fatalf("apply config files with skip review: %v", applyErr)
	}
	if programOptions.user != "env-user" {
		testContext.Fatalf("user not loaded from .env config")
	}
	if programOptions.password != "env-password" {
		testContext.Fatalf("password not loaded from .env config")
	}
	if programOptions.server != "env-host" {
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

	programOptions := &options{envFile: dotEnvPath}
	applyErr := applyDotEnvConfigFile(programOptions, map[string]bool{})
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
