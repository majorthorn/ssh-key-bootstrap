package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
	resolvedPublicKey, resolveErr := resolvePublicKey(inlinePublicKey, "")
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

	resolvedPublicKey, resolveErr := resolvePublicKey("", publicKeyPath)
	if resolveErr != nil {
		testContext.Fatalf("resolve file key: %v", resolveErr)
	}
	if resolvedPublicKey == "" {
		testContext.Fatalf("empty key")
	}
}

// TestResolvePublicKeyBothSources rejects simultaneous inline and file inputs.
func TestResolvePublicKeyBothSources(testContext *testing.T) {
	testContext.Parallel()

	if _, resolveErr := resolvePublicKey("key", "file"); resolveErr == nil {
		testContext.Fatalf("expected error when both sources provided")
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
  "password_env": "JSON_PASSWORD",
  "pubkey": "ssh-ed25519 AAAAJSON",
  "pubkey_file": "./json-id.pub",
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
PASSWORD_ENV=ENV_PASSWORD
PUBKEY="ssh-ed25519 AAAAENV"
PUBKEY_FILE=./env-id.pub
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
