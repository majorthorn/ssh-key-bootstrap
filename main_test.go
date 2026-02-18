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
