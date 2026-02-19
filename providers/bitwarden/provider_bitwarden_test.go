package bitwarden

import (
	"strings"
	"testing"
)

func TestProviderSupports(t *testing.T) {
	t.Parallel()

	bitwardenProvider := provider{}
	testCases := []struct {
		ref     string
		support bool
	}{
		{ref: "bw://secret-id", support: true},
		{ref: "bw:secret-id", support: true},
		{ref: "bitwarden://secret-id", support: true},
		{ref: "aws-sm://secret-id", support: false},
		{ref: "random-value", support: false},
	}

	for _, testCase := range testCases {
		actual := bitwardenProvider.Supports(testCase.ref)
		if actual != testCase.support {
			t.Fatalf("Supports(%q) = %v, want %v", testCase.ref, actual, testCase.support)
		}
	}
}

func TestParseSecretID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		ref         string
		expectedID  string
		expectError bool
	}{
		{name: "bw-scheme", ref: "bw://abc123", expectedID: "abc123"},
		{name: "bw-short", ref: "bw:abc123", expectedID: "abc123"},
		{name: "bitwarden-scheme", ref: "bitwarden://abc123", expectedID: "abc123"},
		{name: "invalid-scheme", ref: "vault://abc123", expectError: true},
		{name: "empty-id", ref: "bw://   ", expectError: true},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(testContext *testing.T) {
			actualID, err := parseSecretID(testCase.ref)
			if testCase.expectError {
				if err == nil {
					testContext.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				testContext.Fatalf("unexpected error: %v", err)
			}
			if actualID != testCase.expectedID {
				testContext.Fatalf("got %q want %q", actualID, testCase.expectedID)
			}
		})
	}
}

func TestParseBWSSecretOutput(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		output      string
		expected    string
		expectError bool
	}{
		{name: "valid-json", output: `{"value":"super-secret"}`, expected: "super-secret"},
		{name: "invalid-json", output: "not-json", expectError: true},
		{name: "empty-value", output: `{"value":"   "}`, expectError: true},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(testContext *testing.T) {
			actual, err := parseBWSSecretOutput(testCase.output)
			if testCase.expectError {
				if err == nil {
					testContext.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				testContext.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(actual) != testCase.expected {
				testContext.Fatalf("got %q want %q", actual, testCase.expected)
			}
		})
	}
}

func TestProviderResolve(t *testing.T) {
	t.Run("uses bw when available", func(testContext *testing.T) {
		commandDirectory := testContext.TempDir()
		createFakeCommand(testContext, commandDirectory, "bw", `#!/bin/sh
printf "bw-provider-secret"
`)
		createFakeCommand(testContext, commandDirectory, "bws", `#!/bin/sh
printf '{"value":"bws-should-not-be-used"}'
`)
		testContext.Setenv("PATH", commandDirectory)

		resolvedSecret, err := provider{}.Resolve("bw://secret-id")
		if err != nil {
			testContext.Fatalf("provider resolve: %v", err)
		}
		if resolvedSecret != "bw-provider-secret" {
			testContext.Fatalf("resolved secret = %q, want %q", resolvedSecret, "bw-provider-secret")
		}
	})

	t.Run("falls back to bws when bw fails", func(testContext *testing.T) {
		commandDirectory := testContext.TempDir()
		createFakeCommand(testContext, commandDirectory, "bw", `#!/bin/sh
echo "bw failed" >&2
exit 1
`)
		createFakeCommand(testContext, commandDirectory, "bws", `#!/bin/sh
printf '{"value":"resolved-from-bws-fallback"}'
`)
		testContext.Setenv("PATH", commandDirectory)

		resolvedSecret, err := provider{}.Resolve("bw://secret-id")
		if err != nil {
			testContext.Fatalf("provider resolve fallback: %v", err)
		}
		if resolvedSecret != "resolved-from-bws-fallback" {
			testContext.Fatalf("resolved secret = %q, want %q", resolvedSecret, "resolved-from-bws-fallback")
		}
	})

	t.Run("returns bws error when both commands fail", func(testContext *testing.T) {
		commandDirectory := testContext.TempDir()
		createFakeCommand(testContext, commandDirectory, "bw", `#!/bin/sh
echo "bw failed" >&2
exit 1
`)
		createFakeCommand(testContext, commandDirectory, "bws", `#!/bin/sh
echo "bws failed" >&2
exit 1
`)
		testContext.Setenv("PATH", commandDirectory)

		_, err := provider{}.Resolve("bw://secret-id")
		if err == nil {
			testContext.Fatalf("expected provider resolve error")
		}
		if !strings.Contains(err.Error(), "bws failed") {
			testContext.Fatalf("expected bws failure in error, got %v", err)
		}
	})

	t.Run("rejects unsupported reference format", func(testContext *testing.T) {
		_, err := provider{}.Resolve("vault://secret-id")
		if err == nil {
			testContext.Fatalf("expected parse error")
		}
		if !strings.Contains(err.Error(), "invalid bitwarden secret ref") {
			testContext.Fatalf("unexpected error: %v", err)
		}
	})
}
