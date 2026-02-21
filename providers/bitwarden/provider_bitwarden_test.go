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
		t.Run(testCase.name, func(t *testing.T) {
			actualID, err := parseSecretID(testCase.ref)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if actualID != testCase.expectedID {
				t.Fatalf("got %q want %q", actualID, testCase.expectedID)
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
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := parseBWSSecretOutput(testCase.output)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(actual) != testCase.expected {
				t.Fatalf("got %q want %q", actual, testCase.expected)
			}
		})
	}
}

func TestProviderResolve(t *testing.T) {
	t.Run("uses bw when available", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "bw", `#!/bin/sh
printf "bw-provider-secret"
`)
		createFakeCommand(t, commandDirectory, "bws", `#!/bin/sh
printf '{"value":"bws-should-not-be-used"}'
`)
		t.Setenv("PATH", commandDirectory)

		resolvedSecret, err := provider{}.Resolve("bw://secret-id")
		if err != nil {
			t.Fatalf("provider resolve: %v", err)
		}
		if resolvedSecret != "bw-provider-secret" {
			t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "bw-provider-secret")
		}
	})

	t.Run("falls back to bws when bw fails", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "bw", `#!/bin/sh
echo "bw failed" >&2
exit 1
`)
		createFakeCommand(t, commandDirectory, "bws", `#!/bin/sh
printf '{"value":"resolved-from-bws-fallback"}'
`)
		t.Setenv("PATH", commandDirectory)

		resolvedSecret, err := provider{}.Resolve("bw://secret-id")
		if err != nil {
			t.Fatalf("provider resolve fallback: %v", err)
		}
		if resolvedSecret != "resolved-from-bws-fallback" {
			t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "resolved-from-bws-fallback")
		}
	})

	t.Run("returns bws error when both commands fail", func(t *testing.T) {
		commandDirectory := t.TempDir()
		createFakeCommand(t, commandDirectory, "bw", `#!/bin/sh
echo "bw failed" >&2
exit 1
`)
		createFakeCommand(t, commandDirectory, "bws", `#!/bin/sh
echo "bws failed" >&2
exit 1
`)
		t.Setenv("PATH", commandDirectory)

		_, err := provider{}.Resolve("bw://secret-id")
		if err == nil {
			t.Fatalf("expected provider resolve error")
		}
		if !strings.Contains(err.Error(), "bw failed") {
			t.Fatalf("expected bw failure in error, got %v", err)
		}
		if !strings.Contains(err.Error(), "bws failed") {
			t.Fatalf("expected bws failure in error, got %v", err)
		}
	})

	t.Run("rejects unsupported reference format", func(t *testing.T) {
		_, err := provider{}.Resolve("vault://secret-id")
		if err == nil {
			t.Fatalf("expected parse error")
		}
		if !strings.Contains(err.Error(), "invalid bitwarden secret ref") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
