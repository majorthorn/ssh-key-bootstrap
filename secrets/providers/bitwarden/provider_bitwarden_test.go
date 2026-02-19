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
