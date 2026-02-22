package infisical

import (
	"strings"
	"testing"
)

func TestProviderSupports(t *testing.T) {
	t.Parallel()

	infisicalProvider := provider{}
	testCases := []struct {
		ref     string
		support bool
	}{
		{ref: "infisical://secret-id", support: true},
		{ref: "infisical:secret-id", support: true},
		{ref: "inf://secret-id", support: true},
		{ref: "inf:secret-id", support: true},
		{ref: " INF://secret-id ", support: true},
		{ref: "bw://secret-id", support: false},
	}

	for _, testCase := range testCases {
		actual := infisicalProvider.Supports(testCase.ref)
		if actual != testCase.support {
			t.Fatalf("Supports(%q) = %v, want %v", testCase.ref, actual, testCase.support)
		}
	}
}

func TestParseSecretRef(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		ref               string
		expectedSecret    string
		expectedProjectID string
		expectedEnv       string
		expectError       bool
	}{
		{name: "canonical", ref: "infisical://app/password", expectedSecret: "app/password"},
		{name: "short-alias", ref: "inf:secret-name", expectedSecret: "secret-name"},
		{name: "query-overrides", ref: "infisical://db/password?projectId=proj-1&environment=prod", expectedSecret: "db/password", expectedProjectID: "proj-1", expectedEnv: "prod"},
		{name: "invalid-scheme", ref: "vault://secret", expectError: true},
		{name: "missing-secret", ref: "infisical://   ", expectError: true},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			actualSecretRef, err := parseSecretRef(testCase.ref)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if actualSecretRef.secretName != testCase.expectedSecret {
				t.Fatalf("secretName = %q, want %q", actualSecretRef.secretName, testCase.expectedSecret)
			}
			if actualSecretRef.projectID != testCase.expectedProjectID {
				t.Fatalf("projectID = %q, want %q", actualSecretRef.projectID, testCase.expectedProjectID)
			}
			if actualSecretRef.environment != testCase.expectedEnv {
				t.Fatalf("environment = %q, want %q", actualSecretRef.environment, testCase.expectedEnv)
			}
		})
	}
}

func TestProviderResolveInvalidRef(t *testing.T) {
	t.Parallel()

	_, err := provider{}.Resolve("vault://unknown")
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), "invalid infisical secret ref") {
		t.Fatalf("unexpected error: %v", err)
	}
}
