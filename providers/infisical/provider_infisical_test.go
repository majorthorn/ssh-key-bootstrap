package infisical

import (
	"strings"
	"testing"
)

func TestNewModeProviderDefaultsToCLI(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{})

	providerInstance, err := newModeProvider()
	if err != nil {
		t.Fatalf("newModeProvider() error = %v", err)
	}
	if _, ok := providerInstance.(cliProvider); !ok {
		t.Fatalf("expected default provider type cliProvider, got %T", providerInstance)
	}
}

func TestNewModeProviderSelectsAPI(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{"INFISICAL_MODE": "api"})

	providerInstance, err := newModeProvider()
	if err != nil {
		t.Fatalf("newModeProvider() error = %v", err)
	}
	if _, ok := providerInstance.(apiProvider); !ok {
		t.Fatalf("expected provider type apiProvider, got %T", providerInstance)
	}
}

func TestNewModeProviderInvalidMode(t *testing.T) {
	t.Parallel()

	setLookupEnvForTest(t, map[string]string{"INFISICAL_MODE": "not-valid"})

	_, err := newModeProvider()
	if err == nil {
		t.Fatalf("expected invalid mode error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderSupports(t *testing.T) {
	t.Parallel()

	infisicalProvider := provider{}
	testCases := []struct {
		ref     string
		support bool
	}{
		{ref: "infisical://secret-id", support: true},
		{ref: "infisical:secret-id", support: false},
		{ref: "inf://secret-id", support: true},
		{ref: "inf:secret-id", support: false},
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
		{name: "short-scheme-alias", ref: "inf://secret-name", expectedSecret: "secret-name"},
		{name: "legacy-colon-format", ref: "infisical:secret-name", expectError: true},
		{name: "legacy-short-colon-format", ref: "inf:secret-name", expectError: true},
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
				if !strings.Contains(err.Error(), infisicalRefFormatErr) && testCase.name != "missing-secret" {
					t.Fatalf("unexpected error: %v", err)
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

	secretRef := "vault://very-sensitive-secret-id"
	_, err := provider{}.Resolve(secretRef)
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), infisicalRefFormatErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), secretRef) || strings.Contains(err.Error(), "very-sensitive-secret-id") {
		t.Fatalf("expected invalid ref error to avoid echoing full input, got %v", err)
	}
}

func TestProviderResolveRejectsLegacySingleColonFormat(t *testing.T) {
	t.Parallel()

	_, err := provider{}.Resolve("infisical:very-sensitive-secret-id")
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), infisicalRefFormatErr) {
		t.Fatalf("unexpected error: %v", err)
	}
}
