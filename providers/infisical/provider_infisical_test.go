package infisical

import (
	"errors"
	"strings"
	"testing"
)

type fakeInfisicalResolver struct {
	resolvedSecret string
	resolveErr     error
	lastSpec       secretRefSpec
}

func (f *fakeInfisicalResolver) Resolve(secretSpec secretRefSpec) (string, error) {
	f.lastSpec = secretSpec
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return f.resolvedSecret, nil
}

func setResolverFactoryForTest(t *testing.T, factory func() infisicalResolver) {
	t.Helper()
	originalFactory := newInfisicalResolver
	newInfisicalResolver = factory
	t.Cleanup(func() {
		newInfisicalResolver = originalFactory
	})
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

func TestProviderResolveDelegatesToResolver(t *testing.T) {
	resolver := &fakeInfisicalResolver{resolvedSecret: "resolved-secret"}
	setResolverFactoryForTest(t, func() infisicalResolver {
		return resolver
	})

	secretValue, err := provider{}.Resolve("infisical://app/secret?projectId=project-a&environment=prod")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if secretValue != "resolved-secret" {
		t.Fatalf("secret value = %q, want %q", secretValue, "resolved-secret")
	}
	if resolver.lastSpec.secretName != "app/secret" {
		t.Fatalf("secret name = %q, want %q", resolver.lastSpec.secretName, "app/secret")
	}
	if resolver.lastSpec.projectID != "project-a" {
		t.Fatalf("project id = %q, want %q", resolver.lastSpec.projectID, "project-a")
	}
	if resolver.lastSpec.environment != "prod" {
		t.Fatalf("environment = %q, want %q", resolver.lastSpec.environment, "prod")
	}
}

func TestProviderResolvePropagatesResolverError(t *testing.T) {
	resolver := &fakeInfisicalResolver{resolveErr: errors.New("resolution failed")}
	setResolverFactoryForTest(t, func() infisicalResolver {
		return resolver
	})

	_, err := provider{}.Resolve("inf://app/secret")
	if err == nil {
		t.Fatalf("expected resolver error")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderResolveInvalidRef(t *testing.T) {
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
	_, err := provider{}.Resolve("infisical:very-sensitive-secret-id")
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), infisicalRefFormatErr) {
		t.Fatalf("unexpected error: %v", err)
	}
}
