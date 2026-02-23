package infisical

import (
	"errors"
	"strings"
	"testing"
)

type fakeSDKClient struct {
	loginCalls int
	loginInput struct {
		clientID         string
		clientSecret     string
		organizationSlug string
	}
	loginErr error

	retrieveCalls int
	retrieveInput sdkRetrieveSecretOptions
	retrieveValue string
	retrieveErr   error
}

func (f *fakeSDKClient) LoginUniversalAuth(clientID, clientSecret, organizationSlug string) error {
	f.loginCalls++
	f.loginInput.clientID = clientID
	f.loginInput.clientSecret = clientSecret
	f.loginInput.organizationSlug = organizationSlug
	return f.loginErr
}

func (f *fakeSDKClient) RetrieveSecret(options sdkRetrieveSecretOptions) (string, error) {
	f.retrieveCalls++
	f.retrieveInput = options
	if f.retrieveErr != nil {
		return "", f.retrieveErr
	}
	return f.retrieveValue, nil
}

func setEnvGetterForTest(t *testing.T, valueMap map[string]string) {
	t.Helper()
	originalEnvGetter := envGetter
	envGetter = func(key string) string {
		return valueMap[key]
	}
	t.Cleanup(func() {
		envGetter = originalEnvGetter
	})
}

func setSDKClientFactoryForTest(t *testing.T, factory func(siteURL string) infisicalSDKClient) {
	t.Helper()
	originalFactory := newInfisicalSDKClient
	newInfisicalSDKClient = factory
	t.Cleanup(func() {
		newInfisicalSDKClient = originalFactory
	})
}

func resetSecretCacheForTest(t *testing.T) {
	t.Helper()
	cacheMu.Lock()
	secretCache = map[string]string{}
	cacheMu.Unlock()
}

func TestLoadSDKRuntimeConfigValidation(t *testing.T) {
	t.Run("missing universal auth client id", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-1",
			"INFISICAL_PROJECT_ID":                   "project-1",
			"INFISICAL_ENV":                          "prod",
		})

		_, err := loadSDKRuntimeConfig(secretRefSpec{secretName: "db/password"})
		if err == nil {
			t.Fatalf("expected missing client id error")
		}
		if !strings.Contains(err.Error(), "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID") {
			t.Fatalf("expected client id guidance, got %v", err)
		}
	})

	t.Run("missing universal auth client secret", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "client-1",
			"INFISICAL_PROJECT_ID":               "project-1",
			"INFISICAL_ENV":                      "prod",
		})

		_, err := loadSDKRuntimeConfig(secretRefSpec{secretName: "db/password"})
		if err == nil {
			t.Fatalf("expected missing client secret error")
		}
		if !strings.Contains(err.Error(), "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET") {
			t.Fatalf("expected client secret guidance, got %v", err)
		}
	})

	t.Run("missing project id", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-1",
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-1",
			"INFISICAL_ENV":                          "prod",
		})

		_, err := loadSDKRuntimeConfig(secretRefSpec{secretName: "db/password"})
		if err == nil {
			t.Fatalf("expected missing project id error")
		}
		if !strings.Contains(err.Error(), "INFISICAL_PROJECT_ID") {
			t.Fatalf("expected project id guidance, got %v", err)
		}
	})

	t.Run("missing environment", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-1",
			"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-1",
			"INFISICAL_PROJECT_ID":                   "project-1",
		})

		_, err := loadSDKRuntimeConfig(secretRefSpec{secretName: "db/password"})
		if err == nil {
			t.Fatalf("expected missing environment error")
		}
		if !strings.Contains(err.Error(), "INFISICAL_ENV") {
			t.Fatalf("expected environment guidance, got %v", err)
		}
	})
}

func TestNormalizeInfisicalSiteURLValidation(t *testing.T) {
	testCases := []struct {
		name        string
		rawURL      string
		expectError string
	}{
		{name: "http scheme", rawURL: "http://app.infisical.com", expectError: "must use https"},
		{name: "path included", rawURL: "https://app.infisical.com/api", expectError: "must not include a path"},
		{name: "query included", rawURL: "https://app.infisical.com?x=1", expectError: "without query"},
		{name: "missing host", rawURL: "https://", expectError: "must include a host"},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			_, err := normalizeInfisicalSiteURL(testCase.rawURL)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), testCase.expectError) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolveWithInfisicalSDKUsesQueryOverrides(t *testing.T) {
	fakeClient := &fakeSDKClient{retrieveValue: "resolved-secret"}
	capturedSiteURL := ""

	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-from-env",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-from-env",
		"INFISICAL_AUTH_ORGANIZATION_SLUG":       "org-slug",
		"INFISICAL_PROJECT_ID":                   "project-from-env",
		"INFISICAL_ENV":                          "env-from-env",
		"INFISICAL_SITE_URL":                     "https://self-host.example.com",
	})
	setSDKClientFactoryForTest(t, func(siteURL string) infisicalSDKClient {
		capturedSiteURL = siteURL
		return fakeClient
	})
	resetSecretCacheForTest(t)

	secretValue, err := resolveWithInfisicalSDK(secretRefSpec{
		secretName:  "ssh/password",
		projectID:   "project-from-ref",
		environment: "env-from-ref",
	})
	if err != nil {
		t.Fatalf("resolveWithInfisicalSDK() error = %v", err)
	}
	if secretValue != "resolved-secret" {
		t.Fatalf("secret value = %q, want %q", secretValue, "resolved-secret")
	}
	if capturedSiteURL != "https://self-host.example.com" {
		t.Fatalf("site URL = %q, want %q", capturedSiteURL, "https://self-host.example.com")
	}
	if fakeClient.loginCalls != 1 {
		t.Fatalf("login calls = %d, want 1", fakeClient.loginCalls)
	}
	if fakeClient.loginInput.clientID != "client-from-env" {
		t.Fatalf("client id = %q, want %q", fakeClient.loginInput.clientID, "client-from-env")
	}
	if fakeClient.loginInput.clientSecret != "secret-from-env" {
		t.Fatalf("client secret = %q, want %q", fakeClient.loginInput.clientSecret, "secret-from-env")
	}
	if fakeClient.loginInput.organizationSlug != "org-slug" {
		t.Fatalf("organization slug = %q, want %q", fakeClient.loginInput.organizationSlug, "org-slug")
	}
	if fakeClient.retrieveCalls != 1 {
		t.Fatalf("retrieve calls = %d, want 1", fakeClient.retrieveCalls)
	}
	if fakeClient.retrieveInput.secretKey != "ssh/password" {
		t.Fatalf("secret key = %q, want %q", fakeClient.retrieveInput.secretKey, "ssh/password")
	}
	if fakeClient.retrieveInput.projectID != "project-from-ref" {
		t.Fatalf("project id = %q, want %q", fakeClient.retrieveInput.projectID, "project-from-ref")
	}
	if fakeClient.retrieveInput.environment != "env-from-ref" {
		t.Fatalf("environment = %q, want %q", fakeClient.retrieveInput.environment, "env-from-ref")
	}
}

func TestResolveWithInfisicalSDKCachesSecrets(t *testing.T) {
	fakeClient := &fakeSDKClient{retrieveValue: "cached-secret"}

	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-1",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-1",
		"INFISICAL_PROJECT_ID":                   "project-1",
		"INFISICAL_ENV":                          "staging",
	})
	setSDKClientFactoryForTest(t, func(siteURL string) infisicalSDKClient {
		return fakeClient
	})
	resetSecretCacheForTest(t)

	for i := 0; i < 2; i++ {
		secretValue, err := resolveWithInfisicalSDK(secretRefSpec{secretName: "ssh/password"})
		if err != nil {
			t.Fatalf("resolveWithInfisicalSDK() call %d error = %v", i+1, err)
		}
		if secretValue != "cached-secret" {
			t.Fatalf("secret value = %q, want %q", secretValue, "cached-secret")
		}
	}

	if fakeClient.loginCalls != 1 {
		t.Fatalf("login calls = %d, want 1", fakeClient.loginCalls)
	}
	if fakeClient.retrieveCalls != 1 {
		t.Fatalf("retrieve calls = %d, want 1", fakeClient.retrieveCalls)
	}
}

func TestResolveWithInfisicalSDKPropagatesSDKErrors(t *testing.T) {
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":     "client-1",
		"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "secret-1",
		"INFISICAL_PROJECT_ID":                   "project-1",
		"INFISICAL_ENV":                          "dev",
	})

	t.Run("login error", func(t *testing.T) {
		fakeClient := &fakeSDKClient{loginErr: errors.New("login failed")}
		setSDKClientFactoryForTest(t, func(siteURL string) infisicalSDKClient {
			return fakeClient
		})
		resetSecretCacheForTest(t)

		_, err := resolveWithInfisicalSDK(secretRefSpec{secretName: "ssh/password"})
		if err == nil {
			t.Fatalf("expected login error")
		}
		if !strings.Contains(err.Error(), "login failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("retrieve error", func(t *testing.T) {
		fakeClient := &fakeSDKClient{retrieveErr: errors.New("retrieve failed")}
		setSDKClientFactoryForTest(t, func(siteURL string) infisicalSDKClient {
			return fakeClient
		})
		resetSecretCacheForTest(t)

		_, err := resolveWithInfisicalSDK(secretRefSpec{secretName: "ssh/password"})
		if err == nil {
			t.Fatalf("expected retrieve error")
		}
		if !strings.Contains(err.Error(), "retrieve failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
