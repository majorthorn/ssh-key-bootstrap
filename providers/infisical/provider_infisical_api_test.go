package infisical

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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

func setHTTPClientForTest(t *testing.T, client *http.Client) {
	t.Helper()
	originalHTTPClient := httpClient
	httpClient = client
	t.Cleanup(func() {
		httpClient = originalHTTPClient
	})
}

func resetSecretCacheForTest(t *testing.T) {
	t.Helper()
	cacheMu.Lock()
	secretCache = map[string]string{}
	cacheMu.Unlock()
}

func TestResolveWithInfisicalMissingToken(t *testing.T) {
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_PROJECT_ID": "project-1",
		"INFISICAL_ENV":        "prod",
	})
	resetSecretCacheForTest(t)

	_, err := resolveWithInfisical(secretRefSpec{secretName: "db/password"})
	if err == nil {
		t.Fatalf("expected missing token error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_TOKEN") {
		t.Fatalf("expected INFISICAL_TOKEN guidance, got %v", err)
	}
	if strings.Contains(err.Error(), "db/password") {
		t.Fatalf("error should not leak full secret identifier, got %v", err)
	}
}

func TestResolveWithInfisicalMissingProjectID(t *testing.T) {
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_TOKEN": "token-1",
		"INFISICAL_ENV":   "prod",
	})
	resetSecretCacheForTest(t)

	_, err := resolveWithInfisical(secretRefSpec{secretName: "db/password"})
	if err == nil {
		t.Fatalf("expected missing project id error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_PROJECT_ID") {
		t.Fatalf("expected INFISICAL_PROJECT_ID guidance, got %v", err)
	}
}

func TestResolveWithInfisicalMissingEnvironment(t *testing.T) {
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_TOKEN":      "token-1",
		"INFISICAL_PROJECT_ID": "project-1",
	})
	resetSecretCacheForTest(t)

	_, err := resolveWithInfisical(secretRefSpec{secretName: "db/password"})
	if err == nil {
		t.Fatalf("expected missing environment error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_ENV") {
		t.Fatalf("expected INFISICAL_ENV guidance, got %v", err)
	}
}

func TestResolveWithInfisicalAuthorizationHeader(t *testing.T) {
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("Authorization"), "Bearer token-123"; got != want {
			responseWriter.WriteHeader(http.StatusUnauthorized)
			_, _ = responseWriter.Write([]byte(fmt.Sprintf(`{"message":"bad auth: %s"}`, got)))
			return
		}
		_, _ = responseWriter.Write([]byte(`{"secretValue":"resolved-secret"}`))
	}))
	defer testServer.Close()

	setHTTPClientForTest(t, testServer.Client())
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_API_URL":    testServer.URL,
		"INFISICAL_TOKEN":      "token-123",
		"INFISICAL_PROJECT_ID": "project-1",
		"INFISICAL_ENV":        "dev",
	})
	resetSecretCacheForTest(t)

	resolvedSecret, err := resolveWithInfisical(secretRefSpec{secretName: "ssh/password"})
	if err != nil {
		t.Fatalf("resolveWithInfisical() error = %v", err)
	}
	if resolvedSecret != "resolved-secret" {
		t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "resolved-secret")
	}
}

func TestResolveWithInfisicalCachesSecrets(t *testing.T) {
	var requestCount int32
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = responseWriter.Write([]byte(`{"secretValue":"cached-secret"}`))
	}))
	defer testServer.Close()

	setHTTPClientForTest(t, testServer.Client())
	setEnvGetterForTest(t, map[string]string{
		"INFISICAL_API_URL":    testServer.URL,
		"INFISICAL_TOKEN":      "token-123",
		"INFISICAL_PROJECT_ID": "project-1",
		"INFISICAL_ENV":        "staging",
	})
	resetSecretCacheForTest(t)

	for i := 0; i < 2; i++ {
		resolvedSecret, err := resolveWithInfisical(secretRefSpec{secretName: "ssh/password"})
		if err != nil {
			t.Fatalf("resolveWithInfisical() call %d error = %v", i+1, err)
		}
		if resolvedSecret != "cached-secret" {
			t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "cached-secret")
		}
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}
