package infisical

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func mapEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestProviderSupports(t *testing.T) {
	t.Parallel()

	providerInstance := newProvider()
	testCases := []struct {
		ref     string
		support bool
	}{
		{ref: "infisical://ssh/password", support: true},
		{ref: "infisical:ssh/password", support: true},
		{ref: "inf://ssh/password", support: true},
		{ref: "inf:ssh/password", support: true},
		{ref: "  INF://ssh/password  ", support: true},
		{ref: "bw://ssh/password", support: false},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.ref, func(t *testing.T) {
			t.Parallel()
			actual := providerInstance.Supports(testCase.ref)
			if actual != testCase.support {
				t.Fatalf("Supports(%q) = %v, want %v", testCase.ref, actual, testCase.support)
			}
		})
	}
}

func TestResolveMissingToken(t *testing.T) {
	t.Parallel()

	providerInstance := &provider{
		httpClient: &http.Client{},
		envGet: mapEnv(map[string]string{
			"INFISICAL_PROJECT_ID": "project-1",
			"INFISICAL_ENV":        "prod",
		}),
		cache: map[string]string{},
	}

	_, err := providerInstance.Resolve("infisical://db/password")
	if err == nil {
		t.Fatalf("expected missing token error")
	}
	if !strings.Contains(err.Error(), "INFISICAL_TOKEN") {
		t.Fatalf("expected INFISICAL_TOKEN guidance, got %v", err)
	}
	if strings.Contains(err.Error(), "db/password") {
		t.Fatalf("error should not leak full secret reference details: %v", err)
	}
}

func TestResolveEnvTokenOverridesStaticConfigToken(t *testing.T) {
	t.Parallel()

	var receivedAuthorization string
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		receivedAuthorization = request.Header.Get("Authorization")
		_, _ = responseWriter.Write([]byte(`{"secretValue":"resolved-password"}`))
	}))
	defer testServer.Close()

	providerInstance := &provider{
		httpClient: testServer.Client(),
		envGet: mapEnv(map[string]string{
			"INFISICAL_API_URL":    testServer.URL,
			"INFISICAL_TOKEN":      "env-token",
			"INFISICAL_PROJECT_ID": "project-1",
			"INFISICAL_ENV":        "prod",
		}),
		staticConfig: providerConfig{Token: "config-token"},
		cache:        map[string]string{},
	}

	resolvedSecret, err := providerInstance.Resolve("inf://db/password")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolvedSecret != "resolved-password" {
		t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "resolved-password")
	}
	if receivedAuthorization != "Bearer env-token" {
		t.Fatalf("Authorization header = %q, want %q", receivedAuthorization, "Bearer env-token")
	}
}

func TestResolveUsesAuthorizationHeader(t *testing.T) {
	t.Parallel()

	testServer := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("Authorization"), "Bearer token-123"; got != want {
			responseWriter.WriteHeader(http.StatusUnauthorized)
			_, _ = responseWriter.Write([]byte(fmt.Sprintf(`{"message":"authorization mismatch: %s"}`, got)))
			return
		}
		_, _ = responseWriter.Write([]byte(`{"secret":{"secretValue":"ok-secret"}}`))
	}))
	defer testServer.Close()

	providerInstance := &provider{
		httpClient: testServer.Client(),
		envGet: mapEnv(map[string]string{
			"INFISICAL_API_URL":    testServer.URL,
			"INFISICAL_TOKEN":      "token-123",
			"INFISICAL_PROJECT_ID": "project-1",
			"INFISICAL_ENV":        "dev",
		}),
		cache: map[string]string{},
	}

	resolvedSecret, err := providerInstance.Resolve("inf:my-secret")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolvedSecret != "ok-secret" {
		t.Fatalf("resolved secret = %q, want %q", resolvedSecret, "ok-secret")
	}
}

func TestResolveCachesValues(t *testing.T) {
	t.Parallel()

	var requestCount int32
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_, _ = responseWriter.Write([]byte(`{"secretValue":"cached-secret"}`))
	}))
	defer testServer.Close()

	providerInstance := &provider{
		httpClient: testServer.Client(),
		envGet: mapEnv(map[string]string{
			"INFISICAL_API_URL":    testServer.URL,
			"INFISICAL_TOKEN":      "token-123",
			"INFISICAL_PROJECT_ID": "project-1",
			"INFISICAL_ENV":        "staging",
		}),
		cache: map[string]string{},
	}

	for i := 0; i < 2; i++ {
		resolvedSecret, err := providerInstance.Resolve("infisical://shared/password")
		if err != nil {
			t.Fatalf("Resolve() call %d error = %v", i+1, err)
		}
		if resolvedSecret != "cached-secret" {
			t.Fatalf("Resolve() call %d secret = %q, want %q", i+1, resolvedSecret, "cached-secret")
		}
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("request count = %d, want 1", requestCount)
	}
}
