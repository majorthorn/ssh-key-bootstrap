package local

import (
	"strings"
	"testing"
)

func setEnvGetterForTest(t *testing.T, values map[string]string) {
	t.Helper()
	originalGetter := getEnv
	getEnv = func(key string) string {
		return values[key]
	}
	t.Cleanup(func() {
		getEnv = originalGetter
	})
}

func TestProviderNameAndSupport(t *testing.T) {
	localProvider := provider{}
	if localProvider.Name() != "local" {
		t.Fatalf("Name() = %q, want %q", localProvider.Name(), "local")
	}
	if !localProvider.Supports("local://password") {
		t.Fatalf("expected local:// ref to be supported")
	}
	if localProvider.Supports("bw://secret-id") {
		t.Fatalf("did not expect bw:// ref to be supported")
	}
}

func TestProviderResolve(t *testing.T) {
	t.Run("returns password from env", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{
			"PASSWORD": "local-password",
		})
		resolvedPassword, err := provider{}.Resolve("")
		if err != nil {
			t.Fatalf("Resolve() error = %v", err)
		}
		if resolvedPassword != "local-password" {
			t.Fatalf("Resolve() = %q, want %q", resolvedPassword, "local-password")
		}
	})

	t.Run("errors when missing password", func(t *testing.T) {
		setEnvGetterForTest(t, map[string]string{})
		_, err := provider{}.Resolve("")
		if err == nil {
			t.Fatalf("expected missing password error")
		}
		if !strings.Contains(err.Error(), "PASSWORD") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
