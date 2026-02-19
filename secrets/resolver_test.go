package secrets

import (
	"errors"
	"strings"
	"testing"
)

type fakeProvider struct {
	name       string
	supports   bool
	value      string
	resolveErr error
}

func (provider fakeProvider) Name() string { return provider.name }
func (provider fakeProvider) Supports(ref string) bool {
	return provider.supports
}
func (provider fakeProvider) Resolve(ref string) (string, error) {
	if provider.resolveErr != nil {
		return "", provider.resolveErr
	}
	return provider.value, nil
}

func TestResolveSecretReference(t *testing.T) {
	t.Parallel()

	secretValue, err := ResolveSecretReference("bw://prod-ssh", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "secret-value"},
	})
	if err != nil {
		t.Fatalf("resolve secret: %v", err)
	}
	if secretValue != "secret-value" {
		t.Fatalf("got %q want %q", secretValue, "secret-value")
	}
}

func TestResolveSecretReferenceNoProvider(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("unknown://ref", []Provider{
		fakeProvider{name: "provider-a", supports: false},
	})
	if err == nil {
		t.Fatalf("expected no provider error")
	}
}

func TestResolveSecretReferenceProviderError(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("bw://prod-ssh", []Provider{
		fakeProvider{name: "provider-a", supports: true, resolveErr: errors.New("boom")},
	})
	if err == nil {
		t.Fatalf("expected provider error")
	}
}

func TestRegisterProviderDeduplicatesByName(t *testing.T) {
	providerRegistryMu.Lock()
	providerRegistry = nil
	providerRegistryMu.Unlock()

	RegisterProvider(fakeProvider{name: "duplicate-provider", supports: true, value: "a"})
	RegisterProvider(fakeProvider{name: "duplicate-provider", supports: true, value: "b"})

	registered := DefaultProviders()
	if len(registered) != 1 {
		t.Fatalf("expected 1 registered provider, got %d", len(registered))
	}
	if !strings.EqualFold(registered[0].Name(), "duplicate-provider") {
		t.Fatalf("unexpected provider name %q", registered[0].Name())
	}
}
