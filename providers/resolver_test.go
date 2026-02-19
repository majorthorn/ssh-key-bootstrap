package providers

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

func TestResolveSecretReferenceEmptyRef(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("   ", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "secret-value"},
	})
	if err == nil {
		t.Fatalf("expected empty-ref error")
	}
	if !strings.Contains(err.Error(), "secret reference is empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSecretReferenceProviderReturnsEmptySecret(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("bw://prod-ssh", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "   "},
	})
	if err == nil {
		t.Fatalf("expected empty-secret error")
	}
	if !strings.Contains(err.Error(), "returned an empty secret") {
		t.Fatalf("unexpected error: %v", err)
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

func TestRegisterProviderIgnoresNilAndBlankName(t *testing.T) {
	providerRegistryMu.Lock()
	providerRegistry = nil
	providerRegistryMu.Unlock()

	RegisterProvider(nil)
	RegisterProvider(fakeProvider{name: "   ", supports: true, value: "ignored"})

	registered := DefaultProviders()
	if len(registered) != 0 {
		t.Fatalf("expected no registered providers, got %d", len(registered))
	}
}

func TestDefaultProvidersReturnsCopy(t *testing.T) {
	providerRegistryMu.Lock()
	providerRegistry = nil
	providerRegistryMu.Unlock()

	RegisterProvider(fakeProvider{name: "copy-check-provider", supports: true, value: "a"})

	registered := DefaultProviders()
	if len(registered) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(registered))
	}

	registered[0] = fakeProvider{name: "tampered-provider", supports: true, value: "b"}

	originalRegistry := DefaultProviders()
	if len(originalRegistry) != 1 {
		t.Fatalf("expected registry length to remain 1, got %d", len(originalRegistry))
	}
	if !strings.EqualFold(originalRegistry[0].Name(), "copy-check-provider") {
		t.Fatalf("registry was mutated through returned slice: %q", originalRegistry[0].Name())
	}
}
