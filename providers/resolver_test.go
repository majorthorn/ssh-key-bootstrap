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

func TestResolveSecretReferenceNoProvidersConfigured(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("bw://prod-ssh", nil)
	if err == nil {
		t.Fatalf("expected no-providers-configured error")
	}
	if !errors.Is(err, ErrNoProvidersConfigured) {
		t.Fatalf("expected ErrNoProvidersConfigured, got %v", err)
	}
	if !strings.Contains(err.Error(), "no providers configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveSecretReferenceAllNilProviders(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReference("bw://prod-ssh", []Provider{nil, nil})
	if err == nil {
		t.Fatalf("expected no-providers-configured error")
	}
	if !errors.Is(err, ErrNoProvidersConfigured) {
		t.Fatalf("expected ErrNoProvidersConfigured, got %v", err)
	}
}

func TestResolveSecretReferenceSkipsNilProviders(t *testing.T) {
	t.Parallel()

	secretValue, err := ResolveSecretReference("bw://prod-ssh", []Provider{
		nil,
		fakeProvider{name: "provider-a", supports: true, value: "secret-value"},
	})
	if err != nil {
		t.Fatalf("resolve secret with nil provider present: %v", err)
	}
	if secretValue != "secret-value" {
		t.Fatalf("got %q want %q", secretValue, "secret-value")
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

func TestResolveSecretReferenceErrorDoesNotLeakFullRef(t *testing.T) {
	t.Parallel()

	secretRef := "infisical://very-sensitive-secret-name"
	_, err := ResolveSecretReference(secretRef, []Provider{
		fakeProvider{name: "provider-a", supports: true, resolveErr: errors.New("boom")},
	})
	if err == nil {
		t.Fatalf("expected provider error")
	}
	if strings.Contains(err.Error(), secretRef) {
		t.Fatalf("error leaked full secret reference: %v", err)
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
	if !errors.Is(err, ErrEmptySecretReference) {
		t.Fatalf("expected ErrEmptySecretReference, got %v", err)
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

func TestProviderByName(t *testing.T) {
	t.Parallel()

	selectedProvider, ok := ProviderByName("provider-a", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "secret-value"},
	})
	if !ok {
		t.Fatalf("expected provider match")
	}
	if selectedProvider.Name() != "provider-a" {
		t.Fatalf("provider name = %q, want %q", selectedProvider.Name(), "provider-a")
	}

	_, ok = ProviderByName("missing", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "secret-value"},
	})
	if ok {
		t.Fatalf("did not expect provider match")
	}
}

func TestProviderNames(t *testing.T) {
	t.Parallel()

	names := ProviderNames([]Provider{
		fakeProvider{name: "provider-b", supports: true, value: "a"},
		fakeProvider{name: "provider-a", supports: true, value: "b"},
		fakeProvider{name: "PROVIDER-A", supports: true, value: "c"},
		nil,
		fakeProvider{name: "  ", supports: true, value: "d"},
	})
	if got, want := strings.Join(names, ","), "provider-a,provider-b"; got != want {
		t.Fatalf("ProviderNames() = %q, want %q", got, want)
	}
}

func TestResolveSecretReferenceWithProvider(t *testing.T) {
	t.Parallel()

	resolvedValue, err := ResolveSecretReferenceWithProvider("ignored://value", "provider-a", []Provider{
		fakeProvider{name: "provider-a", supports: false, value: "named-resolution"},
	})
	if err != nil {
		t.Fatalf("ResolveSecretReferenceWithProvider() error = %v", err)
	}
	if resolvedValue != "named-resolution" {
		t.Fatalf("resolved value = %q, want %q", resolvedValue, "named-resolution")
	}
}

func TestResolveSecretReferenceWithProviderUnknown(t *testing.T) {
	t.Parallel()

	_, err := ResolveSecretReferenceWithProvider("ignored://value", "missing-provider", []Provider{
		fakeProvider{name: "provider-a", supports: true, value: "a"},
		fakeProvider{name: "provider-b", supports: true, value: "b"},
	})
	if err == nil {
		t.Fatalf("expected unknown provider error")
	}
	if !strings.Contains(err.Error(), "missing-provider") || !strings.Contains(err.Error(), "provider-a") {
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

func TestRegisterProviderSkipsNilRegistryEntries(t *testing.T) {
	providerRegistryMu.Lock()
	providerRegistry = []Provider{nil}
	providerRegistryMu.Unlock()

	RegisterProvider(fakeProvider{name: "safe-provider", supports: true, value: "ok"})

	registered := DefaultProviders()
	if len(registered) != 1 {
		t.Fatalf("expected 1 valid registered provider, got %d", len(registered))
	}
	if registered[0] == nil {
		t.Fatalf("expected first entry to be a registered provider")
	}
	if !strings.EqualFold(registered[0].Name(), "safe-provider") {
		t.Fatalf("unexpected provider name %q", registered[0].Name())
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

func TestDefaultProvidersFiltersInvalidEntries(t *testing.T) {
	providerRegistryMu.Lock()
	providerRegistry = []Provider{
		nil,
		fakeProvider{name: "   ", supports: true, value: "ignored"},
		fakeProvider{name: "valid-provider", supports: true, value: "ok"},
	}
	providerRegistryMu.Unlock()

	registered := DefaultProviders()
	if len(registered) != 1 {
		t.Fatalf("expected only valid providers, got %d", len(registered))
	}
	if !strings.EqualFold(registered[0].Name(), "valid-provider") {
		t.Fatalf("unexpected provider name %q", registered[0].Name())
	}
}
