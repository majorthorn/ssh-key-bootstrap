package providers

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

type Provider interface {
	Name() string
	Supports(ref string) bool
	Resolve(ref string) (string, error)
}

var (
	providerRegistryMu sync.RWMutex
	providerRegistry   []Provider

	ErrEmptySecretReference  = errors.New("secret reference is empty")
	ErrNoProvidersConfigured = errors.New("no providers configured")
)

func RegisterProvider(provider Provider) {
	if provider == nil {
		return
	}

	providerName := strings.TrimSpace(provider.Name())
	if providerName == "" {
		return
	}

	providerRegistryMu.Lock()
	defer providerRegistryMu.Unlock()

	for _, registeredProvider := range providerRegistry {
		if registeredProvider == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(registeredProvider.Name()), providerName) {
			return
		}
	}
	providerRegistry = append(providerRegistry, provider)
}

func DefaultProviders() []Provider {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()

	registeredProviders := make([]Provider, 0, len(providerRegistry))
	for _, provider := range providerRegistry {
		if provider == nil {
			continue
		}
		if strings.TrimSpace(provider.Name()) == "" {
			continue
		}
		registeredProviders = append(registeredProviders, provider)
	}
	return registeredProviders
}

func ResolveSecretReference(secretRef string, providers []Provider) (string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	if trimmedRef == "" {
		return "", ErrEmptySecretReference
	}
	if len(providers) == 0 {
		return "", ErrNoProvidersConfigured
	}

	var resolveErrors []string
	hasUsableProvider := false
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		hasUsableProvider = true

		providerName := provider.Name()
		if strings.TrimSpace(providerName) == "" {
			providerName = "<unnamed provider>"
		}

		if !provider.Supports(trimmedRef) {
			continue
		}

		resolvedValue, err := provider.Resolve(trimmedRef)
		if err == nil {
			if strings.TrimSpace(resolvedValue) == "" {
				return "", fmt.Errorf("%s returned an empty secret", providerName)
			}
			return strings.TrimSpace(resolvedValue), nil
		}
		resolveErrors = append(resolveErrors, fmt.Sprintf("%s: %v", providerName, err))
	}

	if !hasUsableProvider {
		return "", ErrNoProvidersConfigured
	}

	if len(resolveErrors) == 0 {
		return "", errors.New("no provider supports the supplied secret reference")
	}
	return "", fmt.Errorf("secret reference resolution failed (%s)", strings.Join(resolveErrors, "; "))
}

func ResolveSecretReferenceWithProvider(secretRef, providerName string, providers []Provider) (string, error) {
	trimmedProviderName := strings.TrimSpace(providerName)
	if trimmedProviderName == "" {
		return "", errors.New("provider name is required")
	}

	selectedProvider, ok := ProviderByName(trimmedProviderName, providers)
	if !ok {
		validProviderNames := ProviderNames(providers)
		if len(validProviderNames) == 0 {
			return "", ErrNoProvidersConfigured
		}
		return "", fmt.Errorf("unknown provider %q (valid: %s)", trimmedProviderName, strings.Join(validProviderNames, ", "))
	}

	resolvedValue, err := selectedProvider.Resolve(strings.TrimSpace(secretRef))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(resolvedValue) == "" {
		return "", fmt.Errorf("%s returned an empty secret", selectedProvider.Name())
	}
	return strings.TrimSpace(resolvedValue), nil
}

func ProviderByName(providerName string, providers []Provider) (Provider, bool) {
	trimmedProviderName := strings.TrimSpace(providerName)
	if trimmedProviderName == "" {
		return nil, false
	}
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(provider.Name()), trimmedProviderName) {
			return provider, true
		}
	}
	return nil, false
}

func ProviderNames(providers []Provider) []string {
	providerNames := make([]string, 0, len(providers))
	seenNames := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		name := strings.TrimSpace(provider.Name())
		if name == "" {
			continue
		}

		key := strings.ToLower(name)
		if _, exists := seenNames[key]; exists {
			continue
		}
		seenNames[key] = struct{}{}
		providerNames = append(providerNames, name)
	}
	slices.Sort(providerNames)
	return providerNames
}
