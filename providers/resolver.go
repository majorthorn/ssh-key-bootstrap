package providers

import (
	"errors"
	"fmt"
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
		if strings.EqualFold(strings.TrimSpace(registeredProvider.Name()), providerName) {
			return
		}
	}
	providerRegistry = append(providerRegistry, provider)
}

func DefaultProviders() []Provider {
	providerRegistryMu.RLock()
	defer providerRegistryMu.RUnlock()

	registeredProviders := make([]Provider, len(providerRegistry))
	copy(registeredProviders, providerRegistry)
	return registeredProviders
}

func ResolveSecretReference(secretRef string, providers []Provider) (string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	if trimmedRef == "" {
		return "", errors.New("secret reference is empty")
	}
	if len(providers) == 0 {
		return "", errors.New("no providers configured")
	}

	var resolveErrors []string
	for _, provider := range providers {
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

	if len(resolveErrors) == 0 {
		return "", fmt.Errorf("no provider supports secret reference %q", trimmedRef)
	}
	return "", fmt.Errorf("resolve %q failed (%s)", trimmedRef, strings.Join(resolveErrors, "; "))
}
