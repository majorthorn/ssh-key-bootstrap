package local

import (
	"errors"
	"os"
	"strings"

	"ssh-key-bootstrap/providers"
)

type provider struct{}

var getEnv = os.Getenv

func init() {
	providers.RegisterProvider(provider{})
}

func (provider) Name() string {
	return "local"
}

func (provider) Supports(secretRef string) bool {
	normalizedRef := strings.ToLower(strings.TrimSpace(secretRef))
	return strings.HasPrefix(normalizedRef, "local://")
}

func (provider) Resolve(_ string) (string, error) {
	password := getEnv("PASSWORD")
	if strings.TrimSpace(password) == "" {
		return "", errors.New("local password is required (set PASSWORD or run interactively)")
	}
	return password, nil
}
