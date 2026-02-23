package bitwarden

import (
	"errors"
	"strings"
)

const bitwardenRefFormatErr = "invalid secret reference format: expected bw://<value> or bitwarden://<value>"

func parseSecretID(secretRef string) (string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	switch {
	case strings.HasPrefix(strings.ToLower(trimmedRef), "bw://"):
		trimmedRef = trimmedRef[len("bw://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "bitwarden://"):
		trimmedRef = trimmedRef[len("bitwarden://"):]
	default:
		return "", errors.New(bitwardenRefFormatErr)
	}

	trimmedRef = strings.TrimSpace(trimmedRef)
	if trimmedRef == "" {
		return "", errors.New("bitwarden secret ref is missing secret identifier")
	}
	return trimmedRef, nil
}
