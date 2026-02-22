package bitwarden

import (
	"errors"
	"strings"
)

func parseSecretID(secretRef string) (string, error) {
	trimmedRef := strings.TrimSpace(secretRef)
	switch {
	case strings.HasPrefix(strings.ToLower(trimmedRef), "bw://"):
		trimmedRef = trimmedRef[len("bw://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "bitwarden://"):
		trimmedRef = trimmedRef[len("bitwarden://"):]
	case strings.HasPrefix(strings.ToLower(trimmedRef), "bw:"):
		trimmedRef = trimmedRef[len("bw:"):]
	default:
		return "", errors.New("invalid bitwarden secret ref")
	}

	trimmedRef = strings.TrimSpace(trimmedRef)
	if trimmedRef == "" {
		return "", errors.New("bitwarden secret ref is missing secret identifier")
	}
	return trimmedRef, nil
}
