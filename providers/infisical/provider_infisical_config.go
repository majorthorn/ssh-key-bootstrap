package infisical

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type infisicalMode string

const (
	modeCLI infisicalMode = "cli"
	modeAPI infisicalMode = "api"

	defaultCLIBinary  = "infisical"
	defaultCLITimeout = 10 * time.Second
)

type modeConfig struct {
	mode       infisicalMode
	cliBinary  string
	cliTimeout time.Duration
}

var lookupEnv = os.LookupEnv

func loadModeConfig() (modeConfig, error) {
	configuredMode, exists := lookupEnv("INFISICAL_MODE")
	modeValue := strings.ToLower(strings.TrimSpace(configuredMode))
	if !exists || modeValue == "" {
		modeValue = string(modeCLI)
	}

	if modeValue != string(modeCLI) && modeValue != string(modeAPI) {
		return modeConfig{}, fmt.Errorf("invalid INFISICAL_MODE %q (allowed: cli, api)", configuredMode)
	}

	cliBinary := defaultCLIBinary
	if configuredCLIBinary, exists := lookupEnv("INFISICAL_CLI_BIN"); exists {
		if trimmed := strings.TrimSpace(configuredCLIBinary); trimmed != "" {
			cliBinary = trimmed
		}
	}

	cliTimeout := defaultCLITimeout
	if configuredTimeout, exists := lookupEnv("INFISICAL_CLI_TIMEOUT"); exists {
		trimmedTimeout := strings.TrimSpace(configuredTimeout)
		if trimmedTimeout != "" {
			parsedTimeout, err := time.ParseDuration(trimmedTimeout)
			if err != nil {
				return modeConfig{}, fmt.Errorf("invalid INFISICAL_CLI_TIMEOUT %q: %w", configuredTimeout, err)
			}
			if parsedTimeout <= 0 {
				return modeConfig{}, fmt.Errorf("invalid INFISICAL_CLI_TIMEOUT %q: must be > 0", configuredTimeout)
			}
			cliTimeout = parsedTimeout
		}
	}

	return modeConfig{
		mode:       infisicalMode(modeValue),
		cliBinary:  cliBinary,
		cliTimeout: cliTimeout,
	}, nil
}
