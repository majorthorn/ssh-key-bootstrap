package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ApplyDotEnvWithMetadata(programOptions *Options) (map[string]bool, error) {
	if programOptions == nil {
		return nil, errors.New("program options are required")
	}

	loadedFieldNames := map[string]bool{}
	if strings.TrimSpace(programOptions.EnvFile) == "" {
		return loadedFieldNames, nil
	}

	envFilePath, err := expandHomePath(strings.TrimSpace(programOptions.EnvFile))
	if err != nil {
		return nil, fmt.Errorf("resolve .env path: %w", err)
	}
	envBytes, err := os.ReadFile(envFilePath) // #nosec G304 -- dotenv path is explicit user input
	if err != nil {
		return nil, fmt.Errorf("read .env file: %w", err)
	}

	parsedEnvValues, err := parseDotEnvContent(string(envBytes))
	if err != nil {
		return nil, fmt.Errorf("parse .env file: %w", err)
	}

	setLoaded := func(fieldName string, apply func() error) error {
		if err := apply(); err != nil {
			return err
		}
		loadedFieldNames[fieldName] = true
		return nil
	}

	setEnvOption := func(envKey, fieldName string, trim bool, setter func(string)) {
		if value, ok := parsedEnvValues[envKey]; ok {
			if trim {
				value = strings.TrimSpace(value)
			}
			_ = setLoaded(fieldName, func() error {
				setter(value)
				return nil
			})
		}
	}

	setEnvOption("SERVER", "server", true, func(v string) {
		programOptions.Server = v
	})
	setEnvOption("SERVERS", "servers", true, func(v string) {
		programOptions.Servers = v
	})
	setEnvOption("USER", "user", true, func(v string) {
		programOptions.User = v
	})
	setEnvOption("PASSWORD", "password", false, func(v string) {
		programOptions.Password = v
	})
	setEnvOption("PASSWORD_SECRET_REF", "passwordSecretRef", true, func(v string) {
		programOptions.PasswordSecretRef = v
	})
	setEnvOption("PASSWORD_PROVIDER", "passwordProvider", true, func(v string) {
		programOptions.PasswordProvider = strings.ToLower(v)
	})

	keyInputs := collectNonEmptyDotEnvValues(parsedEnvValues, "KEY", "PUBKEY", "PUBKEY_FILE")
	if len(keyInputs) > 1 {
		return nil, fmt.Errorf(".env must set only one of KEY/PUBKEY/PUBKEY_FILE")
	}
	if len(keyInputs) == 1 {
		if err := setLoaded("keyInput", func() error {
			programOptions.KeyInput = keyInputs[0]
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if portValue, ok := parsedEnvValues["PORT"]; ok {
		if err := setLoaded("port", func() error {
			portNumber, conversionErr := strconv.Atoi(strings.TrimSpace(portValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key PORT must be an integer: %w", conversionErr)
			}
			programOptions.Port = portNumber
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if timeoutValue, ok := parsedEnvValues["TIMEOUT"]; ok {
		if err := setLoaded("timeoutSec", func() error {
			timeoutSeconds, conversionErr := strconv.Atoi(strings.TrimSpace(timeoutValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key TIMEOUT must be an integer: %w", conversionErr)
			}
			programOptions.TimeoutSec = timeoutSeconds
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if insecureValue, ok := parsedEnvValues["INSECURE_IGNORE_HOST_KEY"]; ok {
		if err := setLoaded("insecureIgnoreHostKey", func() error {
			insecureMode, conversionErr := strconv.ParseBool(strings.TrimSpace(insecureValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key INSECURE_IGNORE_HOST_KEY must be a boolean: %w", conversionErr)
			}
			programOptions.InsecureIgnoreHostKey = insecureMode
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if knownHostsValue, ok := parsedEnvValues["KNOWN_HOSTS"]; ok {
		if err := setLoaded("knownHosts", func() error {
			programOptions.KnownHosts = strings.TrimSpace(knownHostsValue)
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return loadedFieldNames, nil
}
