package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func applyDotEnvConfigFile(programOptions *options) error {
	_, err := applyDotEnvConfigFileWithMetadata(programOptions)
	return err
}

func applyDotEnvConfigFileWithMetadata(programOptions *options) (map[string]bool, error) {
	loadedFieldNames := map[string]bool{}
	if strings.TrimSpace(programOptions.envFile) == "" {
		return loadedFieldNames, nil
	}

	envFilePath, err := expandHomePath(strings.TrimSpace(programOptions.envFile))
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

	if serverValue, ok := parsedEnvValues["SERVER"]; ok {
		_ = setLoaded("server", func() error { programOptions.server = strings.TrimSpace(serverValue); return nil })
	}
	if serversValue, ok := parsedEnvValues["SERVERS"]; ok {
		_ = setLoaded("servers", func() error { programOptions.servers = strings.TrimSpace(serversValue); return nil })
	}
	if userValue, ok := parsedEnvValues["USER"]; ok {
		_ = setLoaded("user", func() error { programOptions.user = strings.TrimSpace(userValue); return nil })
	}
	if passwordValue, ok := parsedEnvValues["PASSWORD"]; ok {
		_ = setLoaded("password", func() error { programOptions.password = passwordValue; return nil })
	}
	if passwordSecretRefValue, ok := parsedEnvValues["PASSWORD_SECRET_REF"]; ok {
		_ = setLoaded("passwordSecretRef", func() error {
			programOptions.passwordSecretRef = strings.TrimSpace(passwordSecretRefValue)
			return nil
		})
	}
	keyInputs := collectNonEmptyDotEnvValues(parsedEnvValues, "KEY", "PUBKEY", "PUBKEY_FILE")
	if len(keyInputs) > 1 {
		return nil, fmt.Errorf(".env must set only one of KEY/PUBKEY/PUBKEY_FILE")
	}
	if len(keyInputs) == 1 {
		_ = setLoaded("keyInput", func() error { programOptions.keyInput = keyInputs[0]; return nil })
	}
	if portValue, ok := parsedEnvValues["PORT"]; ok {
		if err := setLoaded("port", func() error {
			portNumber, conversionErr := strconv.Atoi(strings.TrimSpace(portValue))
			if conversionErr != nil {
				return fmt.Errorf(".env key PORT must be an integer: %w", conversionErr)
			}
			programOptions.port = portNumber
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
			programOptions.timeoutSec = timeoutSeconds
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
			programOptions.insecureIgnoreHostKey = insecureMode
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if knownHostsValue, ok := parsedEnvValues["KNOWN_HOSTS"]; ok {
		_ = setLoaded("knownHosts", func() error { programOptions.knownHosts = strings.TrimSpace(knownHostsValue); return nil })
	}

	return loadedFieldNames, nil
}
