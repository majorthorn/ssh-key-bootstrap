package main

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type configField struct {
	key           string
	label         string
	prompt        string
	kind          string
	passwordInput bool
	get           func(*options) string
	set           func(*options, string) error
}

func confirmLoadedConfigFields(inputReader *bufio.Reader, programOptions *options, loadedFieldNames map[string]bool) error {
	if len(loadedFieldNames) == 0 {
		return nil
	}

	acceptAllRemainingValues := false
	fmt.Println("Review loaded configuration values. For each field choose: yes (y), no/edit (n), or yes to all remaining (a).")

	for _, field := range configFields() {
		if !loadedFieldNames[field.key] || acceptAllRemainingValues {
			continue
		}

		for {
			fmt.Printf("%s: %s\n", field.label, previewFieldValue(field, programOptions))

			answer, err := promptLine(inputReader, "Use this value? [y/n/a]: ")
			if err != nil {
				return err
			}

			switch strings.ToLower(strings.TrimSpace(answer)) {
			case "y", "yes":
				goto confirmed
			case "a", "all":
				acceptAllRemainingValues = true
				goto confirmed
			case "n", "no":
				if err := promptReplacementValueForField(inputReader, programOptions, field); err != nil {
					return err
				}
				goto confirmed
			default:
				fmt.Println("Please answer with y, n, or a.")
			}
		}

	confirmed:
	}

	return nil
}

func configFields() []configField {
	return []configField{
		{key: "server", label: "Server", prompt: "Enter updated server (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.server }, set: func(optionsValue *options, value string) error {
			optionsValue.server = strings.TrimSpace(value)
			return nil
		}},
		{key: "servers", label: "Servers", prompt: "Enter updated servers list (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.servers }, set: func(optionsValue *options, value string) error {
			optionsValue.servers = strings.TrimSpace(value)
			return nil
		}},
		{key: "serversFile", label: "Servers File", prompt: "Enter updated servers file path (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.serversFile }, set: func(optionsValue *options, value string) error {
			optionsValue.serversFile = strings.TrimSpace(value)
			return nil
		}},
		{key: "user", label: "SSH User", prompt: "Enter updated SSH username (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.user }, set: func(optionsValue *options, value string) error {
			optionsValue.user = strings.TrimSpace(value)
			return nil
		}},
		{key: "password", label: "SSH Password", prompt: "Enter updated SSH password (leave empty to clear): ", kind: "password", passwordInput: true, get: func(optionsValue *options) string { return optionsValue.password }, set: func(optionsValue *options, value string) error {
			optionsValue.password = strings.TrimSpace(value)
			return nil
		}},
		{key: "passwordSecretRef", label: "Password Secret Ref", prompt: "Enter updated password secret reference (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.passwordSecretRef }, set: func(optionsValue *options, value string) error {
			optionsValue.passwordSecretRef = strings.TrimSpace(value)
			return nil
		}},
		{key: "keyInput", label: "Public Key Input", prompt: "Enter updated key input (public key text or key file path, leave empty to clear): ", kind: "publickey", get: func(optionsValue *options) string { return optionsValue.keyInput }, set: func(optionsValue *options, value string) error {
			optionsValue.keyInput = strings.TrimSpace(value)
			return nil
		}},
		{key: "port", label: "Default Port", prompt: "Enter updated default port: ", kind: "text", get: func(optionsValue *options) string { return strconv.Itoa(optionsValue.port) }, set: func(optionsValue *options, value string) error {
			parsedPort, parseErr := strconv.Atoi(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("port must be an integer")
			}
			optionsValue.port = parsedPort
			return nil
		}},
		{key: "timeoutSec", label: "Timeout (Seconds)", prompt: "Enter updated timeout in seconds: ", kind: "text", get: func(optionsValue *options) string { return strconv.Itoa(optionsValue.timeoutSec) }, set: func(optionsValue *options, value string) error {
			parsedTimeout, parseErr := strconv.Atoi(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("timeout must be an integer")
			}
			optionsValue.timeoutSec = parsedTimeout
			return nil
		}},
		{key: "insecureIgnoreHostKey", label: "Insecure Ignore Host Key", prompt: "Enter updated insecure-ignore-host-key value (true/false): ", kind: "text", get: func(optionsValue *options) string { return strconv.FormatBool(optionsValue.insecureIgnoreHostKey) }, set: func(optionsValue *options, value string) error {
			parsedValue, parseErr := strconv.ParseBool(strings.TrimSpace(value))
			if parseErr != nil {
				return errors.New("value must be true or false")
			}
			optionsValue.insecureIgnoreHostKey = parsedValue
			return nil
		}},
		{key: "knownHosts", label: "Known Hosts Path", prompt: "Enter updated known_hosts path (leave empty to clear): ", kind: "text", get: func(optionsValue *options) string { return optionsValue.knownHosts }, set: func(optionsValue *options, value string) error {
			optionsValue.knownHosts = strings.TrimSpace(value)
			return nil
		}},
	}
}

func previewFieldValue(field configField, programOptions *options) string {
	value := field.get(programOptions)
	switch field.kind {
	case "password":
		return maskSensitiveValue(value)
	case "publickey":
		return previewTextValue(value, 120)
	default:
		return previewTextValue(value, 80)
	}
}

func promptReplacementValueForField(inputReader *bufio.Reader, programOptions *options, field configField) error {
	for {
		var replacementValue string
		var err error
		if field.passwordInput {
			replacementValue, err = promptPasswordAllowEmpty(inputReader, field.prompt)
		} else {
			replacementValue, err = promptLine(inputReader, field.prompt)
		}
		if err != nil {
			return err
		}
		if err := field.set(programOptions, replacementValue); err != nil {
			fmt.Println(err.Error())
			continue
		}
		return nil
	}
}

func previewTextValue(value string, maxLength int) string {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "<empty>"
	}
	if len(trimmedValue) <= maxLength {
		return trimmedValue
	}
	return trimmedValue[:maxLength] + "..."
}

func maskSensitiveValue(value string) string {
	if value == "" {
		return "<empty>"
	}
	visiblePrefixLength := 3
	if len(value) <= visiblePrefixLength {
		visiblePrefixLength = 1
	}
	return value[:visiblePrefixLength] + "***"
}
