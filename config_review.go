package main

import (
	"fmt"
	"strings"
)

type configField struct {
	key   string
	label string
	kind  string
	get   func(*options) string
}

func confirmLoadedConfigFields(programOptions *options, loadedFieldNames map[string]bool) {
	if len(loadedFieldNames) == 0 {
		return
	}

	outputPrintln("Loaded configuration values:")
	for _, field := range configFields() {
		if !loadedFieldNames[field.key] {
			continue
		}
		outputPrintf("%s: %s\n", field.label, previewFieldValue(field, programOptions))
	}
}

func configFields() []configField {
	return []configField{
		{key: "server", label: "Server", kind: "text", get: func(optionsValue *options) string { return optionsValue.server }},
		{key: "servers", label: "Servers", kind: "text", get: func(optionsValue *options) string { return optionsValue.servers }},
		{key: "user", label: "SSH User", kind: "text", get: func(optionsValue *options) string { return optionsValue.user }},
		{key: "password", label: "SSH Password", kind: "password", get: func(optionsValue *options) string { return optionsValue.password }},
		{key: "passwordSecretRef", label: "Password Secret Ref", kind: "text", get: func(optionsValue *options) string { return optionsValue.passwordSecretRef }},
		{key: "keyInput", label: "Public Key Input", kind: "publickey", get: func(optionsValue *options) string { return optionsValue.keyInput }},
		{key: "port", label: "Default Port", kind: "text", get: func(optionsValue *options) string { return fmt.Sprintf("%d", optionsValue.port) }},
		{key: "timeoutSec", label: "Timeout (Seconds)", kind: "text", get: func(optionsValue *options) string { return fmt.Sprintf("%d", optionsValue.timeoutSec) }},
		{key: "insecureIgnoreHostKey", label: "Insecure Ignore Host Key", kind: "text", get: func(optionsValue *options) string { return fmt.Sprintf("%t", optionsValue.insecureIgnoreHostKey) }},
		{key: "knownHosts", label: "Known Hosts Path", kind: "text", get: func(optionsValue *options) string { return optionsValue.knownHosts }},
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
