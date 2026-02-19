package config

import (
	"fmt"
	"strings"
)

type configField struct {
	key   string
	label string
	kind  string
	get   func(*Options) string
}

func confirmLoadedConfigFields(programOptions *Options, loadedFieldNames map[string]bool, runtimeIO RuntimeIO) {
	if len(loadedFieldNames) == 0 {
		return
	}

	runtimeIO.Println("Loaded configuration values:")
	for _, field := range configFields() {
		if !loadedFieldNames[field.key] {
			continue
		}
		runtimeIO.Printf("%s: %s\n", field.label, previewFieldValue(field, programOptions))
	}
}

func configFields() []configField {
	return []configField{
		{key: "server", label: "Server", kind: "text", get: func(optionsValue *Options) string { return optionsValue.Server }},
		{key: "servers", label: "Servers", kind: "text", get: func(optionsValue *Options) string { return optionsValue.Servers }},
		{key: "user", label: "SSH User", kind: "text", get: func(optionsValue *Options) string { return optionsValue.User }},
		{key: "password", label: "SSH Password", kind: "password", get: func(optionsValue *Options) string { return optionsValue.Password }},
		{key: "passwordSecretRef", label: "Password Secret Ref", kind: "text", get: func(optionsValue *Options) string { return optionsValue.PasswordSecretRef }},
		{key: "keyInput", label: "Public Key Input", kind: "publickey", get: func(optionsValue *Options) string { return optionsValue.KeyInput }},
		{key: "port", label: "Default Port", kind: "text", get: func(optionsValue *Options) string { return fmt.Sprintf("%d", optionsValue.Port) }},
		{key: "timeoutSec", label: "Timeout (Seconds)", kind: "text", get: func(optionsValue *Options) string { return fmt.Sprintf("%d", optionsValue.TimeoutSec) }},
		{key: "insecureIgnoreHostKey", label: "Insecure Ignore Host Key", kind: "text", get: func(optionsValue *Options) string { return fmt.Sprintf("%t", optionsValue.InsecureIgnoreHostKey) }},
		{key: "knownHosts", label: "Known Hosts Path", kind: "text", get: func(optionsValue *Options) string { return optionsValue.KnownHosts }},
	}
}

func previewFieldValue(field configField, programOptions *Options) string {
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
