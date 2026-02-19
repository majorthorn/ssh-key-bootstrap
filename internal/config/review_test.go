package config

import (
	"strings"
	"testing"
)

type testRuntimeIO struct{}

func (testRuntimeIO) PromptLine(string) (string, error) { return "", nil }
func (testRuntimeIO) Println(arguments ...any)          {}
func (testRuntimeIO) Printf(string, ...any)             {}
func (testRuntimeIO) IsInteractive() bool               { return true }

func TestConfirmLoadedConfigFieldsNoLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &Options{}
	confirmLoadedConfigFields(programOptions, map[string]bool{}, testRuntimeIO{})
}

func TestConfirmLoadedConfigFieldsLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &Options{
		Server:   "app01",
		Port:     22,
		Password: "super-secret",
	}

	confirmLoadedConfigFields(programOptions, map[string]bool{
		"server":   true,
		"port":     true,
		"password": true,
	}, testRuntimeIO{})
}

func TestPreviewHelpers(t *testing.T) {
	t.Parallel()

	if got := previewTextValue("", 10); got != "<empty>" {
		t.Fatalf("previewTextValue(empty) = %q, want %q", got, "<empty>")
	}
	if got := previewTextValue("abcdefghijk", 5); got != "abcde..." {
		t.Fatalf("previewTextValue(truncate) = %q, want %q", got, "abcde...")
	}
	if got := maskSensitiveValue("abcd"); got != "<redacted>" {
		t.Fatalf("maskSensitiveValue = %q, want %q", got, "<redacted>")
	}
	if got := maskSensitiveValue("a"); got != "<redacted>" {
		t.Fatalf("maskSensitiveValue(short) = %q, want %q", got, "<redacted>")
	}

	programOptions := &Options{
		Password: "super-secret",
		KeyInput: strings.Repeat("k", 150),
		Server:   "host01",
	}

	passwordPreview := previewFieldValue(configField{
		kind: "password",
		get:  func(optionsValue *Options) string { return optionsValue.Password },
	}, programOptions)
	if passwordPreview != "<redacted>" {
		t.Fatalf("password preview not redacted: %q", passwordPreview)
	}

	keyPreview := previewFieldValue(configField{
		kind: "publickey",
		get:  func(optionsValue *Options) string { return optionsValue.KeyInput },
	}, programOptions)
	if !strings.HasSuffix(keyPreview, "...") {
		t.Fatalf("public key preview should be truncated: %q", keyPreview)
	}

	textPreview := previewFieldValue(configField{
		kind: "text",
		get:  func(optionsValue *Options) string { return optionsValue.Server },
	}, programOptions)
	if textPreview != "host01" {
		t.Fatalf("text preview = %q, want %q", textPreview, "host01")
	}
}
