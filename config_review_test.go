package main

import (
	"strings"
	"testing"
)

func TestConfirmLoadedConfigFieldsNoLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &options{}
	confirmLoadedConfigFields(programOptions, map[string]bool{})
}

func TestConfirmLoadedConfigFieldsLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &options{
		server:   "app01",
		port:     22,
		password: "super-secret",
	}

	confirmLoadedConfigFields(programOptions, map[string]bool{
		"server":   true,
		"port":     true,
		"password": true,
	})
}

func TestPreviewHelpers(t *testing.T) {
	t.Parallel()

	if got := previewTextValue("", 10); got != "<empty>" {
		t.Fatalf("previewTextValue(empty) = %q, want %q", got, "<empty>")
	}
	if got := previewTextValue("abcdefghijk", 5); got != "abcde..." {
		t.Fatalf("previewTextValue(truncate) = %q, want %q", got, "abcde...")
	}
	if got := maskSensitiveValue("abcd"); got != "abc***" {
		t.Fatalf("maskSensitiveValue = %q, want %q", got, "abc***")
	}
	if got := maskSensitiveValue("a"); got != "a***" {
		t.Fatalf("maskSensitiveValue(short) = %q, want %q", got, "a***")
	}

	programOptions := &options{
		password: "super-secret",
		keyInput: strings.Repeat("k", 150),
		server:   "host01",
	}

	passwordPreview := previewFieldValue(configField{
		kind: "password",
		get:  func(optionsValue *options) string { return optionsValue.password },
	}, programOptions)
	if !strings.HasSuffix(passwordPreview, "***") {
		t.Fatalf("password preview not masked: %q", passwordPreview)
	}

	keyPreview := previewFieldValue(configField{
		kind: "publickey",
		get:  func(optionsValue *options) string { return optionsValue.keyInput },
	}, programOptions)
	if !strings.HasSuffix(keyPreview, "...") {
		t.Fatalf("public key preview should be truncated: %q", keyPreview)
	}

	textPreview := previewFieldValue(configField{
		kind: "text",
		get:  func(optionsValue *options) string { return optionsValue.server },
	}, programOptions)
	if textPreview != "host01" {
		t.Fatalf("text preview = %q, want %q", textPreview, "host01")
	}
}
