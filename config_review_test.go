package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestConfirmLoadedConfigFieldsNoLoadedValues(t *testing.T) {
	t.Parallel()

	programOptions := &options{}
	inputReader := bufio.NewReader(strings.NewReader(""))
	if err := confirmLoadedConfigFields(inputReader, programOptions, map[string]bool{}); err != nil {
		t.Fatalf("confirm loaded fields: %v", err)
	}
}

func TestConfirmLoadedConfigFieldsInvalidAnswerThenAccept(t *testing.T) {
	t.Parallel()

	programOptions := &options{server: "app01"}
	inputReader := bufio.NewReader(strings.NewReader("maybe\ny\n"))

	err := confirmLoadedConfigFields(inputReader, programOptions, map[string]bool{"server": true})
	if err != nil {
		t.Fatalf("confirm loaded fields: %v", err)
	}
	if programOptions.server != "app01" {
		t.Fatalf("server unexpectedly changed: %q", programOptions.server)
	}
}

func TestConfirmLoadedConfigFieldsEditPortWithRetry(t *testing.T) {
	t.Parallel()

	programOptions := &options{port: 22}
	inputReader := bufio.NewReader(strings.NewReader("n\ninvalid\n2222\n"))

	err := confirmLoadedConfigFields(inputReader, programOptions, map[string]bool{"port": true})
	if err != nil {
		t.Fatalf("confirm loaded fields: %v", err)
	}
	if programOptions.port != 2222 {
		t.Fatalf("port = %d, want %d", programOptions.port, 2222)
	}
}

func TestConfirmLoadedConfigFieldsAcceptAllRemaining(t *testing.T) {
	t.Parallel()

	programOptions := &options{
		server: "app01",
		user:   "deploy",
	}
	inputReader := bufio.NewReader(strings.NewReader("a\n"))

	err := confirmLoadedConfigFields(inputReader, programOptions, map[string]bool{
		"server": true,
		"user":   true,
	})
	if err != nil {
		t.Fatalf("confirm loaded fields: %v", err)
	}
	if programOptions.server != "app01" || programOptions.user != "deploy" {
		t.Fatalf("values unexpectedly changed: server=%q user=%q", programOptions.server, programOptions.user)
	}
}

func TestPromptReplacementValueForFieldPasswordInput(t *testing.T) {
	t.Parallel()

	programOptions := &options{}
	passwordField := configField{
		prompt:        "Password: ",
		passwordInput: true,
		set: func(optionsValue *options, value string) error {
			optionsValue.password = value
			return nil
		},
	}
	inputReader := bufio.NewReader(strings.NewReader("super-secret\n"))
	if err := promptReplacementValueForField(inputReader, programOptions, passwordField); err != nil {
		t.Fatalf("prompt replacement value: %v", err)
	}
	if programOptions.password != "super-secret" {
		t.Fatalf("password = %q, want %q", programOptions.password, "super-secret")
	}
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
