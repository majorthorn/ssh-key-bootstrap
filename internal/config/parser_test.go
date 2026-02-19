package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDotEnvContentParsesCommonForms(t *testing.T) {
	t.Parallel()

	content := "\n# comment\nserver = app01\nexport USER=admin\nPASSWORD='p@ss word'\nKEY=\"line\\nnext\"\nPORT=2200 # inline comment\nEMPTY=\n"
	parsed, err := parseDotEnvContent(content)
	if err != nil {
		t.Fatalf("parseDotEnvContent() error = %v", err)
	}

	if parsed["SERVER"] != "app01" {
		t.Fatalf("SERVER = %q, want %q", parsed["SERVER"], "app01")
	}
	if parsed["USER"] != "admin" {
		t.Fatalf("USER = %q, want %q", parsed["USER"], "admin")
	}
	if parsed["PASSWORD"] != "p@ss word" {
		t.Fatalf("PASSWORD = %q, want %q", parsed["PASSWORD"], "p@ss word")
	}
	if parsed["KEY"] != "line\nnext" {
		t.Fatalf("KEY = %q, want %q", parsed["KEY"], "line\nnext")
	}
	if parsed["PORT"] != "2200" {
		t.Fatalf("PORT = %q, want %q", parsed["PORT"], "2200")
	}
	if parsed["EMPTY"] != "" {
		t.Fatalf("EMPTY = %q, want empty", parsed["EMPTY"])
	}
}

func TestParseDotEnvContentInvalidLine(t *testing.T) {
	t.Parallel()

	_, err := parseDotEnvContent("SERVER\nUSER=admin\n")
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error %q should include line number", err)
	}
}

func TestParseDotEnvValueCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		raw   string
		want  string
		isErr bool
	}{
		{name: "empty", raw: "", want: ""},
		{name: "doubleQuoted", raw: "\"hello\\nworld\"", want: "hello\nworld"},
		{name: "singleQuoted", raw: "' value # literal '", want: " value # literal "},
		{name: "inlineComment", raw: "value # comment", want: "value"},
		{name: "plainTrimmed", raw: "  value  ", want: "value"},
		{name: "unterminatedDouble", raw: "\"value", isErr: true},
		{name: "unterminatedSingle", raw: "'value", isErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDotEnvValue(tc.raw)
			if tc.isErr {
				if err == nil {
					t.Fatalf("parseDotEnvValue(%q) expected error", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDotEnvValue(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseDotEnvValue(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCollectNonEmptyDotEnvValues(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"SERVER":   " app01 ",
		"PASSWORD": "   ",
		"KEY":      "ssh-ed25519 AAAA",
	}

	got := collectNonEmptyDotEnvValues(values, "SERVER", "PASSWORD", "MISSING", "KEY")
	want := []string{"app01", "ssh-ed25519 AAAA"}
	if len(got) != len(want) {
		t.Fatalf("collectNonEmptyDotEnvValues() len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collectNonEmptyDotEnvValues()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeLFConfigHelpers(t *testing.T) {
	t.Parallel()

	input := "a\r\nb\rc\n"
	got := normalizeLF(input)
	if got != "a\nb\nc\n" {
		t.Fatalf("normalizeLF() = %q, want %q", got, "a\nb\nc\n")
	}
}

func TestExpandHomePath(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() error = %v", err)
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty", input: "", wantErr: true},
		{name: "unchanged", input: "/tmp/config.env", want: "/tmp/config.env"},
		{name: "tildeOnly", input: "~", want: home},
		{name: "tildeSlash", input: "~/config.env", want: filepath.Join(home, "config.env")},
		{name: "tildeBackslash", input: "~\\folder\\config.env", want: filepath.Join(home, `folder\config.env`)},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := expandHomePath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expandHomePath(%q) expected error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandHomePath(%q) error = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expandHomePath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
