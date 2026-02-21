package main

import (
	"bufio"
	"os"

	appconfig "ssh-key-bootstrap/internal/config"
)

// configRuntimeIO adapts CLI I/O primitives (stdin/stdout) to the appconfig
// runtime IO interface used during configuration loading. It allows the
// appconfig package to perform interactive prompts and output via the CLI
// without depending directly on concrete I/O types.
type configRuntimeIO struct {
	inputReader *bufio.Reader
}

func (runtimeIO configRuntimeIO) PromptLine(label string) (string, error) {
	return promptLine(runtimeIO.inputReader, label)
}

func (configRuntimeIO) Println(arguments ...any) {
	outputPrintln(arguments...)
}

func (configRuntimeIO) Printf(format string, arguments ...any) {
	outputPrintf(format, arguments...)
}

func (configRuntimeIO) IsInteractive() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

// applyConfigFiles applies file-backed configuration values to programOptions
// and uses inputReader for any interactive prompts needed during loading.
// It returns any loader, parse, validation, or interactive prompt errors.

func applyConfigFiles(programOptions *options, inputReader *bufio.Reader) error {
	runtimeIO := configRuntimeIO{inputReader: inputReader}
	return appconfig.ApplyFiles(programOptions, runtimeIO)
}

// applyDotEnvConfigFileWithMetadata applies configuration values from a .env file
// and returns metadata describing which options were affected. The returned map
// is keyed by configuration option name; a value of true indicates that the
// corresponding option was populated or overridden from the .env file, while a
// value of false indicates that the option was considered but not changed (for
// example, because it was already set from another source).
func applyDotEnvConfigFileWithMetadata(programOptions *options) (map[string]bool, error) {
	return appconfig.ApplyDotEnvWithMetadata(programOptions)
}
