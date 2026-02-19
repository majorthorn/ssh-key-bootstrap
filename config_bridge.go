package main

import (
	"bufio"
	"os"

	appconfig "ssh-key-bootstrap/internal/config"
)

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

func applyConfigFiles(programOptions *options, inputReader *bufio.Reader) error {
	runtimeIO := configRuntimeIO{inputReader: inputReader}
	return appconfig.ApplyFiles(programOptions, runtimeIO)
}

func applyDotEnvConfigFileWithMetadata(programOptions *options) (map[string]bool, error) {
	return appconfig.ApplyDotEnvWithMetadata(programOptions)
}
