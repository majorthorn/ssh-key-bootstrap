package main

import (
	"bufio"
	"os"

	appconfig "vibe-ssh-lift/internal/config"
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

func applyConfigFiles(programOptions *options) error {
	configOptions := toConfigOptions(programOptions)
	runtimeIO := configRuntimeIO{inputReader: bufio.NewReader(os.Stdin)}
	err := appconfig.ApplyFiles(configOptions, runtimeIO)
	applyConfigOptionValues(programOptions, configOptions)
	return err
}

func applyDotEnvConfigFileWithMetadata(programOptions *options) (map[string]bool, error) {
	configOptions := toConfigOptions(programOptions)
	loadedFieldNames, err := appconfig.ApplyDotEnvWithMetadata(configOptions)
	applyConfigOptionValues(programOptions, configOptions)
	return loadedFieldNames, err
}

func toConfigOptions(programOptions *options) *appconfig.Options {
	return &appconfig.Options{
		Server:                programOptions.server,
		Servers:               programOptions.servers,
		User:                  programOptions.user,
		Password:              programOptions.password,
		PasswordSecretRef:     programOptions.passwordSecretRef,
		KeyInput:              programOptions.keyInput,
		EnvFile:               programOptions.envFile,
		Port:                  programOptions.port,
		TimeoutSec:            programOptions.timeoutSec,
		InsecureIgnoreHostKey: programOptions.insecureIgnoreHostKey,
		KnownHosts:            programOptions.knownHosts,
	}
}

func applyConfigOptionValues(programOptions *options, configOptions *appconfig.Options) {
	programOptions.server = configOptions.Server
	programOptions.servers = configOptions.Servers
	programOptions.user = configOptions.User
	programOptions.password = configOptions.Password
	programOptions.passwordSecretRef = configOptions.PasswordSecretRef
	programOptions.keyInput = configOptions.KeyInput
	programOptions.envFile = configOptions.EnvFile
	programOptions.port = configOptions.Port
	programOptions.timeoutSec = configOptions.TimeoutSec
	programOptions.insecureIgnoreHostKey = configOptions.InsecureIgnoreHostKey
	programOptions.knownHosts = configOptions.KnownHosts
}
