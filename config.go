package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func applyConfigFiles(programOptions *options) error {
	inputReader := bufio.NewReader(os.Stdin)

	selectedDotEnvPath, err := resolveDotEnvSource(programOptions, inputReader)
	if err != nil {
		return err
	}
	if selectedDotEnvPath == "" {
		return nil
	}

	programOptions.envFile = selectedDotEnvPath
	loadedFieldNames, err := applyDotEnvConfigFileWithMetadata(programOptions)
	if err != nil {
		return err
	}
	confirmLoadedConfigFields(programOptions, loadedFieldNames)
	return nil
}

func resolveDotEnvSource(programOptions *options, inputReader *bufio.Reader) (string, error) {
	explicitDotEnvPath := strings.TrimSpace(programOptions.envFile)
	if explicitDotEnvPath != "" {
		return explicitDotEnvPath, nil
	}
	if !isInteractiveSession() {
		return "", nil
	}

	discoveredDotEnvPath, err := discoverConfigFileNearBinary()
	if err != nil {
		return "", err
	}
	if discoveredDotEnvPath == "" {
		return "", nil
	}

	useDotEnv, err := promptUseSingleConfigSource(inputReader, ".env", discoveredDotEnvPath)
	if err != nil {
		return "", err
	}
	if !useDotEnv {
		return "", nil
	}
	return discoveredDotEnvPath, nil
}

func discoverConfigFileNearBinary() (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}

	executableDirectory := filepath.Dir(executablePath)
	dotEnvPath := filepath.Join(executableDirectory, defaultBinaryDotEnvFilename)
	if !fileExists(dotEnvPath) {
		dotEnvPath = ""
	}
	return dotEnvPath, nil
}

func promptUseSingleConfigSource(inputReader *bufio.Reader, displayName, sourcePath string) (bool, error) {
	for {
		answer, err := promptLine(inputReader, fmt.Sprintf("Found %s next to the binary at %q. Use it? [y/n]: ", displayName, sourcePath))
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Println("Please answer with y or n.")
	}
}

func isInteractiveSession() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	return err == nil && !fileInfo.IsDir()
}
