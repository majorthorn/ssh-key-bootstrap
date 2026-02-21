package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultBinaryDotEnvFilename = ".env"

type RuntimeIO interface {
	PromptLine(label string) (string, error)
	Println(arguments ...any)
	Printf(format string, arguments ...any)
	IsInteractive() bool
}

func ApplyFiles(programOptions *Options, runtimeIO RuntimeIO) error {
	if programOptions == nil {
		return errors.New("program options are required")
	}
	if runtimeIO == nil {
		return errors.New("runtime IO is required")
	}

	selectedDotEnvPath, err := resolveDotEnvSource(programOptions, runtimeIO)
	if err != nil {
		return err
	}
	if selectedDotEnvPath == "" {
		return nil
	}

	programOptions.EnvFile = selectedDotEnvPath
	loadedFieldNames, err := ApplyDotEnvWithMetadata(programOptions)
	if err != nil {
		return err
	}
	if runtimeIO.IsInteractive() {
		confirmLoadedConfigFields(programOptions, loadedFieldNames, runtimeIO)
	}
	return nil
}

func resolveDotEnvSource(programOptions *Options, runtimeIO RuntimeIO) (string, error) {
	explicitDotEnvPath := strings.TrimSpace(programOptions.EnvFile)
	if explicitDotEnvPath != "" {
		return explicitDotEnvPath, nil
	}
	if !runtimeIO.IsInteractive() {
		return "", nil
	}

	discoveredDotEnvPath, err := discoverConfigFileNearBinary()
	if err != nil {
		return "", err
	}
	if discoveredDotEnvPath == "" {
		return "", nil
	}

	useDotEnv, err := promptUseSingleConfigSource(runtimeIO, ".env", discoveredDotEnvPath)
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
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}

	executableDirectory := filepath.Dir(executablePath)
	dotEnvPath := filepath.Join(executableDirectory, defaultBinaryDotEnvFilename)
	if !fileExists(dotEnvPath) {
		dotEnvPath = ""
	}
	return dotEnvPath, nil
}

func promptUseSingleConfigSource(runtimeIO RuntimeIO, displayName, sourcePath string) (bool, error) {
	for {
		answer, err := runtimeIO.PromptLine(fmt.Sprintf("Found %s next to the binary at %q. Use it? [y/n]: ", displayName, sourcePath))
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		runtimeIO.Println("Please answer with y or n.")
	}
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !fileInfo.IsDir()
}
