package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"vibe-ssh-lift/providers"
)

var resolvePasswordFromSecretRef = func(secretRef string) (string, error) {
	return providers.ResolveSecretReference(secretRef, providers.DefaultProviders())
}

func validateOptions(programOptions *options) error {
	if programOptions.Port < 1 || programOptions.Port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if programOptions.TimeoutSec <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	if strings.TrimSpace(programOptions.Password) != "" && strings.TrimSpace(programOptions.PasswordSecretRef) != "" {
		return errors.New("use either PASSWORD/password or PASSWORD_SECRET_REF/password_secret_ref, not both")
	}
	if strings.TrimSpace(programOptions.Password) == "" && strings.TrimSpace(programOptions.PasswordSecretRef) != "" {
		resolvedPassword, err := resolvePasswordFromSecretRef(programOptions.PasswordSecretRef)
		if err != nil {
			return fmt.Errorf("resolve password secret reference: %w", err)
		}
		programOptions.Password = resolvedPassword
	}
	return nil
}

func fillMissingInputs(inputReader *bufio.Reader, programOptions *options) error {
	var err error

	if strings.TrimSpace(programOptions.User) == "" {
		programOptions.User, err = promptRequired(inputReader, "SSH username: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.Password) == "" {
		programOptions.Password, err = promptPassword(inputReader, "SSH password: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.Server) == "" &&
		strings.TrimSpace(programOptions.Servers) == "" {
		programOptions.Servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.KeyInput) == "" {
		programOptions.KeyInput, err = promptRequired(inputReader, "Public key text or path to public key file: ")
		if err != nil {
			return err
		}
	}

	return nil
}

func promptRequired(reader *bufio.Reader, label string) (string, error) {
	for {
		value, err := promptLine(reader, label)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
		outputPrintln("Value is required.")
	}
}

func promptPassword(reader *bufio.Reader, label string) (string, error) {
	for {
		outputPrint(label)

		var passwordInput string
		if isTerminal(os.Stdin) {
			passwordBytes, err := readPassword(os.Stdin)
			outputPrintln()
			if err != nil {
				return "", err
			}
			passwordInput = strings.TrimSpace(string(passwordBytes))
		} else {
			line, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			passwordInput = strings.TrimSpace(line)
		}

		if passwordInput != "" {
			return passwordInput, nil
		}
		outputPrintln("Value is required.")
	}
}
