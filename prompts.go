package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"ssh-key-bootstrap/providers"
)

var resolvePasswordFromSecretRef = func(secretRef string) (string, error) {
	return providers.ResolveSecretReference(secretRef, providers.DefaultProviders())
}

var isTerminalForPasswordPrompt = isTerminal
var readPasswordForPrompt = readPassword

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
			return wrapMissingInputError("SSH username", err)
		}
	}

	if strings.TrimSpace(programOptions.Password) == "" {
		programOptions.Password, err = promptPassword(inputReader, os.Stdin, "SSH password: ")
		if err != nil {
			return wrapMissingInputError("SSH password", err)
		}
	}

	if strings.TrimSpace(programOptions.Server) == "" &&
		strings.TrimSpace(programOptions.Servers) == "" {
		programOptions.Servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return wrapMissingInputError("Servers", err)
		}
	}

	if strings.TrimSpace(programOptions.KeyInput) == "" {
		programOptions.KeyInput, err = promptRequired(inputReader, "Public key text or path to public key file: ")
		if err != nil {
			return wrapMissingInputError("Public key", err)
		}
	}

	return nil
}

func wrapMissingInputError(fieldName string, err error) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%s is required but input ended (EOF)", fieldName)
	}
	return fmt.Errorf("read %s: %w", fieldName, err)
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

func promptPassword(reader *bufio.Reader, terminalInput *os.File, label string) (string, error) {
	if terminalInput == nil {
		terminalInput = os.Stdin
	}
	if reader == nil {
		reader = bufio.NewReader(terminalInput)
	}

	for {
		outputPrint(label)

		var passwordInput string
		if isTerminalForPasswordPrompt(terminalInput) {
			passwordBytes, err := readPasswordForPrompt(terminalInput)
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
			if errors.Is(err, io.EOF) && passwordInput == "" {
				return "", io.EOF
			}
		}

		if passwordInput != "" {
			return passwordInput, nil
		}
		outputPrintln("Value is required.")
	}
}
