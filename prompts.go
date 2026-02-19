package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func validateOptions(programOptions *options) error {
	if programOptions.port < 1 || programOptions.port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if programOptions.timeoutSec <= 0 {
		return errors.New("timeout must be greater than zero")
	}
	return nil
}

func fillMissingInputs(inputReader *bufio.Reader, programOptions *options) error {
	var err error

	if strings.TrimSpace(programOptions.user) == "" {
		programOptions.user, err = promptRequired(inputReader, "SSH username: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.password) == "" {
		programOptions.password, err = promptPassword(inputReader, "SSH password: ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.server) == "" &&
		strings.TrimSpace(programOptions.servers) == "" &&
		strings.TrimSpace(programOptions.serversFile) == "" {
		programOptions.servers, err = promptRequired(inputReader, "Servers (comma-separated, host or host:port): ")
		if err != nil {
			return err
		}
	}

	if strings.TrimSpace(programOptions.keyInput) == "" {
		programOptions.keyInput, err = promptRequired(inputReader, "Public key text or path to public key file: ")
		if err != nil {
			return err
		}
	}

	return nil
}

func promptLine(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
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
		fmt.Println("Value is required.")
	}
}

func promptPassword(reader *bufio.Reader, label string) (string, error) {
	for {
		fmt.Print(label)

		var passwordInput string
		if term.IsTerminal(int(os.Stdin.Fd())) {
			bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return "", err
			}
			passwordInput = strings.TrimSpace(string(bytes))
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
		fmt.Println("Value is required.")
	}
}

func promptPasswordAllowEmpty(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
