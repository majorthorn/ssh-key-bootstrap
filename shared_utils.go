package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func promptLine(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func expandHomePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

func normalizeLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func terminalFD(file *os.File) (int, bool) {
	if file == nil {
		return 0, false
	}
	maxIntValue := int(^uint(0) >> 1)
	fileDescriptor := file.Fd()
	if fileDescriptor > uintptr(maxIntValue) {
		return 0, false
	}
	return int(fileDescriptor), true // #nosec G115 -- os.File descriptors fit into int on supported platforms
}

func isTerminal(file *os.File) bool {
	terminalFileDescriptor, ok := terminalFD(file)
	return ok && term.IsTerminal(terminalFileDescriptor)
}

func readPassword(file *os.File) ([]byte, error) {
	terminalFileDescriptor, ok := terminalFD(file)
	if !ok {
		return nil, errors.New("invalid terminal file descriptor")
	}
	return term.ReadPassword(terminalFileDescriptor)
}
