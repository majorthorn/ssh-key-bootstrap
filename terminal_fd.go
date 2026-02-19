package main

import (
	"errors"
	"os"

	"golang.org/x/term"
)

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
