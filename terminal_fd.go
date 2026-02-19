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
	maxInt := int(^uint(0) >> 1)
	fd := file.Fd()
	if fd > uintptr(maxInt) {
		return 0, false
	}
	return int(fd), true // #nosec G115 -- os.File descriptors fit into int on supported platforms
}

func isTerminal(file *os.File) bool {
	fd, ok := terminalFD(file)
	return ok && term.IsTerminal(fd)
}

func readPassword(file *os.File) ([]byte, error) {
	fd, ok := terminalFD(file)
	if !ok {
		return nil, errors.New("invalid terminal file descriptor")
	}
	return term.ReadPassword(fd)
}
