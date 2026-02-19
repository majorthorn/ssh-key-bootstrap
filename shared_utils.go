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

var standardOutputWriter io.Writer = os.Stdout
var standardErrorWriter io.Writer = os.Stderr

const ansibleTaskPaddingWidth = 69

func promptLine(reader *bufio.Reader, label string) (string, error) {
	outputPrint(label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func outputPrint(arguments ...any) {
	_, _ = fmt.Fprint(standardOutputWriter, arguments...)
}

func outputPrintf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(standardOutputWriter, format, arguments...)
}

func outputPrintln(arguments ...any) {
	_, _ = fmt.Fprintln(standardOutputWriter, arguments...)
}

func errorPrintln(arguments ...any) {
	_, _ = fmt.Fprintln(standardErrorWriter, arguments...)
}

func commandOutputWriter() io.Writer {
	return standardErrorWriter
}

func outputAnsibleTask(taskName string) {
	paddingLength := ansibleTaskPaddingWidth - len(taskName)
	if paddingLength < 5 {
		paddingLength = 5
	}
	outputPrintf("\nTASK [%s] %s\n", taskName, strings.Repeat("*", paddingLength))
}

func outputAnsibleHostStatus(status, hostName, message string) {
	trimmedMessage := strings.TrimSpace(message)
	if trimmedMessage == "" {
		outputPrintf("%s: [%s]\n", status, hostName)
		return
	}
	outputPrintf("%s: [%s] => %s\n", status, hostName, trimmedMessage)
}

func outputAnsiblePlayRecap(hosts []string, hostRecaps map[string]hostRunRecap) {
	outputPrintln()
	outputPrintln("PLAY RECAP *********************************************************************")
	for _, hostName := range hosts {
		recap := hostRecaps[hostName]
		outputPrintf("%-24s : ok=%d changed=%d unreachable=0 failed=%d\n", hostName, recap.ok, recap.changed, recap.failed)
	}
}

func setupRunLogFile(applicationName string) (func(), error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path for run log: %w", err)
	}

	logDirectory := filepath.Dir(executablePath)
	logPath := filepath.Join(logDirectory, applicationName+".log")
	logFileHandle, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- log path is fixed to binary directory
	if err != nil {
		return nil, fmt.Errorf("open run log %q: %w", logPath, err)
	}

	standardOutputWriter = io.MultiWriter(os.Stdout, logFileHandle)
	standardErrorWriter = io.MultiWriter(os.Stderr, logFileHandle)

	cleanupRunLog := func() {
		standardOutputWriter = os.Stdout
		standardErrorWriter = os.Stderr
		_ = logFileHandle.Close()
	}
	return cleanupRunLog, nil
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
