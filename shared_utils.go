package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

var (
	standardWritersMu    sync.RWMutex
	standardOutputWriter io.Writer = os.Stdout
	standardErrorWriter  io.Writer = os.Stderr
)

func getStandardOutputWriter() io.Writer {
	standardWritersMu.RLock()
	defer standardWritersMu.RUnlock()
	return standardOutputWriter
}

func getStandardErrorWriter() io.Writer {
	standardWritersMu.RLock()
	defer standardWritersMu.RUnlock()
	return standardErrorWriter
}

func setStandardWriters(outputWriter, errorWriter io.Writer) {
	standardWritersMu.Lock()
	defer standardWritersMu.Unlock()
	standardOutputWriter = outputWriter
	standardErrorWriter = errorWriter
}

type timestampedLineWriter struct {
	mu      sync.Mutex
	writer  io.Writer
	pending []byte
	nowFunc func() time.Time
}

func newTimestampedLineWriter(writer io.Writer) *timestampedLineWriter {
	return &timestampedLineWriter{
		writer:  writer,
		nowFunc: time.Now,
	}
}

func (timestampWriter *timestampedLineWriter) Write(data []byte) (int, error) {
	timestampWriter.mu.Lock()
	defer timestampWriter.mu.Unlock()

	timestampWriter.pending = append(timestampWriter.pending, data...)
	for {
		lineEndIndex := bytes.IndexByte(timestampWriter.pending, '\n')
		if lineEndIndex < 0 {
			break
		}
		lineBytes := timestampWriter.pending[:lineEndIndex]
		if err := timestampWriter.writeLineLocked(lineBytes, true); err != nil {
			return len(data), err
		}
		timestampWriter.pending = timestampWriter.pending[lineEndIndex+1:]
	}
	return len(data), nil
}

func (timestampWriter *timestampedLineWriter) Close() error {
	timestampWriter.mu.Lock()
	defer timestampWriter.mu.Unlock()

	if len(timestampWriter.pending) == 0 {
		return nil
	}
	if err := timestampWriter.writeLineLocked(timestampWriter.pending, false); err != nil {
		return err
	}
	timestampWriter.pending = nil
	return nil
}

func (timestampWriter *timestampedLineWriter) writeLineLocked(line []byte, appendNewline bool) error {
	timestampPrefix := timestampWriter.nowFunc().UTC().Format(time.RFC3339)
	if _, err := fmt.Fprintf(timestampWriter.writer, "[%s] %s", timestampPrefix, string(line)); err != nil {
		return err
	}
	if appendNewline {
		if _, err := timestampWriter.writer.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

func promptLine(reader *bufio.Reader, label string) (string, error) {
	if reader == nil {
		return "", errors.New("input reader is nil")
	}

	outputPrint(label)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	trimmedLine := strings.TrimSpace(line)
	if errors.Is(err, io.EOF) && trimmedLine == "" {
		return "", io.EOF
	}
	return trimmedLine, nil
}

func outputPrint(arguments ...any) {
	_, _ = fmt.Fprint(getStandardOutputWriter(), arguments...)
}

func outputPrintf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(getStandardOutputWriter(), format, arguments...)
}

func outputPrintln(arguments ...any) {
	_, _ = fmt.Fprintln(getStandardOutputWriter(), arguments...)
}

func errorPrintln(arguments ...any) {
	_, _ = fmt.Fprintln(getStandardErrorWriter(), arguments...)
}

func commandOutputWriter() io.Writer {
	return getStandardErrorWriter()
}

func setupRunLogFile(applicationName string) (func(), error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}

	logDirectory := filepath.Dir(executablePath)
	logPath := filepath.Join(logDirectory, applicationName+".log")
	logFileHandle, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- log path is fixed to binary directory
	if err != nil {
		return nil, fmt.Errorf("open run log %q: %w", logPath, err)
	}
	timestampedLogWriter := newTimestampedLineWriter(logFileHandle)

	setStandardWriters(
		io.MultiWriter(os.Stdout, timestampedLogWriter),
		io.MultiWriter(os.Stderr, timestampedLogWriter),
	)

	cleanupRunLog := func() {
		setStandardWriters(os.Stdout, os.Stderr)
		_ = timestampedLogWriter.Close()
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
