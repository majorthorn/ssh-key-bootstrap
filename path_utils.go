package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

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
