package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// File permissions for what sievelog writes. Runtime configurations embed the user's whole pipeline
// configuration, which can hold credentials, so only the owner reads them. Reports, rules and
// rewritten queries hold no credentials (URLs with credentials are refused) and are meant to be
// shared.
const (
	PrivateFile os.FileMode = 0o600
	SharedFile  os.FileMode = 0o644
	outputDir   os.FileMode = 0o755
)

// WriteFile writes data through a temporary file in the same directory and a rename, so a reader
// never sees half a file and a failed write leaves the previous file whole. That matters most for
// rules.json, which rewrite -apply updates in place.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target // replace the file a link points to, not the link
	}
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return os.WriteFile(path, data, perm) // a device or pipe, such as /dev/stdout, cannot be replaced
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteJSON writes v as indented JSON.
func WriteJSON(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return WriteFile(path, append(b, '\n'), perm)
}
