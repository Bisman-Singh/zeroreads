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
//
// A link is written through, so the file it points to is replaced and the link stays, but only a link
// the user running sievelog owns: one that someone else planted in a shared directory would make
// sievelog overwrite a file of their choosing. An existing file never gets wider permissions.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
		if !ownedByUs(li) {
			return fmt.Errorf("%s is a link someone else owns; not writing through it", path)
		}
		if target, err := filepath.EvalSymlinks(path); err == nil {
			path = target
		}
	}
	if fi, err := os.Stat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return os.WriteFile(path, data, perm) // a device or pipe, such as /dev/stdout, cannot be replaced
		}
		perm &= fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails harmlessly after the rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is the one to report
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
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
