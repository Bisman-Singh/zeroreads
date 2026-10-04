package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rules.json")
	if err := WriteFile(p, []byte("one"), SharedFile); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("two"), PrivateFile); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != PrivateFile {
		t.Fatalf("mode %v", fi.Mode())
	}
	// A link keeps pointing at the rewritten file.
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("three"), SharedFile); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link was replaced by a file")
	}
	if b, _ := os.ReadFile(p); string(b) != "three" {
		t.Fatalf("target content %q", b)
	}
	// A failed write leaves the previous file whole, and no temporary file behind.
	if err := WriteJSON(p, map[string]any{"x": make(chan int)}, SharedFile); err == nil {
		t.Fatal("unmarshalable value written")
	}
	if b, _ := os.ReadFile(p); string(b) != "three" {
		t.Fatalf("content after a failed write %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("leftover files: %v", entries)
	}
	if err := WriteFile(os.DevNull, []byte("x"), SharedFile); err != nil {
		t.Fatalf("device: %v", err)
	}
}

// Writing never widens an existing file's permissions, through a link or not.
func TestWriteFileKeepsStricterModes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.md")
	if err := os.WriteFile(p, []byte("mine"), PrivateFile); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("report"), SharedFile); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != PrivateFile {
		t.Fatalf("a private file became %v", fi.Mode().Perm())
	}
}
