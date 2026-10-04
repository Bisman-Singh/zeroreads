//go:build unix

package app

import (
	"os"
	"syscall"
	"testing"
)

type ownedBy struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (o ownedBy) Sys() any { return o.st }

// A link someone else owns is never written through.
func TestOnlyOwnLinksAreFollowed(t *testing.T) {
	fi, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByUs(fi) {
		t.Fatal("a file this user made is not owned by it")
	}
	if ownedByUs(ownedBy{fi, &syscall.Stat_t{Uid: uint32(os.Getuid()) + 1}}) {
		t.Fatal("another user's link would be written through")
	}
}
