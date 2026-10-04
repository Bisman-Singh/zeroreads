//go:build unix

package app

import (
	"os"
	"syscall"
)

// ownedByUs reports whether the user running sievelog owns the file.
func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
