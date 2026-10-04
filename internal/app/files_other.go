//go:build !unix

package app

import "os"

// ownedByUs is true where file ownership is not a user ID: creating a link there takes rights a
// planted link would need anyway.
func ownedByUs(os.FileInfo) bool { return true }
