//go:build unix

package server

import (
	"errors"
	"os"
	"syscall"
)

// hasMultipleLinks reports whether path has more than one hard link. A hard link
// makes a runtime secret reachable under an innocent name, since the workspace
// denylist only inspects path segments.
func hasMultipleLinks(path string, fi os.FileInfo) bool {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Nlink > 1
	}
	return false
}

// openNoFollow creates/truncates path without following a symlink at the final
// component. os.Create would follow one, writing to whatever the link targets.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil && errors.Is(err, syscall.ELOOP) {
		return nil, errNotRegularFile
	}
	return f, err
}
