//go:build windows

package server

import (
	"os"
	"syscall"
)

// hasMultipleLinks reports whether fi has more than one hard link.
//
// Win32FileAttributeData carries no link count, so the file must be opened and
// queried through GetFileInformationByHandle. NTFS supports hard links, and a
// link inside the workspace pointing at a runtime secret is exactly the bypass
// this check exists to stop.
func hasMultipleLinks(path string, fi os.FileInfo) bool {
	_ = fi // the handle query below is authoritative
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	// Zero desired-access is enough for GetFileInformationByHandle, and avoids
	// asking for rights that a read-only file might refuse.
	h, err := syscall.CreateFile(
		p,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)

	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return false
	}
	return info.NumberOfLinks > 1
}

// openNoFollow creates/truncates path.
//
// Windows has no O_NOFOLLOW. FILE_FLAG_OPEN_REPARSE_POINT makes an existing
// reparse point (symlink/junction) be opened itself rather than followed, so a
// planted link cannot redirect the write; the workspace resolver has already
// rejected dangling links.
func openNoFollow(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		p,
		syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
