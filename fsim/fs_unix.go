//go:build darwin || freebsd || linux || netbsd || openbsd || android || darwin || freebsd || ios || linux || netbsd || openbsd || wasip1
// +build darwin freebsd linux netbsd openbsd android darwin freebsd ios linux netbsd openbsd wasip1

package fsim

import "syscall"

// sameFilesystem checks if two paths are on the same filesystem by comparing device IDs
func sameFilesystem(path1, path2 string) (bool, error) {
	var stat1, stat2 syscall.Stat_t

	if err := syscall.Stat(path1, &stat1); err != nil {
		return false, err
	}
	if err := syscall.Stat(path2, &stat2); err != nil {
		return false, err
	}

	return stat1.Dev == stat2.Dev, nil
}
