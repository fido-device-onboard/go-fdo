//go:build windows

package fsim

import "path/filepath"

func sameFilesystem(path1, path2 string) (bool, error) {
	vol1 := filepath.VolumeName(path1)
	vol2 := filepath.VolumeName(path2)
	return vol1 != "" && vol1 == vol2, nil
}
