//go:build aix || dragonfly || illumos || js || plan9 || solaris
// +build aix dragonfly illumos js plan9 solaris

package fsim

func sameFilesystem(_, _ string) (bool, error) {
	return false, nil
}
