// Package procfs gives read-only access to a filesystem tree that looks like
// /proc and /sys. The roots are configurable so collectors can be tested
// against fixture directories without root.
package procfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Source is a rooted view of procfs and sysfs.
type Source struct {
	Proc string
	Sys  string
}

// New returns a Source. Empty roots fall back to the real /proc and /sys.
func New(procRoot, sysRoot string) *Source {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysRoot == "" {
		sysRoot = "/sys"
	}
	return &Source{Proc: procRoot, Sys: sysRoot}
}

// ProcPath joins parts under the proc root.
func (s *Source) ProcPath(parts ...string) string {
	return filepath.Join(append([]string{s.Proc}, parts...)...)
}

// SysPath joins parts under the sys root.
func (s *Source) SysPath(parts ...string) string {
	return filepath.Join(append([]string{s.Sys}, parts...)...)
}

// ReadProc reads a file under the proc root.
func (s *Source) ReadProc(parts ...string) ([]byte, error) {
	b, err := os.ReadFile(s.ProcPath(parts...))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", strings.Join(parts, "/"), err)
	}
	return b, nil
}

// ReadSys reads a file under the sys root.
func (s *Source) ReadSys(parts ...string) ([]byte, error) {
	b, err := os.ReadFile(s.SysPath(parts...))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", strings.Join(parts, "/"), err)
	}
	return b, nil
}

// ExistsProc reports whether a proc path is present.
func (s *Source) ExistsProc(parts ...string) bool {
	_, err := os.Stat(s.ProcPath(parts...))
	return err == nil
}

// ExistsSys reports whether a sys path is present.
func (s *Source) ExistsSys(parts ...string) bool {
	_, err := os.Stat(s.SysPath(parts...))
	return err == nil
}
