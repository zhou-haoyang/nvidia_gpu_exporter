package process

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type Resolver interface {
	Resolve(pid int) ProcAttributes
}

type ProcFSResolver struct {
	Root string
}

func NewProcFSResolver(root string) *ProcFSResolver {
	if root == "" {
		root = "/proc"
	}

	return &ProcFSResolver{Root: root}
}

func (r *ProcFSResolver) Resolve(pid int) ProcAttributes {
	attrs := ProcAttributes{PID: pid}
	procRoot := filepath.Join(r.Root, strconv.Itoa(pid))

	if comm, err := os.ReadFile(filepath.Join(procRoot, "comm")); err == nil {
		attrs.Comm = strings.TrimSpace(string(comm))
	}

	if cmdline, err := os.ReadFile(filepath.Join(procRoot, "cmdline")); err == nil {
		attrs.Cmdline = splitNullSeparated(cmdline)
	}

	if exeFull, err := os.Readlink(filepath.Join(procRoot, "exe")); err == nil {
		attrs.ExeFull = exeFull
		attrs.ExeBase = filepath.Base(exeFull)
	}

	if attrs.ExeFull == "" && len(attrs.Cmdline) > 0 {
		attrs.ExeFull = attrs.Cmdline[0]
		attrs.ExeBase = filepath.Base(attrs.ExeFull)
	}

	if attrs.Comm == "" {
		attrs.Comm = attrs.ExeBase
	}

	if uid, err := readProcessUID(procRoot); err == nil {
		if uname, lookupErr := user.LookupId(uid); lookupErr == nil {
			attrs.Username = uname.Username
		}
	}

	return attrs
}

func splitNullSeparated(content []byte) []string {
	parts := strings.Split(string(content), "\x00")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		result = append(result, part)
	}

	return result
}

func readProcessUID(procRoot string) (string, error) {
	status, err := os.ReadFile(filepath.Join(procRoot, "status"))
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", fmt.Errorf("malformed status uid line")
		}

		return fields[1], nil
	}

	return "", fmt.Errorf("uid not found")
}
