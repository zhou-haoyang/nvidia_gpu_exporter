package process

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcFSResolverResolve(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("procfs resolver is Linux-only")
	}

	root := t.TempDir()
	procDir := filepath.Join(root, "1234")
	require.NoError(t, os.MkdirAll(procDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "comm"), []byte("python3\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("python3\x00--app=train\x00"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "status"), []byte("Name:\tpython3\nUid:\t1000\t1000\t1000\t1000\n"), 0o644))
	require.NoError(t, os.Symlink("/usr/bin/python3", filepath.Join(procDir, "exe")))

	attrs := NewProcFSResolver(root).Resolve(1234)

	assert.Equal(t, "python3", attrs.Comm)
	assert.Equal(t, "python3", attrs.ExeBase)
	assert.Equal(t, "/usr/bin/python3", attrs.ExeFull)
	assert.Equal(t, []string{"python3", "--app=train"}, attrs.Cmdline)
	assert.NotEmpty(t, attrs.Username)
}
