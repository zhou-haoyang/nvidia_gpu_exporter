package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigAndMatch(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig([]byte(`
process_names:
  - name: "{{.Comm}}:{{.ExeBase}}:{{.Username}}:{{.Matches.App}}"
    comm:
      - python3
    exe:
      - /usr/bin/python3
    cmdline:
      - --app=(?P<App>[^\s]+)
`))
	require.NoError(t, err)

	matched, name := cfg.Match(ProcAttributes{
		Comm:     "python3",
		ExeBase:  "python3",
		ExeFull:  "/usr/bin/python3",
		Username: "alice",
		Cmdline:  []string{"python3", "--app=train"},
	})

	assert.True(t, matched)
	assert.Equal(t, "python3:python3:alice:train", name)
}

func TestParseConfigFirstMatchWins(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfig([]byte(`
process_names:
  - name: first
    comm:
      - python3
  - name: second
    comm:
      - python3
`))
	require.NoError(t, err)

	matched, name := cfg.Match(ProcAttributes{Comm: "python3"})

	assert.True(t, matched)
	assert.Equal(t, "first", name)
}

func TestParseConfigValidationErrors(t *testing.T) {
	t.Parallel()

	_, err := ParseConfig([]byte(`
process_names:
  - name: "{{.Missing"
    comm:
      - python3
`))
	require.Error(t, err)
}
