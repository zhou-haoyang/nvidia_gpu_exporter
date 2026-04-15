package process

import (
	"context"
	_ "embed"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/utkuozdemir/nvidia_gpu_exporter/internal/exporter"
)

//go:embed testdata/compute_apps.csv
var computeAppsCSV string

type fakeResolver struct {
	attrs ProcAttributes
}

func (f fakeResolver) Resolve(pid int) ProcAttributes {
	f.attrs.PID = pid
	return f.attrs
}

func TestCollectorCollect(t *testing.T) {
	t.Parallel()

	logger := slogt.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	cfg, err := ParseConfig([]byte(`
process_names:
  - name: "{{.Comm}}"
    comm:
      - python3
`))
	require.NoError(t, err)

	collector, err := NewCollector(
		ctx,
		DefaultPrefix,
		"nvidia-smi",
		"timestamp,gpu_name,gpu_bus_id,gpu_serial,gpu_uuid,pid,name,used_memory",
		cfg,
		fakeResolver{attrs: ProcAttributes{Comm: "python3", ExeBase: "python3", ExeFull: "/usr/bin/python3", Username: "alice"}},
		logger,
	)
	require.NoError(t, err)

	collector.command = func(cmd *exec.Cmd) error {
		_, _ = cmd.Stdout.Write([]byte(computeAppsCSV))
		return nil
	}

	metricCh := make(chan prometheus.Metric)
	doneCh := make(chan struct{})
	go func() {
		collector.Collect(metricCh)
		close(doneCh)
	}()

	var descs []string
	for {
		select {
		case metric := <-metricCh:
			descs = append(descs, metric.Desc().String())
		case <-doneCh:
			assert.NotEmpty(t, descs)
			joined := strings.Join(descs, "\n")
			assert.Contains(t, joined, "process_info")
			assert.Contains(t, joined, "process_used_memory_bytes")
			assert.Contains(t, joined, "process_command_exit_code")
			return
		}
	}
}

func TestParseAutoQFieldsWithHelpArg(t *testing.T) {
	t.Parallel()

	var capturedCmd *exec.Cmd
	fields, err := parseAutoQFieldsWithHelpArg(t.Context(), "nvidia-smi", "--help-query-compute-apps", func(cmd *exec.Cmd) error {
		capturedCmd = cmd
		_, _ = cmd.Stdout.Write([]byte("\n\n\"pid\"\n\n\"gpu_uuid\"\n\n\"used_memory\"\n"))
		return nil
	})
	require.NoError(t, err)
	if assert.Len(t, capturedCmd.Args, 2) {
		assert.Equal(t, "--help-query-compute-apps", capturedCmd.Args[1])
	}
	require.Len(t, fields, 3)
	assert.Equal(t, []string{"pid", "gpu_uuid", "used_memory"}, []string{string(fields[0]), string(fields[1]), string(fields[2])})
}

func TestNormalizeComputeAppsQFields(t *testing.T) {
	t.Parallel()

	input := []exporter.QField{"timestamp", "gpu_name", "gpu_bus_id", "gpu_serial", "gpu_uuid", "pid", "process_name", "name", "used_gpu_memory", "used_memory"}
	output := normalizeComputeAppsQFields(input)

	assert.Equal(t, []exporter.QField{"timestamp", "gpu_name", "gpu_bus_id", "gpu_serial", "gpu_uuid", "pid", "name", "used_memory"}, output)
}
