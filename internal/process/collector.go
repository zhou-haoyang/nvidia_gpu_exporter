package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/utkuozdemir/nvidia_gpu_exporter/internal/exporter"
)

type runCmd func(cmd *exec.Cmd) error

const (
	DefaultPrefix           = "nvidia_smi"
	DefaultNvidiaSmiCommand = "nvidia-smi"
	DefaultQField           = "AUTO"
)

var defaultRunCmd = func(cmd *exec.Cmd) error {
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error running command: %w", err)
	}

	return nil
}

var requiredFields = []exporter.QField{
	"timestamp",
	"gpu_uuid",
	"gpu_name",
	"gpu_bus_id",
	"gpu_serial",
	"pid",
	"name",
	"used_memory",
}

var fallbackQFieldToRFieldMap = map[exporter.QField]exporter.RField{
	"timestamp":   "timestamp",
	"gpu_name":    "gpu_name",
	"gpu_bus_id":  "gpu_bus_id",
	"gpu_serial":  "gpu_serial",
	"gpu_uuid":    "gpu_uuid",
	"pid":         "pid",
	"name":        "name",
	"used_memory": "used_memory [MiB]",
}

var computeAppsAutoAliases = map[exporter.QField]exporter.QField{
	"process_name":    "name",
	"used_gpu_memory": "used_memory",
}

type Collector struct {
	mutex              sync.RWMutex
	prefix             string
	qFields            []exporter.QField
	nvidiaSmiCommand   string
	failedScrapesTotal prometheus.Counter
	exitCode           prometheus.Gauge
	processInfoDesc    *prometheus.Desc
	usedMemoryDesc     *prometheus.Desc
	logger             *slog.Logger
	command            runCmd
	ctx                context.Context //nolint:containedctx
	resolver           Resolver
	config             *Config
}

func NewCollector(
	ctx context.Context,
	prefix string,
	nvidiaSmiCommand string,
	qFieldsRaw string,
	config *Config,
	resolver Resolver,
	logger *slog.Logger,
) (*Collector, error) {
	qFields, err := buildQFields(ctx, qFieldsRaw, nvidiaSmiCommand, defaultRunCmd)
	if err != nil {
		return nil, err
	}

	collector := &Collector{
		ctx:              ctx,
		prefix:           prefix,
		nvidiaSmiCommand: nvidiaSmiCommand,
		qFields:          qFields,
		logger:           logger,
		command:          defaultRunCmd,
		resolver:         resolver,
		config:           config,
		failedScrapesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: prefix,
			Name:      "process_failed_scrapes_total",
			Help:      "Number of failed process scrapes",
		}),
		exitCode: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: prefix,
			Name:      "process_command_exit_code",
			Help:      "Exit code of the last process scrape command",
		}),
		processInfoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(prefix, "", "process_info"),
			"A metric with a constant '1' value labeled by process and GPU metadata.",
			[]string{"gpu_uuid", "gpu_name", "gpu_bus_id", "gpu_serial", "pid", "groupname", "comm", "exe_base", "exe_full", "username"},
			nil,
		),
		usedMemoryDesc: prometheus.NewDesc(
			prometheus.BuildFQName(prefix, "", "process_used_memory_bytes"),
			"GPU memory used by a matched process.",
			[]string{"gpu_uuid", "gpu_name", "gpu_bus_id", "gpu_serial", "pid", "groupname"},
			nil,
		),
	}

	return collector, nil
}

func buildQFields(
	ctx context.Context,
	qFieldsRaw string,
	nvidiaSmiCommand string,
	command runCmd,
) ([]exporter.QField, error) {
	qFieldsSeparated := strings.Split(qFieldsRaw, ",")
	qFields := toQFieldSlice(qFieldsSeparated)
	for _, reqField := range requiredFields {
		qFields = append(qFields, reqField)
	}
	qFields = removeDuplicates(qFields)

	if len(qFieldsSeparated) == 1 && qFieldsSeparated[0] == DefaultQField {
		parsed, err := parseAutoQFieldsWithHelpArg(ctx, nvidiaSmiCommand, "--help-query-compute-apps", command)
		if err != nil {
			return requiredFields, nil
		}
		qFields = normalizeComputeAppsQFields(parsed)
	}

	return qFields, nil
}

func normalizeComputeAppsQFields(qFields []exporter.QField) []exporter.QField {
	normalized := make([]exporter.QField, 0, len(qFields))
	for _, qField := range qFields {
		if alias, ok := computeAppsAutoAliases[qField]; ok {
			normalized = append(normalized, alias)
			continue
		}

		normalized = append(normalized, qField)
	}

	return removeDuplicates(normalized)
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(descCh chan<- *prometheus.Desc) {
	c.sendDesc(descCh, c.failedScrapesTotal.Desc())
	c.sendDesc(descCh, c.exitCode.Desc())
	c.sendDesc(descCh, c.processInfoDesc)
	c.sendDesc(descCh, c.usedMemoryDesc)
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(metricCh chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	exitCode, currentTable, err := scrape(c.ctx, c.qFields, c.nvidiaSmiCommand, c.command)
	c.exitCode.Set(float64(exitCode))
	c.sendMetric(metricCh, c.exitCode)

	if err != nil {
		c.logger.Error("failed to collect process metrics", "err", err)
		c.failedScrapesTotal.Inc()
		c.sendMetric(metricCh, c.failedScrapesTotal)
		return
	}

	for _, currentRow := range currentTable.Rows {
		pidCell, ok := currentRow.QFieldToCells["pid"]
		if !ok {
			continue
		}

		pid, pidErr := strconv.Atoi(strings.TrimSpace(pidCell.RawValue))
		if pidErr != nil {
			c.logger.Debug("failed to parse pid", "err", pidErr, "raw_value", pidCell.RawValue)
			continue
		}

		attrs := c.resolver.Resolve(pid)
		if attrs.Comm == "" && attrs.ExeBase == "" && attrs.ExeFull == "" && len(attrs.Cmdline) == 0 {
			continue
		}
		if nameCell, ok := currentRow.QFieldToCells["name"]; ok {
			if attrs.Comm == "" {
				attrs.Comm = nameCell.RawValue
			}
			if attrs.ExeBase == "" {
				attrs.ExeBase = nameCell.RawValue
			}
			if attrs.ExeFull == "" {
				attrs.ExeFull = nameCell.RawValue
			}
		}
		if attrs.ExeBase == "" && attrs.ExeFull != "" {
			attrs.ExeBase = attrs.ExeFull
		}

		matched, groupName := c.config.Match(attrs)
		if !matched {
			continue
		}

		memoryCell, ok := currentRow.QFieldToCells["used_memory"]
		if !ok {
			continue
		}

		_, multiplier := exporter.BuildFQNameAndMultiplier("", memoryCell.RField, c.logger)
		memoryBytes, memoryErr := exporter.TransformRawValue(memoryCell.RawValue, multiplier)
		if memoryErr != nil {
			c.logger.Debug("failed to transform used memory", "err", memoryErr, "raw_value", memoryCell.RawValue)
			continue
		}

		labels := []string{
			gpuLabel(currentRow, "gpu_uuid"),
			gpuLabel(currentRow, "gpu_name"),
			gpuLabel(currentRow, "gpu_bus_id"),
			gpuLabel(currentRow, "gpu_serial"),
			strconv.Itoa(pid),
			groupName,
		}

		infoMetric, infoErr := prometheus.NewConstMetric(c.processInfoDesc, prometheus.GaugeValue, 1,
			labels[0], labels[1], labels[2], labels[3], labels[4], labels[5], attrs.Comm, attrs.ExeBase, attrs.ExeFull, attrs.Username)
		if infoErr != nil {
			c.logger.Error("failed to create process info metric", "err", infoErr)
			continue
		}
		c.sendMetric(metricCh, infoMetric)

		memoryMetric, memoryMetricErr := prometheus.NewConstMetric(c.usedMemoryDesc, prometheus.GaugeValue, memoryBytes,
			labels[0], labels[1], labels[2], labels[3], labels[4], labels[5])
		if memoryMetricErr != nil {
			c.logger.Error("failed to create process memory metric", "err", memoryMetricErr)
			continue
		}
		c.sendMetric(metricCh, memoryMetric)
	}
}

func gpuLabel(row exporter.Row, qField string) string {
	cell, ok := row.QFieldToCells[exporter.QField(qField)]
	if !ok {
		return ""
	}

	return cell.RawValue
}

func (c *Collector) sendMetric(metricCh chan<- prometheus.Metric, metric prometheus.Metric) {
	select {
	case <-c.ctx.Done():
		c.logger.Info("context done, return")
		return
	case metricCh <- metric:
	}
}

func (c *Collector) sendDesc(descCh chan<- *prometheus.Desc, desc *prometheus.Desc) {
	select {
	case <-c.ctx.Done():
		c.logger.Info("context done, return")
		return
	case descCh <- desc:
	}
}

func scrape(
	ctx context.Context,
	qFields []exporter.QField,
	nvidiaSmiCommand string,
	command runCmd,
) (int, *exporter.Table, error) {
	qFieldsJoined := strings.Join(exporter.QFieldSliceToStringSlice(qFields), ",")

	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
	cmdAndArgs = append(cmdAndArgs, "--query-compute-apps="+qFieldsJoined)
	cmdAndArgs = append(cmdAndArgs, "--format=csv")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := command(cmd)
	if err != nil {
		exitCode := -1

		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}

		return exitCode, nil, fmt.Errorf(
			"command failed: code: %d | command: %s | stdout: %s | stderr: %s: %w",
			exitCode,
			strings.Join(cmdAndArgs, " "),
			stdout.String(),
			stderr.String(),
			err,
		)
	}

	t, err := exporter.ParseCSVIntoTable(strings.TrimSpace(stdout.String()), qFields)
	if err != nil {
		return -1, nil, err
	}

	return 0, &t, nil
}

func parseAutoQFieldsWithHelpArg(
	ctx context.Context,
	nvidiaSmiCommand string,
	helpArg string,
	command runCmd,
) ([]exporter.QField, error) {
	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
	cmdAndArgs = append(cmdAndArgs, helpArg)
	cmd := exec.CommandContext(ctx, cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := command(cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: command: %q | stdout: %q | stderr: %q: %w", strings.Join(cmdAndArgs, " "), stdout.String(), stderr.String(), err)
	}

	fields := exporter.ExtractQFields(stdout.String())
	if fields == nil {
		return nil, fmt.Errorf("could not extract any query fields: command: %q | stdout: %q | stderr: %q", strings.Join(cmdAndArgs, " "), stdout.String(), stderr.String())
	}

	return fields, nil
}

func toQFieldSlice(ss []string) []exporter.QField {
	r := make([]exporter.QField, len(ss))
	for i, s := range ss {
		r[i] = exporter.QField(s)
	}

	return r
}

func removeDuplicates[T comparable](qFields []T) []T {
	valMap := make(map[T]struct{})

	var uniques []T

	for _, field := range qFields {
		_, exists := valMap[field]
		if !exists {
			uniques = append(uniques, field)
			valMap[field] = struct{}{}
		}
	}

	return uniques
}
