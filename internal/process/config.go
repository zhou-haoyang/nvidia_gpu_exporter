package process

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

type ProcAttributes struct {
	Comm     string
	ExeBase  string
	ExeFull  string
	Username string
	PID      int
	Cmdline  []string
}

type Config struct {
	Matchers []matcher
}

type matcher struct {
	comms    map[string]struct{}
	exes     map[string]string
	regexes  []*regexp.Regexp
	template *template.Template
}

type yamlMatcher struct {
	Name    string   `yaml:"name"`
	Comm    []string `yaml:"comm"`
	Exe     []string `yaml:"exe"`
	Cmdline []string `yaml:"cmdline"`
}

type yamlConfig struct {
	ProcessNames []yamlMatcher `yaml:"process_names"`
}

type templateParams struct {
	Comm     string
	ExeBase  string
	ExeFull  string
	Username string
	PID      int
	Matches  map[string]string
}

func LoadConfig(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read process config %q: %w", path, err)
	}

	return ParseConfig(content)
}

func ParseConfig(content []byte) (*Config, error) {
	var raw yamlConfig
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return nil, err
	}

	compiled := make([]matcher, 0, len(raw.ProcessNames))
	for _, rule := range raw.ProcessNames {
		compiledMatcher, err := compileMatcher(rule)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledMatcher)
	}

	if len(compiled) == 0 {
		return nil, fmt.Errorf("no process matchers provided")
	}

	return &Config{Matchers: compiled}, nil
}

func (c *Config) Match(attrs ProcAttributes) (bool, string) {
	if c == nil {
		return false, ""
	}

	for _, matcher := range c.Matchers {
		if ok, name := matcher.match(attrs); ok {
			return true, name
		}
	}

	return false, ""
}

func compileMatcher(rule yamlMatcher) (matcher, error) {
	compiled := matcher{}

	if len(rule.Comm) > 0 {
		compiled.comms = make(map[string]struct{}, len(rule.Comm))
		for _, comm := range rule.Comm {
			compiled.comms[comm] = struct{}{}
		}
	}

	if len(rule.Exe) > 0 {
		compiled.exes = make(map[string]string, len(rule.Exe))
		for _, exe := range rule.Exe {
			if strings.Contains(exe, "/") {
				compiled.exes[filepath.Base(exe)] = exe
			} else {
				compiled.exes[exe] = ""
			}
		}
	}

	if len(rule.Cmdline) > 0 {
		compiled.regexes = make([]*regexp.Regexp, 0, len(rule.Cmdline))
		for _, expr := range rule.Cmdline {
			r, err := regexp.Compile(expr)
			if err != nil {
				return matcher{}, fmt.Errorf("bad cmdline regex %q: %w", expr, err)
			}
			compiled.regexes = append(compiled.regexes, r)
		}
	}

	if len(compiled.comms) == 0 && len(compiled.exes) == 0 && len(compiled.regexes) == 0 {
		return matcher{}, fmt.Errorf("no matchers provided")
	}

	tmplText := rule.Name
	if tmplText == "" {
		tmplText = "{{.ExeBase}}"
	}

	tmpl, err := template.New("process-name").Parse(tmplText)
	if err != nil {
		return matcher{}, fmt.Errorf("bad name template %q: %w", tmplText, err)
	}

	compiled.template = tmpl

	return compiled, nil
}

func (m matcher) match(attrs ProcAttributes) (bool, string) {
	if m.comms != nil {
		if _, ok := m.comms[attrs.Comm]; !ok {
			return false, ""
		}
	}

	if m.exes != nil {
		if len(attrs.ExeFull) == 0 && len(attrs.ExeBase) == 0 {
			return false, ""
		}

		base := attrs.ExeBase
		if base == "" {
			base = filepath.Base(attrs.ExeFull)
		}
		full := attrs.ExeFull
		if full == "" {
			full = base
		}

		fqPath, ok := m.exes[base]
		if !ok {
			return false, ""
		}
		if fqPath != "" && fqPath != full {
			return false, ""
		}
	}

	matches := make(map[string]string)
	if len(m.regexes) > 0 {
		joined := strings.Join(attrs.Cmdline, " ")
		for _, re := range m.regexes {
			found := re.FindStringSubmatch(joined)
			if found == nil {
				return false, ""
			}

			for i, name := range re.SubexpNames() {
				if name == "" || i >= len(found) {
					continue
				}
				matches[name] = found[i]
			}
		}
	}

	var buf bytes.Buffer
	params := templateParams{
		Comm:     attrs.Comm,
		ExeBase:  attrs.ExeBase,
		ExeFull:  attrs.ExeFull,
		Username: attrs.Username,
		PID:      attrs.PID,
		Matches:  matches,
	}
	if err := m.template.Execute(&buf, params); err != nil {
		return false, ""
	}

	return true, buf.String()
}
