// Package rules validates vmalert rule files before they reach the center.
// It is a structural check, not a PromQL type checker: the goal is to catch
// typos and missing labels at the edge, not to replace vmalert -dryRun.
package rules

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	Groups []Group `yaml:"groups"`
}

type Group struct {
	Name     string `yaml:"name"`
	Interval string `yaml:"interval"`
	Rules    []Rule `yaml:"rules"`
}

type Rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// Validate returns hard errors and soft warnings.
func Validate(path string) ([]string, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(f.Groups) == 0 {
		return nil, nil, fmt.Errorf("%s: no groups", path)
	}

	var errs, warns []string
	seen := map[string]bool{}
	for gi, g := range f.Groups {
		if g.Name == "" {
			errs = append(errs, fmt.Sprintf("group %d: missing name", gi))
		}
		if len(g.Rules) == 0 {
			warns = append(warns, fmt.Sprintf("group %q: no rules", g.Name))
		}
		for ri, r := range g.Rules {
			where := fmt.Sprintf("group %q rule %d", g.Name, ri)
			if r.Alert == "" {
				errs = append(errs, where+": missing alert name")
			}
			if strings.TrimSpace(r.Expr) == "" {
				errs = append(errs, where+": missing expr")
			}
			if seen[r.Alert] {
				errs = append(errs, where+": duplicate alert name "+r.Alert)
			}
			seen[r.Alert] = true
			if r.Labels["severity"] == "" {
				warns = append(warns, fmt.Sprintf("%s (%s): missing severity label", where, r.Alert))
			}
			if r.Labels["kind"] == "" {
				warns = append(warns, fmt.Sprintf("%s (%s): missing kind label (breaks the metrics button)", where, r.Alert))
			}
			if r.Annotations["summary"] == "" {
				warns = append(warns, fmt.Sprintf("%s (%s): missing summary annotation", where, r.Alert))
			}
		}
	}
	return errs, warns, nil
}
