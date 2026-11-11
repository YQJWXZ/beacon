package main

import (
	"flag"
	"fmt"

	"github.com/yqjwxz/beacon/internal/rules"
)

// cmdRule validates a vmalert rule file structurally. It complements
// `vmalert -dryRun`, which remains the authority on PromQL.
func cmdRule(args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return fmt.Errorf("usage: beacon rule test -file deploy/vmalert/rules.yml")
	}
	fs := flag.NewFlagSet("rule test", flag.ContinueOnError)
	file := fs.String("file", "deploy/vmalert/rules.yml", "rule file to validate")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	errs, warns, err := rules.Validate(*file)
	if err != nil {
		return err
	}
	if *asJSON {
		if e := emitJSON(map[string]any{"valid": len(errs) == 0, "errors": errs, "warnings": warns}); e != nil {
			return e
		}
	} else {
		for _, w := range warns {
			fmt.Println("warning:", w)
		}
		for _, e := range errs {
			fmt.Println("error:", e)
		}
		if len(errs) == 0 {
			fmt.Println("ok: rules are structurally valid")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d rule error(s)", len(errs))
	}
	return nil
}
