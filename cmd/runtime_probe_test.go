package cmd

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/project"
	"github.com/spf13/cobra"
)

func TestRuntimeProbeFlags(t *testing.T) {
	for _, original := range []*cobra.Command{scanCmd, scanProjectCmd} {
		t.Run(original.Name(), func(t *testing.T) {
			runtime := original.Flags().Lookup("runtime-probe")
			if runtime == nil || runtime.DefValue != "false" || runtime.Value.Type() != "bool" {
				t.Fatalf("expected runtime-probe bool default false, got %#v", runtime)
			}
			skip := original.Flags().Lookup("skip-probe")
			if skip == nil || skip.DefValue != "false" || skip.Deprecated == "" {
				t.Fatalf("expected deprecated skip-probe default false, got %#v", skip)
			}
			timeout := original.Flags().Lookup("probe-timeout")
			if timeout == nil || timeout.DefValue != "30s" {
				t.Fatalf("expected retained probe-timeout, got %#v", timeout)
			}
			if original.Flags().Lookup("probe-all") != nil {
				t.Fatal("probe-all must not be registered")
			}
			help := original.UsageString()
			for _, want := range []string{"--runtime-probe", "off by default", "--probe-timeout"} {
				if !strings.Contains(help, want) {
					t.Fatalf("help missing %q:\n%s", want, help)
				}
			}
			if strings.Contains(help, "--probe-all") || strings.Contains(help, "--skip-probe") {
				t.Fatalf("removed/deprecated flags should not appear in help:\n%s", help)
			}
		})
	}
}

func TestRuntimeProbeCLICompatibility(t *testing.T) {
	for _, original := range []*cobra.Command{scanCmd, scanProjectCmd} {
		t.Run(original.Name(), func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				flags   []string
				enabled bool
				wantErr string
			}{
				{name: "default"},
				{name: "opt in", flags: []string{"--runtime-probe"}, enabled: true},
				{name: "explicit off", flags: []string{"--runtime-probe=false"}},
				{name: "legacy skip", flags: []string{"--skip-probe"}},
				{name: "legacy false", flags: []string{"--skip-probe=false"}},
				{name: "opt in with legacy false", flags: []string{"--runtime-probe", "--skip-probe=false"}, enabled: true},
				{name: "explicit off with legacy skip", flags: []string{"--runtime-probe=false", "--skip-probe"}},
				{name: "contradiction", flags: []string{"--runtime-probe", "--skip-probe"}, wantErr: "cannot both be true"},
				{name: "removed probe all", flags: []string{"--probe-all"}, wantErr: "unknown flag: --probe-all"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					oldRuntime, oldSkip := runtimeProbe, skipProbe
					runtimeProbe, skipProbe = false, false
					t.Cleanup(func() { runtimeProbe, skipProbe = oldRuntime, oldSkip })
					// Exercise the real flags and validation without entering the
					// sandbox pipeline (which requires Docker and network access).
					cmd := &cobra.Command{
						Use: original.Use, Args: original.Args, PreRunE: original.PreRunE,
						RunE: func(*cobra.Command, []string) error { return nil },
					}
					cmd.Flags().AddFlagSet(original.Flags())
					for _, name := range []string{"runtime-probe", "skip-probe"} {
						flag := cmd.Flags().Lookup(name)
						oldChanged := flag.Changed
						flag.Changed = false
						t.Cleanup(func() { flag.Changed = oldChanged })
					}
					arg := "npm install lodash"
					if original == scanProjectCmd {
						arg = t.TempDir()
					}
					cmd.SetArgs(append([]string{arg}, tc.flags...))
					cmd.SetOut(io.Discard)
					cmd.SetErr(io.Discard)
					err := cmd.Execute()
					if tc.wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
							t.Fatalf("expected %q, got %v", tc.wantErr, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if runtimeProbe != tc.enabled {
						t.Fatalf("runtimeProbe = %v, want %v", runtimeProbe, tc.enabled)
					}
				})
			}
		})
	}
}

func TestRequestedProbePackages(t *testing.T) {
	for _, command := range []string{
		"npm install lodash@4.17.21 @scope/pkg@1.0.0",
		"pnpm add lodash@4.17.21 @scope/pkg@1.0.0",
		"bun add lodash@4.17.21 @scope/pkg@1.0.0",
	} {
		t.Run(command, func(t *testing.T) {
			if got := requestedProbePackages(command, false); len(got) != 0 {
				t.Fatalf("default-off selected packages: %v", got)
			}
			want := []string{"lodash", "@scope/pkg"}
			if got := requestedProbePackages(command, true); !reflect.DeepEqual(got, want) {
				t.Fatalf("selected %v, want %v", got, want)
			}
		})
	}
	for _, command := range []string{"npm install", "pnpm install", "bun install"} {
		if got := requestedProbePackages(command, true); len(got) != 0 {
			t.Fatalf("%q must not automatically select unnamed dependencies: %v", command, got)
		}
	}
}

func TestProjectProbePackagesOnlyDirectDependencies(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"package.json":      `{"name":"app","dependencies":{"lodash":"4.17.21"},"devDependencies":{"yaml":"2.0.0"},"optionalDependencies":{"minimist":"1.2.8"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"},"node_modules/transitive-only":{"version":"1.0.0"}}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proj, err := project.Open(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	for _, transitive := range []bool{false, true} {
		staticDeps, err := proj.ListDepsForStatic(transitive)
		if err != nil {
			t.Fatal(err)
		}
		if transitive && !strings.Contains(strings.Join(staticDeps, ","), "transitive-only") {
			t.Fatalf("fixture did not select transitive static dependency: %v", staticDeps)
		}
		if got := projectProbePackages(proj, false); len(got) != 0 {
			t.Fatalf("default-off selected packages: %v", got)
		}
		want := []string{"lodash", "minimist", "yaml"}
		if got := projectProbePackages(proj, true); !reflect.DeepEqual(got, want) {
			t.Fatalf("include-transitive=%v selected %v, want %v", transitive, got, want)
		}
	}
}
