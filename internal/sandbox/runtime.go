package sandbox

import (
	"context"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
)

// NodeSandboxImage is the published Node sandbox image used for gVisor scans.
const NodeSandboxImage = "ghcr.io/kushalmeghani1644/goaudit-node-sandbox:latest"

// GVisorSetupURL documents how to install and register runsc with Docker.
const GVisorSetupURL = "https://github.com/KushalMeghani1644/GoAudit-CLI#gvisor-runsc-on-fedora--selinux"

// DefaultNodeImage is the stock Node image used to identify the default Node profile.
const DefaultNodeImage = "node:current-slim"

// DefaultBunImage is the stock Bun image used to identify the default Bun profile.
const DefaultBunImage = "oven/bun:1"

// RuntimeFromDockerInfo returns "runsc" only when Docker has registered that runtime.
func RuntimeFromDockerInfo(runtimes map[string]system.RuntimeWithStatus) string {
	if _, ok := runtimes["runsc"]; ok {
		return "runsc"
	}
	return ""
}

// RequireRunsc verifies that Docker has the only runtime GoAudit supports.
func RequireRunsc(runtimes map[string]system.RuntimeWithStatus) error {
	if RuntimeFromDockerInfo(runtimes) == "runsc" {
		return nil
	}
	return diagnostic.New(
		"gVisor (runsc) is required but is not registered with Docker.",
		diagnostic.Cause("GoAudit will not fall back to runc because that would weaken sandbox isolation."),
		diagnostic.Hint("Install and register runsc, then confirm it appears under docker info Runtimes."),
		diagnostic.Hint("Setup guide: "+GVisorSetupURL),
	)
}

// RunscAvailable reports whether Docker lists runsc in docker info Runtimes.
func RunscAvailable(ctx context.Context) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer cli.Close()
	info, err := cli.Info(ctx)
	if err != nil {
		return false
	}
	return RuntimeFromDockerInfo(info.Runtimes) == "runsc"
}

func detectRuntime(ctx context.Context, cli *client.Client) (string, error) {
	info, err := cli.Info(ctx)
	if err != nil {
		return "", diagnostic.New(
			"Cannot inspect Docker runtimes.",
			diagnostic.Cause("GoAudit could not verify that the required gVisor runtime is registered with Docker."),
			diagnostic.Hint("Verify Docker works with: docker info"),
			diagnostic.Wrap(err),
		)
	}
	if err := RequireRunsc(info.Runtimes); err != nil {
		return "", err
	}
	return "runsc", nil
}
