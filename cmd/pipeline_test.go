package cmd

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
)

func TestResolveRegistryIPsRespectsNetworkPolicy(t *testing.T) {
	// Resolver replacement and CLI globals require serial tests.
	oldResolver, oldNetworkMode, oldOfflineMode := net.DefaultResolver, networkMode, offlineMode
	t.Cleanup(func() {
		net.DefaultResolver = oldResolver
		networkMode = oldNetworkMode
		offlineMode = oldOfflineMode
	})

	var lookups atomic.Int32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, fmt.Errorf("DNS blocked by test")
		},
	}

	for _, tt := range []struct {
		name         string
		profile      string
		mode         string
		offline      bool
		allowNetwork bool
		wantLookup   bool
	}{
		{name: "npm network off", profile: "npm", mode: "off", allowNetwork: true},
		{name: "pnpm network off", profile: "pnpm", mode: "off"},
		{name: "bun network off", profile: "bun", mode: "off"},
		{name: "unknown auto", profile: "other", mode: "auto"},
		{name: "offline overrides auto", profile: "npm", mode: "auto", offline: true},
		{name: "offline overrides on", profile: "pnpm", mode: "on", offline: true},
		{name: "fallback disabled", profile: "npm"},
		{name: "npm online", profile: "npm", mode: "auto", wantLookup: true},
		{name: "pnpm online", profile: "pnpm", mode: "auto", wantLookup: true},
		{name: "bun online", profile: "bun", mode: "auto", wantLookup: true},
		{name: "explicit on", profile: "other", mode: "on", wantLookup: true},
		{name: "fallback enabled", profile: "npm", allowNetwork: true, wantLookup: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			networkMode, offlineMode = tt.mode, tt.offline
			lookups.Store(0)
			got := resolveRegistryIPs(tt.profile, networkEnabledForProfile(tt.profile, tt.allowNetwork))
			if len(got) != 0 {
				t.Fatalf("expected no registry mappings with DNS blocked, got %v", got)
			}
			if attempted := lookups.Load() > 0; attempted != tt.wantLookup {
				t.Fatalf("DNS lookup attempted = %v, want %v", attempted, tt.wantLookup)
			}
		})
	}
}
