package project

import "testing"

func TestBuildInstallCommands(t *testing.T) {
	cases := []struct {
		manager string
		mode    UpgradeMode
		want    string
	}{
		{ManagerNPM, UpgradeRefreshLock, "rm -f package-lock.json\nnpm install"},
		{ManagerNPM, UpgradeNCU, "npx -y npm-check-updates@latest -u\nnpm install"},
		{ManagerPNPM, UpgradeUpdate, "pnpm update"},
		{ManagerBun, UpgradeNCU, "bun update"},
	}

	for _, tc := range cases {
		got, err := BuildInstallCommand(tc.manager, tc.mode)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.manager, tc.mode, err)
		}
		if got != tc.want {
			t.Fatalf("%s %s: got %q want %q", tc.manager, tc.mode, got, tc.want)
		}
	}
}

func TestParseUpgradeMode(t *testing.T) {
	if _, err := ParseUpgradeMode("refresh-lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseUpgradeMode("invalid"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}
