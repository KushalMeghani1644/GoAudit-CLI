package project

import (
	"fmt"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
)

func BuildInstallCommand(manager string, mode UpgradeMode) (string, error) {
	switch manager {
	case ManagerNPM:
		return buildNPMInstall(mode)
	case ManagerPNPM:
		return buildPNPMInstall(mode)
	case ManagerBun:
		return buildBunInstall(mode)
	default:
		return "", diagnostic.New(
			fmt.Sprintf("Unsupported package manager %q.", manager),
			diagnostic.Cause("GoAudit can only build scan-project install commands for npm, pnpm, and bun."),
			diagnostic.Hint("Pass --manager npm, --manager pnpm, or --manager bun, or use goaudit scan with an explicit command."),
		)
	}
}

func buildNPMInstall(mode UpgradeMode) (string, error) {
	switch mode {
	case UpgradeRefreshLock:
		return "rm -f package-lock.json\nnpm install", nil
	case UpgradeNCU:
		return "npx -y npm-check-updates@latest -u\nnpm install", nil
	case UpgradeUpdate:
		return "npm update", nil
	default:
		return "", unsupportedUpgradeModeDiagnostic(mode)
	}
}

func buildPNPMInstall(mode UpgradeMode) (string, error) {
	switch mode {
	case UpgradeRefreshLock:
		return "rm -f pnpm-lock.yaml\npnpm install", nil
	case UpgradeNCU:
		return "npx -y npm-check-updates@latest -u\npnpm install", nil
	case UpgradeUpdate:
		return "pnpm update", nil
	default:
		return "", unsupportedUpgradeModeDiagnostic(mode)
	}
}

func buildBunInstall(mode UpgradeMode) (string, error) {
	switch mode {
	case UpgradeRefreshLock:
		return "rm -f bun.lockb bun.lock\nbun install", nil
	case UpgradeNCU:
		return "bun update", nil
	case UpgradeUpdate:
		return "bun update", nil
	default:
		return "", unsupportedUpgradeModeDiagnostic(mode)
	}
}

func unsupportedUpgradeModeDiagnostic(mode UpgradeMode) error {
	return diagnostic.New(
		fmt.Sprintf("Unknown upgrade mode %q.", mode),
		diagnostic.Cause("The install command builder only understands refresh-lock, ncu, and update."),
		diagnostic.Hint("Use --upgrade-mode refresh-lock, --upgrade-mode ncu, or --upgrade-mode update."),
	)
}
