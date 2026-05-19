package project

import "fmt"

func BuildInstallCommand(manager string, mode UpgradeMode) (string, error) {
	switch manager {
	case ManagerNPM:
		return buildNPMInstall(mode)
	case ManagerPNPM:
		return buildPNPMInstall(mode)
	case ManagerBun:
		return buildBunInstall(mode)
	default:
		return "", fmt.Errorf("unsupported package manager %q", manager)
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
		return "", fmt.Errorf("unknown upgrade mode %q", mode)
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
		return "", fmt.Errorf("unknown upgrade mode %q", mode)
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
		return "", fmt.Errorf("unknown upgrade mode %q", mode)
	}
}
