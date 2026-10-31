package probe

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultTimeoutSec is the default timeout for runtime probes.
const DefaultTimeoutSec = 15

//go:embed node_probe.cjs
var nodeProbeSource string

// GenerateNodeProbeScript creates a shell snippet for the opt-in runtime probe.
// Import incompatibilities are coverage warnings; exhausted budgets exit 124.
func GenerateNodeProbeScript(packages []string, timeoutSec int) string {
	if len(packages) == 0 {
		return ""
	}
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeoutSec
	}
	pkgJSON, _ := json.Marshal(packages)
	var b strings.Builder
	// The sandbox supplies the watchdog's start time. Standalone callers fall
	// back to shell entry, still charging Node startup against the budget.
	b.WriteString("\nGOAUDIT_PROBE_STARTED_MS=${GOAUDIT_PROBE_STARTED_MS:-$(date +%s%3N)}\n")
	b.WriteString("cat << 'GOAUDIT_PROBE_EOF' > /workspace/.goaudit_probe.cjs\n")
	source := strings.Replace(nodeProbeSource, "/*GOAUDIT_CONFIG*/", fmt.Sprintf("const packages = %s;\nconst timeoutMS = %d;", pkgJSON, int64(timeoutSec)*1000), 1)
	b.WriteString(source)
	b.WriteString("\nGOAUDIT_PROBE_EOF\n")
	// Failsafe for the trusted controller; it cleans worker groups on SIGTERM.
	fmt.Fprintf(&b, "NODE_PATH=/workspace/node_modules timeout --signal=TERM --kill-after=1s %d node /workspace/.goaudit_probe.cjs \"$GOAUDIT_PROBE_STARTED_MS\"\n", timeoutSec+2)
	return b.String()
}
