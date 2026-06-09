package probe

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultTimeoutSec is the default timeout for runtime probes.
const DefaultTimeoutSec = 15

// GenerateNodeProbeScript generates a bash snippet that creates and runs
// a Node.js probe script. The probe require()s/import()s each package
// to trigger runtime behavior under strace monitoring.
func GenerateNodeProbeScript(packages []string, timeoutSec int) string {
	if len(packages) == 0 {
		return ""
	}
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeoutSec
	}

	pkgJSON, _ := json.Marshal(packages)

	js := fmt.Sprintf(
		`setTimeout(function(){process.exit(0)},%d);`+
			`var _pkgs=%s;`+
			`(async function(){for(var i=0;i<_pkgs.length;i++){`+
			`try{require(_pkgs[i])}catch(e){`+
			`try{await import(_pkgs[i])}catch(e2){}}}})();`,
		timeoutSec*1000, string(pkgJSON))

	var b strings.Builder
	b.WriteString("\ncat << 'GOAUDIT_PROBE_EOF' > /workspace/.goaudit_probe.js\n")
	b.WriteString(js + "\n")
	b.WriteString("GOAUDIT_PROBE_EOF\n")
	b.WriteString(fmt.Sprintf("NODE_PATH=/workspace/node_modules timeout %d node /workspace/.goaudit_probe.js 2>/dev/null || true\n", timeoutSec+2))
	return b.String()
}
