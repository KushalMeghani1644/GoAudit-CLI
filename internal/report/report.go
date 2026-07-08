package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

type Verdict string

const (
	VerdictClean        Verdict = "CLEAN"
	VerdictSuspicious   Verdict = "SUSPICIOUS"
	VerdictMalicious    Verdict = "MALICIOUS"
	VerdictInconclusive Verdict = "INCONCLUSIVE"
)

type Finding struct {
	Severity   Severity `json:"severity"`
	Type       string   `json:"type"`
	ReasonCode string   `json:"reasonCode,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Path       string   `json:"path,omitempty"`
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type Report struct {
	Verdict    Verdict   `json:"verdict"`
	Confidence int       `json:"confidence"`
	Findings   []Finding `json:"findings"`
}
type ReportMeta struct {
	Command                  string       `json:"command,omitempty"`
	ProfileName              string       `json:"profileName,omitempty"`
	PackageName              string       `json:"packageName,omitempty"`
	PackageVersion           string       `json:"packageVersion,omitempty"`
	SandboxRuntime           string       `json:"sandboxRuntime,omitempty"`
	SuppressExpectedBehavior bool         `json:"suppressExpectedBehavior,omitempty"`
	Dynamic                  *DynamicMeta `json:"dynamic,omitempty"`
}

type DynamicMeta struct {
	Target DynamicPhaseMeta `json:"target"`
	Probe  DynamicPhaseMeta `json:"probe"`
}

type DynamicPhaseMeta struct {
	Expected        bool `json:"expected,omitempty"`
	PhaseObserved   bool `json:"phaseObserved"`
	ExitObserved    bool `json:"exitObserved"`
	ExitCode        int  `json:"exitCode,omitempty"`
	SyscallObserved bool `json:"syscallObserved"`
	TimedOut        bool `json:"timedOut,omitempty"`
}

type EvaluationOptions struct {
	SuppressExpectedBehavior bool
}

type Reporter struct {
	CIMode           bool
	Verbose          bool
	seenNetworkHosts map[string]int
	networkDupCount  int
	mu               sync.Mutex
	spinnerStop      chan struct{}
	spinnerDone      chan struct{}
	spinnerMessage   string
}

func NewReporter(ciMode bool, verbose bool) *Reporter {
	return &Reporter{
		CIMode:           ciMode,
		Verbose:          verbose,
		seenNetworkHosts: make(map[string]int),
	}
}

func (r *Reporter) Fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
func (r *Reporter) StartProgress(message string) {
	if r.CIMode {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spinnerStop != nil {
		r.spinnerMessage = message
		return
	}
	r.spinnerStop = make(chan struct{})
	r.spinnerDone = make(chan struct{})
	r.spinnerMessage = message
	go func() {
		defer close(r.spinnerDone)
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.spinnerStop:
				fmt.Print("\r\033[K")
				return
			case <-ticker.C:
				r.mu.Lock()
				msg := r.spinnerMessage
				r.mu.Unlock()
				fmt.Printf("\r⏳ %s %s", msg, frames[i%len(frames)])
				i++
			}
		}
	}()
}

func (r *Reporter) UpdateProgress(message string) {
	if r.CIMode {
		return
	}
	r.mu.Lock()
	r.spinnerMessage = message
	r.mu.Unlock()
}

func (r *Reporter) StopProgress() {
	if r.CIMode {
		return
	}
	r.mu.Lock()
	stop := r.spinnerStop
	done := r.spinnerDone
	r.spinnerStop = nil
	r.spinnerDone = nil
	r.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

func (r *Reporter) PrintLiveFinding(f Finding) {
	if r.CIMode {
		return
	}
	if !r.Verbose && f.Severity != SeverityCritical && !isPrivilegeWarning(f) {
		return
	}
	if f.ReasonCode == "RUNTIME_METADATA" {
		return
	}
	if f.Severity == SeverityCritical {
		if f.Type == "privilege" {
			color.Red("[CRITICAL] %s: %s\r\n", ExplainReason(f.ReasonCode).Title, f.Path)
		} else if f.Type == "fs_read" {
			color.Red("[CRITICAL] File Read Detected: %s\r\n", f.Path)
		} else if f.Type == "fs_write" {
			color.Red("[CRITICAL] Suspicious File Write: %s\r\n", f.Path)
		} else if f.Type == "exec" {
			color.Red("[CRITICAL] Suspicious Process Executed: %s\r\n", f.Path)
		} else {
			color.Red("[CRITICAL] %s: %s\r\n", f.Type, f.Path)
		}
		return
	}

	if f.Severity == SeverityWarning {
		if isPrivilegeWarning(f) {
			color.Yellow("[WARNING] %s: %s\r\n", ExplainReason(f.ReasonCode).Title, f.Path)
			return
		}
		if f.Type == "network" && f.ReasonCode == "EXTERNAL_NETWORK" {
			// Deduplicate network warnings — only print first occurrence per IP.
			r.seenNetworkHosts[f.IP]++
			if r.seenNetworkHosts[f.IP] > 1 {
				r.networkDupCount++
				return
			}
			color.Yellow("[WARNING] Network Connection: %s (%s:%d)\r\n", f.Host, f.IP, f.Port)
		} else if f.Type == "command" {
			color.Yellow("[WARNING] Suspicious Command Pattern: %s\r\n", f.Path)
		} else if f.Type == "fs_write" {
			color.Yellow("[WARNING] Unexpected File Write: %s\r\n", f.Path)
		} else {
			color.Yellow("[WARNING] %s: %s\r\n", f.Type, f.Path)
		}
		return
	}

	if r.Verbose {
		color.Cyan("[INFO] %s: %s\n", f.Type, f.Path)
	}
}

func isPrivilegeWarning(f Finding) bool {
	if f.Severity != SeverityWarning || f.Type != "privilege" {
		return false
	}
	switch f.ReasonCode {
	case "PRIVILEGE_ESCALATION_ATTEMPT", "PRIVILEGE_ESCALATION_EXEC", "SUID_SGID_BIT_SET",
		"CAPABILITY_ESCALATION", "NAMESPACE_ESCAPE_ATTEMPT", "LD_PRELOAD_PRIVILEGE_ATTEMPT",
		"ACCOUNT_FILE_ACCESS":
		return true
	default:
		return false
	}
}

func isHardMalicious(f Finding) bool {
	return f.ReasonCode == "CREDENTIAL_READ" ||
		f.ReasonCode == "PERSISTENCE_WRITE" ||
		f.ReasonCode == "REVERSE_SHELL" ||
		f.ReasonCode == "PRIVILEGE_ESCALATION" ||
		f.ReasonCode == "SUID_SGID_BIT_SET" ||
		f.ReasonCode == "CAPABILITY_ESCALATION" ||
		f.ReasonCode == "NAMESPACE_ESCAPE_ATTEMPT" ||
		f.ReasonCode == "LD_PRELOAD_PRIVILEGE_ATTEMPT" ||
		f.ReasonCode == "ACCOUNT_FILE_ACCESS" ||
		f.ReasonCode == "FILELESS_EXEC" ||
		f.ReasonCode == "PROCESS_INJECTION" ||
		f.ReasonCode == "ENV_THEFT" ||
		f.ReasonCode == "DATA_EXFIL" ||
		f.ReasonCode == "CLOUD_METADATA_ACCESS"
}

func reasonWeight(reasonCode string) int {
	switch reasonCode {
	case "CREDENTIAL_READ", "PERSISTENCE_WRITE", "PRIVILEGE_ESCALATION", "ENV_THEFT", "DATA_EXFIL":
		return 80
	case "ACCOUNT_FILE_ACCESS":
		return 80
	case "SUID_SGID_BIT_SET", "CAPABILITY_ESCALATION", "NAMESPACE_ESCAPE_ATTEMPT", "LD_PRELOAD_PRIVILEGE_ATTEMPT":
		return 70
	case "PRIVILEGE_ESCALATION_ATTEMPT", "PRIVILEGE_ESCALATION_EXEC":
		return 45
	case "STAGED_DOWNLOADER", "SUSPICIOUS_EXEC", "SCRIPT_OBFUSCATION":
		return 55
	case "FILELESS_EXEC", "PROCESS_INJECTION", "SYMLINK_SENSITIVE_PATH":
		return 85
	case "BACKDOOR_LISTENER":
		return 55
	case "CURL_PIPE_SHELL":
		return 35
	// Generic lifecycle warnings — always fire for any npm/pnpm/bun install.
	// Low weight because they carry no package-specific signal.
	case "NPM_LIFECYCLE_SCRIPTS", "PNPM_LIFECYCLE_SCRIPTS", "BUN_INSTALL_SCRIPTS":
		return 10
	// Package-specific lifecycle metadata — noteworthy but common for legit packages.
	case "NPM_LIFECYCLE_SCRIPT_METADATA", "PNPM_LIFECYCLE_SCRIPT_METADATA", "BUN_LIFECYCLE_SCRIPT_METADATA":
		return 20
	case "NPM_NON_REGISTRY_SOURCE", "PNPM_NON_REGISTRY_SOURCE", "BUN_NON_REGISTRY_SOURCE":
		return 45
	case "NPM_RECENT_PACKAGE", "PNPM_RECENT_PACKAGE", "BUN_RECENT_PACKAGE":
		return 20
	case "UNEXPECTED_WRITE":
		return 30
	// External network — expected during package installs. Low individual weight.
	case "EXTERNAL_NETWORK":
		return 25
	case "INTERNAL_NETWORK":
		return 20
	case "CLOUD_METADATA_ACCESS":
		return 80
	case "EXTERNAL_NETWORK_REGISTRY":
		return 0
	case "RUNTIME_MISSING_TOOL", "RUNTIME_PREP_FAILURE", "RUNTIME_TRACE_UNAVAILABLE":
		return 60
	case "RUNSC_TRACE_FALLBACK_RUNC":
		return 0
	case "TARGET_COMMAND_NOT_FOUND", "TARGET_COMMAND_FAILED", "TARGET_COMMAND_TIMEOUT", "PROBE_COMMAND_NOT_FOUND", "PROBE_COMMAND_FAILED", "PROBE_COMMAND_TIMEOUT":
		return 60
	case "POLICY_BLOCKED_DOMAIN":
		return 20
	case "INCONCLUSIVE_NPM_METADATA", "INCONCLUSIVE_REMOTE_FETCH", "NPM_INCONCLUSIVE_METADATA":
		return 10
	case "INCONCLUSIVE_PNPM_METADATA", "INCONCLUSIVE_BUN_METADATA", "PNPM_INCONCLUSIVE_METADATA", "BUN_INCONCLUSIVE_METADATA":
		return 10
	case "SCRIPT_FETCHED", "RUNTIME_METADATA":
		return 0
	// Lifecycle content analysis (from registry script inspection)
	case "NPM_LIFECYCLE_STAGED_DOWNLOADER", "PNPM_LIFECYCLE_STAGED_DOWNLOADER", "BUN_LIFECYCLE_STAGED_DOWNLOADER":
		return 70
	case "NPM_LIFECYCLE_REVERSE_SHELL", "PNPM_LIFECYCLE_REVERSE_SHELL", "BUN_LIFECYCLE_REVERSE_SHELL":
		return 85
	case "NPM_LIFECYCLE_CREDENTIAL_READ", "PNPM_LIFECYCLE_CREDENTIAL_READ", "BUN_LIFECYCLE_CREDENTIAL_READ":
		return 80
	case "NPM_LIFECYCLE_SCRIPT_OBFUSCATION", "PNPM_LIFECYCLE_SCRIPT_OBFUSCATION", "BUN_LIFECYCLE_SCRIPT_OBFUSCATION":
		return 60
	case "NPM_LIFECYCLE_PERSISTENCE_WRITE", "PNPM_LIFECYCLE_PERSISTENCE_WRITE", "BUN_LIFECYCLE_PERSISTENCE_WRITE":
		return 80
	default:
		return 15
	}
}
func isExpectedBehaviorReason(reasonCode string) bool {
	switch reasonCode {
	case "NPM_LIFECYCLE_SCRIPTS", "PNPM_LIFECYCLE_SCRIPTS", "BUN_INSTALL_SCRIPTS", "EXTERNAL_NETWORK_REGISTRY":
		return true
	default:
		return false
	}
}

func Evaluate(findings []Finding, opts EvaluationOptions) (Verdict, int) {
	if len(findings) == 0 {
		return VerdictClean, 90
	}

	score := 0
	malicious := false
	inconclusive := false
	hasRunscFallback := false
	hasRuncTraceUnavailable := false
	for _, f := range findings {
		if f.ReasonCode == "RUNSC_TRACE_FALLBACK_RUNC" {
			hasRunscFallback = true
		}
		if f.ReasonCode == "RUNTIME_TRACE_UNAVAILABLE" && strings.Contains(strings.ToLower(f.Evidence), "runc runtime trace") {
			hasRuncTraceUnavailable = true
		}
	}
	seenReasonWeight := map[string]int{}
	for _, f := range findings {
		if isHardMalicious(f) || f.Severity == SeverityCritical {
			malicious = true
		}
		if f.ReasonCode == "RUNTIME_MISSING_TOOL" ||
			f.ReasonCode == "RUNTIME_PREP_FAILURE" ||
			f.ReasonCode == "TARGET_COMMAND_NOT_FOUND" ||
			f.ReasonCode == "TARGET_COMMAND_FAILED" ||
			f.ReasonCode == "TARGET_COMMAND_TIMEOUT" ||
			f.ReasonCode == "PROBE_COMMAND_NOT_FOUND" ||
			f.ReasonCode == "PROBE_COMMAND_FAILED" ||
			f.ReasonCode == "PROBE_COMMAND_TIMEOUT" {
			inconclusive = true
		}
		if f.ReasonCode == "RUNTIME_TRACE_UNAVAILABLE" {
			if !hasRunscFallback || hasRuncTraceUnavailable || strings.Contains(strings.ToLower(f.Evidence), "runc runtime trace") {
				inconclusive = true
			}
		}
		if opts.SuppressExpectedBehavior && isExpectedBehaviorReason(f.ReasonCode) {
			continue
		}
		w := reasonWeight(f.ReasonCode)
		if f.ReasonCode == "EXTERNAL_NETWORK" || f.ReasonCode == "EXTERNAL_NETWORK_REGISTRY" {
			// Cap total network contribution at 10 to avoid flooding the score.
			if seenReasonWeight[f.ReasonCode] >= 10 {
				continue
			}
			seenReasonWeight[f.ReasonCode] += w
			score += w
			continue
		}
		if _, exists := seenReasonWeight[f.ReasonCode]; exists {
			continue
		}
		seenReasonWeight[f.ReasonCode] = w
		score += w
	}
	if score > 100 {
		score = 100
	}

	if inconclusive && !malicious {
		return VerdictInconclusive, 35
	}
	if malicious || score >= 80 {
		if score < 80 {
			score = 80
		}
		return VerdictMalicious, score
	}
	if score >= 25 {
		return VerdictSuspicious, 40 + (score / 2)
	}
	return VerdictClean, 75
}

func (r *Reporter) Report(findings []Finding, meta ReportMeta) (Verdict, int) {
	r.StopProgress()
	verdict, confidence := Evaluate(findings, EvaluationOptions{
		SuppressExpectedBehavior: meta.SuppressExpectedBehavior,
	})

	if r.CIMode {
		rep := Report{
			Verdict:    verdict,
			Confidence: confidence,
			Findings:   findings,
		}
		if rep.Findings == nil {
			rep.Findings = []Finding{}
		}
		out, _ := json.MarshalIndent(struct {
			Report
			Meta ReportMeta `json:"meta,omitempty"`
		}{
			Report: rep,
			Meta:   meta,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		if strings.TrimSpace(meta.Command) == "" {
			meta.Command = "scan"
		}

		useColor := false
		// Enable ANSI colors only for interactive terminals and unless the user opted out.
		if os.Getenv("NO_COLOR") == "" {
			if fi, err := os.Stdout.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
				useColor = true
			}
		}
		fmt.Print(FormatHumanReportStyled(findings, meta, verdict, confidence, HumanReportStyle{Color: useColor}) + "\r\n")
	}
	return verdict, confidence
}
