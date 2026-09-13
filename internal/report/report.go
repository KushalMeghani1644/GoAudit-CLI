package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/diagnostic"
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
	// Confidence is retained internally for compatibility with analyzers while
	// they migrate away from numeric heuristics. It is never exposed in reports.
	Confidence int    `json:"-"`
	Path       string `json:"path,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	IP         string `json:"ip,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

type SignalCategory string

const (
	SignalCredentialAccess    SignalCategory = "credential-access"
	SignalPersistence         SignalCategory = "persistence"
	SignalNetworkExfil        SignalCategory = "network-exfil"
	SignalPrivilegeEscalation SignalCategory = "privilege-escalation"
	SignalSuspiciousRegistry  SignalCategory = "suspicious-registry"
)

type Observation struct {
	Kind       string   `json:"kind"`
	Severity   Severity `json:"severity"`
	ReasonCode string   `json:"reasonCode"`
	Path       string   `json:"path,omitempty"`
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type Signal struct {
	Category     SignalCategory `json:"category"`
	Observations []Observation  `json:"observations"`
}

type Report struct {
	Verdict     Verdict       `json:"verdict"`
	Signals     []Signal      `json:"signals"`
	Diagnostics []Observation `json:"diagnostics,omitempty"`
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

func (r *Reporter) Fatal(err error) {
	fmt.Fprint(os.Stderr, diagnostic.Format(err))
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
		"CAPABILITY_ESCALATION", "CAPABILITY_CHANGE", "NAMESPACE_ESCAPE_ATTEMPT", "LD_PRELOAD_PRIVILEGE_ATTEMPT",
		"ACCOUNT_FILE_ACCESS", "MOUNT_OPERATION_ATTEMPT", "PRIVILEGED_KERNEL_OPERATION_ATTEMPT":
		return true
	default:
		return false
	}
}

func isHardMalicious(f Finding) bool {
	// ACCOUNT_FILE_ACCESS is intentionally not hard-malicious by reason code alone:
	// failed/shadow-denied opens are warnings, and successful Critical cases still
	// force MALICIOUS via SeverityCritical in Evaluate.
	return f.ReasonCode == "CREDENTIAL_READ" ||
		f.ReasonCode == "PERSISTENCE_WRITE" ||
		f.ReasonCode == "REVERSE_SHELL" ||
		f.ReasonCode == "PRIVILEGE_ESCALATION" ||
		f.ReasonCode == "SUID_SGID_BIT_SET" ||
		f.ReasonCode == "CAPABILITY_ESCALATION" ||
		f.ReasonCode == "NAMESPACE_ESCAPE_ATTEMPT" ||
		f.ReasonCode == "LD_PRELOAD_PRIVILEGE_ATTEMPT" ||
		f.ReasonCode == "OWNERSHIP_CHANGE" ||
		f.ReasonCode == "MOUNT_OPERATION" ||
		f.ReasonCode == "PRIVILEGED_KERNEL_OPERATION" ||
		f.ReasonCode == "FILELESS_EXEC" ||
		f.ReasonCode == "PROCESS_INJECTION" ||
		f.ReasonCode == "ENV_THEFT" ||
		f.ReasonCode == "DATA_EXFIL" ||
		f.ReasonCode == "CLOUD_METADATA_ACCESS"
}

func isExpectedBehaviorReason(reasonCode string) bool {
	switch reasonCode {
	case "NPM_LIFECYCLE_SCRIPTS", "PNPM_LIFECYCLE_SCRIPTS", "BUN_INSTALL_SCRIPTS", "EXTERNAL_NETWORK_REGISTRY":
		return true
	default:
		return false
	}
}

// BuildSignals converts detector findings into the stable, evidence-first
// report schema. Categories explain the risk; observations show what happened.
func BuildSignals(findings []Finding) []Signal {
	grouped := map[SignalCategory][]Observation{}
	for _, finding := range findings {
		if finding.Type == "runtime" || isOperationalFinding(finding) {
			continue
		}
		category := SignalSuspiciousRegistry
		kind := "registry-metadata-flag"
		reason := strings.ToUpper(finding.ReasonCode)

		switch {
		case finding.Type == "fs_read" || strings.Contains(reason, "CREDENTIAL") || reason == "ENV_THEFT":
			category, kind = SignalCredentialAccess, "file-read"
		case finding.Type == "fs_write" || strings.Contains(reason, "PERSISTENCE") || reason == "SYMLINK_SENSITIVE_PATH":
			category, kind = SignalPersistence, "file-write"
		case finding.Type == "network" || strings.Contains(reason, "EXFIL") || reason == "BACKDOOR_LISTENER":
			category, kind = SignalNetworkExfil, "network-connection"
		case finding.Type == "privilege" || strings.Contains(reason, "PRIVILEGE") ||
			strings.Contains(reason, "CAPABILITY") || strings.Contains(reason, "SUID") ||
			strings.Contains(reason, "OWNERSHIP") || strings.Contains(reason, "MOUNT_OPERATION"):
			category, kind = SignalPrivilegeEscalation, "privilege-operation"
		case finding.Type == "exec" || finding.Type == "command":
			category, kind = SignalPersistence, "process-spawn"
		}

		grouped[category] = append(grouped[category], Observation{
			Kind:       kind,
			Severity:   finding.Severity,
			ReasonCode: finding.ReasonCode,
			Path:       finding.Path,
			Host:       finding.Host,
			Port:       finding.Port,
			IP:         finding.IP,
			Evidence:   finding.Evidence,
		})
	}

	categories := []SignalCategory{
		SignalCredentialAccess,
		SignalPersistence,
		SignalNetworkExfil,
		SignalPrivilegeEscalation,
		SignalSuspiciousRegistry,
	}
	signals := make([]Signal, 0, len(categories))
	for _, category := range categories {
		if observations := grouped[category]; len(observations) > 0 {
			signals = append(signals, Signal{Category: category, Observations: observations})
		}
	}
	return signals
}

func BuildDiagnostics(findings []Finding) []Observation {
	var diagnostics []Observation
	for _, finding := range findings {
		if finding.Type != "runtime" && !isOperationalFinding(finding) {
			continue
		}
		diagnostics = append(diagnostics, Observation{
			Kind:       "diagnostic",
			Severity:   finding.Severity,
			ReasonCode: finding.ReasonCode,
			Path:       finding.Path,
			Evidence:   finding.Evidence,
		})
	}
	return diagnostics
}

func Evaluate(findings []Finding, opts EvaluationOptions) Verdict {
	if len(findings) == 0 {
		return VerdictClean
	}

	malicious := false
	suspicious := false
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
		if f.Severity == SeverityWarning && !isExpectedBehaviorReason(f.ReasonCode) {
			suspicious = true
		}
	}

	if malicious {
		return VerdictMalicious
	}
	if inconclusive {
		return VerdictInconclusive
	}
	if suspicious {
		return VerdictSuspicious
	}
	return VerdictClean
}

func (r *Reporter) Report(findings []Finding, meta ReportMeta) Verdict {
	r.StopProgress()
	verdict := Evaluate(findings, EvaluationOptions{
		SuppressExpectedBehavior: meta.SuppressExpectedBehavior,
	})

	if r.CIMode {
		rep := Report{
			Verdict:     verdict,
			Signals:     BuildSignals(findings),
			Diagnostics: BuildDiagnostics(findings),
		}
		if rep.Signals == nil {
			rep.Signals = []Signal{}
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
		fmt.Print(FormatHumanReportStyled(findings, meta, verdict, HumanReportStyle{Color: useColor}) + "\r\n")
	}
	return verdict
}
