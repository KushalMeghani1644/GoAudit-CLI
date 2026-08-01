package report

// Explanation provides a human-readable title and detail for a reason code.
type Explanation struct {
	Title  string
	Detail string
}

var reasonExplanations = map[string]Explanation{
	// Critical — dynamic (strace)
	"CREDENTIAL_READ":                {"Credential Theft", "Read sensitive files like SSH keys, AWS credentials, or .env secrets"},
	"PERSISTENCE_WRITE":              {"Persistence", "Modified system startup files (.bashrc, crontab, etc.) to survive reboots"},
	"PRIVILEGE_ESCALATION":           {"Privilege Escalation", "Attempted to gain root privileges via setuid(0)"},
	"PRIVILEGE_ESCALATION_ATTEMPT":   {"Privilege Escalation Attempt", "Attempted to switch UID/GID to root, but the syscall failed in the sandbox"},
	"PRIVILEGE_ESCALATION_EXEC":      {"Privilege Helper Execution", "Executed sudo, su, pkexec, or a shell command that invokes a privilege escalation helper"},
	"SUID_SGID_BIT_SET":              {"SUID/SGID Permission Change", "Attempted to set SUID or SGID bits, which can make future executions run with elevated privileges"},
	"CAPABILITY_ESCALATION":          {"Linux Capability Escalation", "Attempted to grant Linux capabilities to an executable (e.g. setcap)"},
	"CAPABILITY_CHANGE":              {"Linux Capability Change", "Used capset to modify process capabilities without a proven capability raise (drop/clear or ambiguous change)"},
	"NAMESPACE_ESCAPE_ATTEMPT":       {"Namespace Escape Attempt", "Executed namespace manipulation tooling such as unshare or nsenter"},
	"LD_PRELOAD_PRIVILEGE_ATTEMPT":   {"LD_PRELOAD Privilege Attempt", "Attempted to inject a preload library into a privileged helper"},
	"OWNERSHIP_CHANGE":               {"Ownership Change", "Changed ownership of a sensitive path (chown on startup/binaries/account files)"},
	"MOUNT_OPERATION":                {"Mount Operation", "Performed or attempted mount/umount inside the sandbox"},
	"MOUNT_OPERATION_ATTEMPT":        {"Mount Operation Attempt", "Attempted mount/umount inside the sandbox, but the syscall failed"},
	"ACCOUNT_FILE_ACCESS":            {"Privilege-Sensitive Account File Access", "Accessed /etc/passwd or /etc/shadow, which can expose account data or support privilege escalation"},
	"SUSPICIOUS_EXEC":                {"Suspicious Process", "Executed a known attack tool (netcat, reverse shell) or ran a binary from /tmp"},
	"FILELESS_EXEC":                  {"Fileless Execution", "Used memfd_create to run code without writing to disk — a common evasion technique"},
	"PROCESS_INJECTION":              {"Process Injection", "Used ptrace to attach to another process — possible code injection"},
	"SYMLINK_SENSITIVE_PATH":         {"Symlink Attack", "Created a symlink targeting sensitive credential files"},
	"REVERSE_SHELL":                  {"Reverse Shell", "Opened an interactive reverse shell connection"},
	"ENV_THEFT":                      {"Environment Variable Theft", "Read /proc/self/environ to steal CI secrets and environment variables"},
	"DATA_EXFIL":                     {"Data Exfiltration", "Observed a network data send (sendto/sendmsg/sendmmsg/sendfile/splice) to a non-registry host after a suspicious outbound connection"},
	"CREDENTIAL_READ_WITH_OUTBOUND":  {"Credential Access With Outbound Connection", "Read credential-like files and opened a non-registry connection; data transmission was not proven"},
	"VERSION_RESOLUTION_APPROXIMATE": {"Approximate Version Analysis", "Static analysis used dist-tags.latest because the install spec was a range or unresolved tag"},
	"PACKAGE_PARSE_INCOMPLETE":       {"Package Command Parse Incomplete", "Could not extract package specs from a package-manager command (quoting, pipes, or wrappers)"},
	"PROBE_LIMITATION":               {"Runtime Probe Limitation", "Runtime probe only loads package entrypoints and optional CLI --help; delayed or input-driven paths are not exercised"},

	// Warning — dynamic (strace)
	"EXTERNAL_NETWORK":          {"Unknown Network Connection", "Connected to a host that isn't a known package registry"},
	"EXTERNAL_NETWORK_REGISTRY": {"Registry Connection", "Connected to a known package registry (expected during install)"},
	"BACKDOOR_LISTENER":         {"Backdoor Listener", "Opened a listening port inside the sandbox — possible backdoor"},
	"UNEXPECTED_WRITE":          {"Unexpected File Write", "Wrote to an unusual location outside normal package directories"},

	// Warning — static (command analysis)
	"CURL_PIPE_SHELL":    {"Pipe to Shell", "Command pipes downloaded content directly into a shell interpreter"},
	"SCRIPT_OBFUSCATION": {"Obfuscated Code", "Command uses base64 decoding, eval, or other obfuscation techniques"},
	"STAGED_DOWNLOADER":  {"Staged Downloader", "Script downloads and immediately executes remote code"},

	// Warning — static (registry metadata)
	"NPM_LIFECYCLE_SCRIPTS":          {"Lifecycle Scripts", "npm install runs lifecycle scripts (preinstall/postinstall) — this is common"},
	"PNPM_LIFECYCLE_SCRIPTS":         {"Lifecycle Scripts", "pnpm install runs lifecycle scripts — this is common"},
	"BUN_INSTALL_SCRIPTS":            {"Lifecycle Scripts", "bun add runs install scripts — this is common"},
	"NPM_LIFECYCLE_SCRIPT_METADATA":  {"Package Has Lifecycle Script", "The package defines a lifecycle script in its registry metadata"},
	"PNPM_LIFECYCLE_SCRIPT_METADATA": {"Package Has Lifecycle Script", "The package defines a lifecycle script in its registry metadata"},
	"BUN_LIFECYCLE_SCRIPT_METADATA":  {"Package Has Lifecycle Script", "The package defines a lifecycle script in its registry metadata"},
	"NPM_NON_REGISTRY_SOURCE":        {"Non-Registry Source", "Package is installed from a URL, git repo, or local path — not the npm registry"},
	"PNPM_NON_REGISTRY_SOURCE":       {"Non-Registry Source", "Package is installed from a non-registry source"},
	"BUN_NON_REGISTRY_SOURCE":        {"Non-Registry Source", "Package is installed from a non-registry source"},
	"NPM_RECENT_PACKAGE":             {"Recently Published", "Package was published very recently — new packages have higher risk"},
	"PNPM_RECENT_PACKAGE":            {"Recently Published", "Package was published very recently"},
	"BUN_RECENT_PACKAGE":             {"Recently Published", "Package was published very recently"},

	// Lifecycle content analysis (static)
	"NPM_LIFECYCLE_STAGED_DOWNLOADER":   {"Malicious Lifecycle Script", "Lifecycle script references downloading and executing remote code"},
	"PNPM_LIFECYCLE_STAGED_DOWNLOADER":  {"Malicious Lifecycle Script", "Lifecycle script references downloading and executing remote code"},
	"BUN_LIFECYCLE_STAGED_DOWNLOADER":   {"Malicious Lifecycle Script", "Lifecycle script references downloading and executing remote code"},
	"NPM_LIFECYCLE_REVERSE_SHELL":       {"Malicious Lifecycle Script", "Lifecycle script references opening a reverse shell"},
	"PNPM_LIFECYCLE_REVERSE_SHELL":      {"Malicious Lifecycle Script", "Lifecycle script references opening a reverse shell"},
	"BUN_LIFECYCLE_REVERSE_SHELL":       {"Malicious Lifecycle Script", "Lifecycle script references opening a reverse shell"},
	"NPM_LIFECYCLE_CREDENTIAL_READ":     {"Malicious Lifecycle Script", "Lifecycle script references reading credential files"},
	"PNPM_LIFECYCLE_CREDENTIAL_READ":    {"Malicious Lifecycle Script", "Lifecycle script references reading credential files"},
	"BUN_LIFECYCLE_CREDENTIAL_READ":     {"Malicious Lifecycle Script", "Lifecycle script references reading credential files"},
	"NPM_LIFECYCLE_SCRIPT_OBFUSCATION":  {"Obfuscated Lifecycle Script", "Lifecycle script uses obfuscation techniques"},
	"PNPM_LIFECYCLE_SCRIPT_OBFUSCATION": {"Obfuscated Lifecycle Script", "Lifecycle script uses obfuscation techniques"},
	"BUN_LIFECYCLE_SCRIPT_OBFUSCATION":  {"Obfuscated Lifecycle Script", "Lifecycle script uses obfuscation techniques"},
	"NPM_LIFECYCLE_PERSISTENCE_WRITE":   {"Malicious Lifecycle Script", "Lifecycle script references modifying system startup files"},
	"PNPM_LIFECYCLE_PERSISTENCE_WRITE":  {"Malicious Lifecycle Script", "Lifecycle script references modifying system startup files"},
	"BUN_LIFECYCLE_PERSISTENCE_WRITE":   {"Malicious Lifecycle Script", "Lifecycle script references modifying system startup files"},

	// Runtime
	"RUNTIME_MISSING_TOOL":                {"Missing Tool", "A required tool was not found in the sandbox"},
	"RUNTIME_PREP_FAILURE":                {"Sandbox Setup Failed", "The sandbox preparation phase failed"},
	"RUNTIME_TRACE_UNAVAILABLE":           {"Runtime Trace Unavailable", "Sandbox command ran without usable target/probe runtime trace evidence"},
	"RUNSC_FALLBACK_RUNC":                 {"gVisor Fallback", "gVisor prep failed; scan retried using runc"},
	"RUNSC_TRACE_FALLBACK_RUNC":           {"gVisor Trace Fallback", "gVisor runtime tracing was unavailable; scan retried using runc"},
	"TARGET_COMMAND_FAILED":               {"Command Failed", "The target command exited with a non-zero status"},
	"TARGET_COMMAND_NOT_FOUND":            {"Command Not Found", "The target command was not found in the sandbox"},
	"RUNTIME_METADATA":                    {"Runtime Metadata", "Runtime metadata emitted by the sandbox for diagnostics"},
	"SCRIPT_FETCHED":                      {"Remote Script Fetched", "A remote script was retrieved for static analysis"},
	"SCRIPT_TRUNCATED":                    {"Remote Script Truncated", "Remote script exceeded the analysis size limit and was truncated"},
	"SSRF_BLOCKED_DESTINATION":            {"Unsafe Remote Destination Blocked", "Remote script fetch blocked because the destination resolved to a non-public or disallowed address"},
	"LOCAL_PACKAGE_REWRITE_UNAVAILABLE":   {"Local Package Rewrite Unavailable", "The local package install could not be rewritten to a single package directory; mounting the working directory is refused unless explicitly requested"},
	"PROJECT_TREE_STAGED":                 {"Project Tree Staged", "A secret-redacted project copy, rather than the live host project, was bind-mounted into the sandbox"},
	"STATIC_COVERAGE_LIMIT":               {"Static Coverage Limit", "Not all package specs were statically analyzed against the registry"},
	"TRANSITIVE_LOCKFILE_MISSING":         {"Transitive Lockfile Missing", "--include-transitive was set but no supported lockfile was found"},
	"TRANSITIVE_LOCKFILE_UNSUPPORTED":     {"Transitive Lockfile Unsupported", "A lockfile was found but could not be parsed for transitive dependencies"},
	"NPM_VERSION_RESOLUTION_APPROXIMATE":  {"Approximate Version Analysis", "Static analysis used dist-tags.latest because the install spec was a range or unresolved tag"},
	"PNPM_VERSION_RESOLUTION_APPROXIMATE": {"Approximate Version Analysis", "Static analysis used dist-tags.latest because the install spec was a range or unresolved tag"},
	"BUN_VERSION_RESOLUTION_APPROXIMATE":  {"Approximate Version Analysis", "Static analysis used dist-tags.latest because the install spec was a range or unresolved tag"},

	// Policy
	"POLICY_BLOCKED_DOMAIN":      {"Blocked Domain", "Remote script URL was blocked by the domain allowlist policy"},
	"INCONCLUSIVE_REMOTE_FETCH":  {"Fetch Failed", "Could not retrieve remote script for analysis"},
	"INCONCLUSIVE_NPM_METADATA":  {"Metadata Fetch Failed", "Could not fetch npm package metadata for full static checks"},
	"INCONCLUSIVE_PNPM_METADATA": {"Metadata Fetch Failed", "Could not fetch pnpm package metadata for full static checks"},
	"INCONCLUSIVE_BUN_METADATA":  {"Metadata Fetch Failed", "Could not fetch bun package metadata for full static checks"},
	// Generated by managerReason() — canonical codes used at runtime.
	"NPM_INCONCLUSIVE_METADATA":       {"Metadata Fetch Failed", "Could not fetch npm package metadata for full static checks"},
	"PNPM_INCONCLUSIVE_METADATA":      {"Metadata Fetch Failed", "Could not fetch pnpm package metadata for full static checks"},
	"BUN_INCONCLUSIVE_METADATA":       {"Metadata Fetch Failed", "Could not fetch bun package metadata for full static checks"},
	"NPM_INCONCLUSIVE_LOCAL_PACKAGE":  {"Local Package Mount Fallback", "The local package install could not be rewritten to a single package directory"},
	"PNPM_INCONCLUSIVE_LOCAL_PACKAGE": {"Local Package Mount Fallback", "The local package install could not be rewritten to a single package directory"},
	"BUN_INCONCLUSIVE_LOCAL_PACKAGE":  {"Local Package Mount Fallback", "The local package install could not be rewritten to a single package directory"},
}

// ExplainReason returns a human-readable explanation for a reason code.
func ExplainReason(code string) Explanation {
	if e, ok := reasonExplanations[code]; ok {
		return e
	}
	return Explanation{Title: code, Detail: ""}
}

// AllReasonExplanations returns a copy of the explanation map for tests and validation.
func AllReasonExplanations() map[string]Explanation {
	out := make(map[string]Explanation, len(reasonExplanations))
	for k, v := range reasonExplanations {
		out[k] = v
	}
	return out
}
