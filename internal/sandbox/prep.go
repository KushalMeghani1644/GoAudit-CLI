package sandbox

// aptPrepScript installs sandbox tools via apt only when base scan tools are missing.
// Published sandbox images skip apt at scan time; runc fallback may still use apt.
const aptPrepScript = `if ! command -v strace >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v rsync >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
    apt-get install -y -qq --no-install-recommends strace curl ca-certificates dnsutils rsync > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
  else
    echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2
    exit 98
  fi
fi
`

func prepScriptForRuntime(runtime string) string {
	if runtime == "runsc" {
		return ""
	}
	return aptPrepScript
}
