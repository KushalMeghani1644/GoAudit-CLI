package diagnostic

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatDiagnosticIncludesCauseHintsAndDetails(t *testing.T) {
	err := New(
		"Cannot pull Docker image node:current-slim.",
		Cause("The sandbox image is not available locally and Docker could not pull it."),
		Hint("Verify Docker is running."),
		Wrap(errors.New("connection refused")),
	)

	out := Format(err)
	for _, want := range []string{
		"Error: Cannot pull Docker image node:current-slim.",
		"Cause: The sandbox image is not available locally and Docker could not pull it.",
		"Hint: Verify Docker is running.",
		"Details: connection refused",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected formatted diagnostic to contain %q, got:\n%s", want, out)
		}
	}
}

func TestFormatPlainError(t *testing.T) {
	out := Format(errors.New("plain failure"))
	if out != "Error: plain failure\n" {
		t.Fatalf("unexpected plain error format: %q", out)
	}
}
