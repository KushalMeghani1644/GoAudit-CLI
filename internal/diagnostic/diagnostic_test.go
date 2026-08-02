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

func TestFormatTypedNilDiagnosticDoesNotPanic(t *testing.T) {
	var err *Error
	out := Format(err)
	if out != "Error: \n" {
		t.Fatalf("unexpected typed-nil diagnostic format: %q", out)
	}
}

func TestFormatDiagnosticWithoutCauseDoesNotRepeatRootError(t *testing.T) {
	err := New("Cannot start sandbox.", Wrap(errors.New("connection refused")))

	out := Format(err)
	if !strings.Contains(out, "Cause: connection refused\n") {
		t.Fatalf("expected root error as cause, got:\n%s", out)
	}
	if strings.Contains(out, "Details:") {
		t.Fatalf("did not expect repeated root error in details, got:\n%s", out)
	}
}
