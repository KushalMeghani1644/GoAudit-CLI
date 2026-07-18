package diagnostic

import (
	"errors"
	"fmt"
	"strings"
)

// Error carries a short user-facing summary plus the best-known cause and fixes.
type Error struct {
	Summary string
	Cause   string
	Hints   []string
	Err     error
}

func New(summary string, opts ...Option) *Error {
	e := &Error{Summary: strings.TrimSpace(summary)}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type Option func(*Error)

func Cause(cause string) Option {
	return func(e *Error) {
		e.Cause = strings.TrimSpace(cause)
	}
}

func Hint(hint string) Option {
	return func(e *Error) {
		hint = strings.TrimSpace(hint)
		if hint != "" {
			e.Hints = append(e.Hints, hint)
		}
	}
}

func Hints(hints ...string) Option {
	return func(e *Error) {
		for _, hint := range hints {
			hint = strings.TrimSpace(hint)
			if hint != "" {
				e.Hints = append(e.Hints, hint)
			}
		}
	}
}

func Wrap(err error) Option {
	return func(e *Error) {
		e.Err = err
	}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Summary != "" {
		return e.Summary
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "unknown error"
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func Format(err error) string {
	if err == nil {
		return ""
	}

	var diag *Error
	if !errors.As(err, &diag) {
		return fmt.Sprintf("Error: %v\n", err)
	}

	var b strings.Builder
	summary := diag.Summary
	if summary == "" {
		summary = diag.Error()
	}
	fmt.Fprintf(&b, "Error: %s\n", summary)
	if diag.Cause != "" {
		fmt.Fprintf(&b, "Cause: %s\n", diag.Cause)
	} else if root := RootCause(err); root != nil && root.Error() != summary {
		fmt.Fprintf(&b, "Cause: %s\n", root)
	}
	for _, hint := range diag.Hints {
		fmt.Fprintf(&b, "Hint: %s\n", hint)
	}
	if root := RootCause(err); root != nil && root.Error() != summary && root.Error() != diag.Cause {
		fmt.Fprintf(&b, "Details: %s\n", root)
	}
	return b.String()
}

func RootCause(err error) error {
	if err == nil {
		return nil
	}
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}
