// Package logx is a minimal levelled logger that writes status to stderr so
// stdout stays clean for results.
package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	verbose bool
	quiet   bool
	color   bool
}

func New(w io.Writer, verbose, quiet, color bool) *Logger {
	return &Logger{w: w, verbose: verbose, quiet: quiet, color: color}
}

// Discard returns a logger that writes nothing (useful in tests).
func Discard() *Logger { return New(io.Discard, false, true, false) }

// IsTerminal reports whether f looks like an interactive terminal.
func IsTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
)

func (l *Logger) print(color, tag, format string, args ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	if l.color {
		fmt.Fprintf(l.w, "%s[%s]%s %s\n", color, tag, reset, msg)
	} else {
		fmt.Fprintf(l.w, "[%s] %s\n", tag, msg)
	}
}

// Raw writes text as-is unless quiet.
func (l *Logger) Raw(s string) {
	if l == nil || l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.w, s)
}

func (l *Logger) Color() bool { return l != nil && l.color }

func (l *Logger) Info(format string, args ...any) {
	if l != nil && !l.quiet {
		l.print(cyan, "INF", format, args...)
	}
}

func (l *Logger) Warn(format string, args ...any) {
	if l != nil && !l.quiet {
		l.print(yellow, "WRN", format, args...)
	}
}

// Error is always printed, even when quiet.
func (l *Logger) Error(format string, args ...any) { l.print(red, "ERR", format, args...) }

func (l *Logger) Debug(format string, args ...any) {
	if l != nil && l.verbose && !l.quiet {
		l.print(grey, "DBG", format, args...)
	}
}
