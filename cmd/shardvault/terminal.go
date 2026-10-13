package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"golang.org/x/term"
)

const maxInputBytes = 16 * 1024

var errInterrupted = errors.New("session cancelled")
var errInputTooLong = errors.New("input exceeds 16 KiB; session cancelled")

type terminal struct {
	in     *bufio.Reader
	out    io.Writer
	skipLF bool
}

// Raw mode avoids OS canonical-line limits (which can silently truncate input).
// One reader owns all input, and echo stays off for the whole session, including
// menu prompts. No password can spill into a later echo-enabled prompt.
func openTerminal() (*terminal, func(), error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, nil, errors.New("run in a trusted interactive TTY; pipelines and devices such as /dev/null are refused")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot enter secure terminal input mode: %w", err)
	}
	t := &terminal{in: bufio.NewReaderSize(os.Stdin, 1024), out: crlfWriter{os.Stdout}}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			fmt.Fprint(t.out, "\033[?2004l\033[2J\033[H\033[?1049l\033[0m")
			if err := term.Restore(int(os.Stdin.Fd()), state); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to restore terminal settings; run reset or stty sane.")
			}
		})
	}
	interrupts := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupts, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGTSTP)
	go func() {
		select {
		case <-interrupts:
			// Treat suspension as cancellation: do not leave raw mode or secrets on
			// screen while a shell is resumed. SIGKILL cannot be handled.
			cleanup()
			os.Exit(130)
		case <-done:
		}
	}()
	fmt.Fprint(t.out, "\033[?1049h\033[?2004h")
	var finishOnce sync.Once
	return t, func() { finishOnce.Do(func() { signal.Stop(interrupts); close(done); cleanup() }) }, nil
}

type crlfWriter struct{ w io.Writer }

func (w crlfWriter) Write(p []byte) (int, error) {
	// Raw terminals do not translate LF into CRLF.
	_, err := io.WriteString(w.w, strings.ReplaceAll(string(p), "\n", "\r\n"))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func fatalInput(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, errInterrupted) || errors.Is(err, errInputTooLong)
}

func (t *terminal) readLine() (string, error) {
	buf := make([]byte, 0, maxInputBytes)
	defer func() { clear(buf[:cap(buf)]) }()
	pasted, overflow := false, false
	appendByte := func(b byte) {
		if len(buf) >= maxInputBytes {
			overflow = true
			return
		}
		buf = append(buf, b)
	}
	for {
		b, err := t.in.ReadByte()
		if err != nil {
			return "", err
		} // Never accept a partial line at EOF.
		if t.skipLF {
			t.skipLF = false
			if b == '\n' {
				continue
			}
		}
		if b == 3 || b == 4 {
			return "", errInterrupted
		} // Ctrl-C / Ctrl-D
		if b == 0x1b {
			// Bracketed paste is kept as ONE value until a separate Enter. Other
			// escape keys are ignored; they are never interpreted as commands.
			seq := []byte{b}
			for len(seq) < 16 {
				c, e := t.in.ReadByte()
				if e != nil {
					return "", e
				}
				if c == 3 || c == 4 {
					return "", errInterrupted
				}
				seq = append(seq, c)
				if len(seq) == 2 && c != '[' {
					break
				}
				if len(seq) >= 3 && c >= 0x40 && c <= 0x7e {
					break
				}
			}
			switch string(seq) {
			case "\x1b[200~":
				pasted = true
			case "\x1b[201~":
				pasted = false
			default:
				if pasted {
					for _, c := range seq {
						appendByte(c)
					}
				}
			}
			continue
		}
		if pasted {
			appendByte(b)
			continue
		}
		switch b {
		case '\r', '\n':
			t.skipLF = b == '\r'
			fmt.Fprintln(t.out)
			if overflow {
				return "", errInputTooLong
			}
			if !utf8.Valid(buf) {
				return "", errors.New("input is not valid UTF-8")
			}
			return string(buf), nil
		case 8, 127: // Backspace removes one UTF-8 rune.
			if len(buf) > 0 {
				_, n := utf8.DecodeLastRune(buf)
				clear(buf[len(buf)-n:])
				buf = buf[:len(buf)-n]
			}
		case 21: // Ctrl-U clears the entire line.
			clear(buf)
			buf = buf[:0]
		default:
			if b >= 32 || b == '\t' {
				appendByte(b)
			}
		}
	}
}

func (t *terminal) ask(label string) (string, error) {
	fmt.Fprint(t.out, bold+"  "+label+" (hidden input) › "+reset)
	return t.readLine()
}
func (t *terminal) secret(label string) (string, error) { return t.ask(label) }
