package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/williampuk/shard-vault/internal/share"
	"golang.org/x/sys/unix"
)

func inputTerminal(s string) *terminal {
	return &terminal{in: bufio.NewReader(strings.NewReader(s)), out: io.Discard}
}
func TestRawInput(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"plain", "hello\r", "hello"},
		{"spaces", "  pass phrase  \r", "  pass phrase  "},
		{"backspace unicode", "pass🔐\x7f!\r", "pass!"},
		{"clear", "discard\x15new\r", "new"},
		{"bracketed paste", "\x1b[200~abc\ndef\x1b[201~\r", "abc\ndef"},
		{"arrows ignored", "a\x1b[Db\r", "ab"},
		{"long passphrase", strings.Repeat("🔐", 128) + "\r", strings.Repeat("🔐", 128)},
		{"boundary", strings.Repeat("x", maxInputBytes) + "\r", strings.Repeat("x", maxInputBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			term := inputTerminal(tc.input)
			term.out = &out
			got, err := term.readLine()
			if err != nil || got != tc.want {
				t.Fatalf("input mismatch: %v", err)
			}
			if out.String() != "\n" {
				t.Fatal("input was echoed")
			}
		})
	}
	for _, s := range []string{"x\x03", "\x1b\x03", "x\x04"} {
		if _, err := inputTerminal(s).readLine(); !errors.Is(err, errInterrupted) {
			t.Fatalf("interrupt: %v", err)
		}
	}
	term := inputTerminal("one\r\ntwo\n")
	a, _ := term.readLine()
	b, _ := term.readLine()
	if a != "one" || b != "two" {
		t.Fatal("CRLF leaked into next prompt")
	}
	if _, err := inputTerminal("incomplete").readLine(); !errors.Is(err, io.EOF) {
		t.Fatal("partial EOF accepted")
	}
	if _, err := inputTerminal("\xff\r").readLine(); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	term = inputTerminal(strings.Repeat("x", maxInputBytes+100) + "\rnext\r")
	if _, err := term.readLine(); !errors.Is(err, errInputTooLong) {
		t.Fatal("oversize accepted")
	}
	if got, err := term.readLine(); err != nil || got != "next" {
		t.Fatal("overflow spilled into next prompt")
	}
}
func TestTokenPagination(t *testing.T) {
	token := strings.Repeat("A", share.MaxTokenBytes)
	for _, size := range [][2]int{{80, 24}, {40, 20}, {120, 40}, {1, 1}} {
		_, pages := tokenPage(token, size[0], size[1], 0)
		var joined string
		for page := 0; page < pages; page++ {
			lines, _ := tokenPage(token, size[0], size[1], page)
			if len(lines) > max(1, size[1]-16) {
				t.Fatal("too many rows")
			}
			for _, line := range lines {
				if len(line) > max(1, size[0]-4) {
					t.Fatal("too wide")
				}
				joined += line
			}
		}
		if joined != token {
			t.Fatal("lost token bytes")
		}
	}
}
func TestSafeErrors(t *testing.T) {
	text := safeError(errors.New("bad\x1b[2J\n\u202e"))
	if strings.ContainsAny(text, "\x1b\n\u202e") {
		t.Fatal("terminal controls not escaped")
	}
}
func TestShareFiles(t *testing.T) {
	shares, err := share.Generate(share.Backup{Entropy: make([]byte, 16)}, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer share.Clear(shares)
	dir := t.TempDir()
	path := filepath.Join(dir, "one.txt")
	if err := saveShare(path, shares[0]); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("bad permissions")
	}
	data, err := readShareFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := share.Parse(string(data))
	if err != nil || !bytes.Equal(parsed.Value, shares[0].Value) {
		t.Fatal("file round trip")
	}
	original := append([]byte(nil), data...)
	if err := saveShare(path, shares[1]); err == nil {
		t.Fatal("overwrote existing file")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("changed existing file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := saveShare(link, shares[1]); err == nil {
		t.Fatal("followed export symlink")
	}
	if _, err := readShareFile(link); err == nil {
		t.Fatal("followed import symlink")
	}
	if _, err := readShareFile(dir); err == nil {
		t.Fatal("read directory")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readShareFile(fifo); err == nil {
		t.Fatal("read FIFO")
	}
	huge := filepath.Join(dir, "huge")
	if err := os.WriteFile(huge, bytes.Repeat([]byte{'A'}, share.MaxTokenBytes+3), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readShareFile(huge); err == nil {
		t.Fatal("read oversized file")
	}
	public := filepath.Join(dir, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0777); err != nil {
		t.Fatal(err)
	}
	if err := saveShare(filepath.Join(public, "no.txt"), shares[0]); err == nil {
		t.Fatal("accepted writable directory")
	}
	set := filepath.Join(dir, "set")
	if err := saveAll(set, shares); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(set)
	if info.Mode().Perm() != 0700 {
		t.Fatal("bad folder permissions")
	}
	if err := saveAll(set, shares); err == nil {
		t.Fatal("reused staging directory")
	}
	if err := saveAll(filepath.Join(dir, "partial"), shares[:2]); err == nil {
		t.Fatal("exported incomplete set")
	}
	if err := saveShare(filepath.Join(dir, "invalid"), share.Share{}); err == nil {
		t.Fatal("exported invalid share")
	}
	if _, err := os.Stat(filepath.Join(dir, "invalid")); !os.IsNotExist(err) {
		t.Fatal("invalid share created file")
	}
	if err := saveShare(filepath.Join(dir, "missing", "one.txt"), shares[0]); err == nil {
		t.Fatal("created implicit parent")
	}
}
