package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/williampuk/shard-vault/internal/backup"
	"github.com/williampuk/shard-vault/internal/share"
)

const (
	reset = "\033[0m"
	cyan  = "\033[36m"
	gold  = "\033[33m"
	green = "\033[32m"
	red   = "\033[31m"
	bold  = "\033[1m"
)

func main() {
	t, cleanup, err := openTerminal()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer cleanup()
	err = t.run()
	cleanup()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, errInterrupted) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (t *terminal) run() error {
	for {
		t.screen("ShardVault · BIP-39 SHAMIR BACKUP")
		fmt.Fprintln(t.out, "  (1) Generate m-of-n shares from a BIP-39 mnemonic")
		fmt.Fprintln(t.out, "  (2) Recover a mnemonic from m shares")
		fmt.Fprintln(t.out, "  (3) Safety and compatibility information")
		fmt.Fprintln(t.out, "  (q) Quit")
		fmt.Fprintln(t.out, "  All input is hidden. Enter submits; Ctrl-U clears; Ctrl-C exits.")
		s, err := t.ask("Choose")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "1":
			err = t.generate()
		case "2":
			err = t.recover()
		case "3":
			err = t.help()
		case "q", "quit", "exit":
			return nil
		default:
			continue
		}
		if err != nil {
			if fatalInput(err) {
				return err
			}
			fmt.Fprintln(t.out, red+"\n  "+safeError(err)+reset)
			if _, err := t.ask("Enter to return to the main menu"); err != nil {
				return err
			}
		}
	}
}

// Quote control characters in filesystem errors and other untrusted text.
func safeError(err error) string {
	s := strconv.QuoteToASCII(err.Error())
	return s[1 : len(s)-1]
}

func (t *terminal) screen(title string) {
	fmt.Fprint(t.out, "\033[2J\033[H")
	fmt.Fprintln(t.out, cyan+bold+"╔══════════════════════════════════════════════════════════════════╗"+reset)
	fmt.Fprintf(t.out, cyan+bold+"  %s"+reset+"\n", title)
	fmt.Fprintln(t.out, cyan+"╚══════════════════════════════════════════════════════════════════╝"+reset)
	fmt.Fprintln(t.out, gold+"  Local-only • No network calls at runtime • Custom format: NOT SLIP-39"+reset)
	fmt.Fprintln(t.out)
}

func (t *terminal) choice(label string) (bool, error) {
	for {
		s, err := t.ask(label + " [y/N]")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		default:
			fmt.Fprintln(t.out, "  Enter y or n.")
		}
	}
}

func (t *terminal) askInt(label string, low, high int) (int, error) {
	for {
		s, err := t.ask(fmt.Sprintf("%s (%d..%d)", label, low, high))
		if err != nil {
			return 0, err
		}
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err == nil && v >= low && v <= high {
			return v, nil
		}
		fmt.Fprintln(t.out, "  Invalid number. Try again.")
	}
}

func (t *terminal) generate() error {
	t.screen("GENERATION · 1 / 3 · INPUT")
	fmt.Fprintln(t.out, "  Enter all 12 or 24 words on one line. English BIP-39 only.")
	fmt.Fprintln(t.out, "  Terminal echo is disabled while you type; paste only in a trusted terminal.")
	sentence, err := t.secret("BIP-39 mnemonic")
	if err != nil {
		return err
	}
	entropy, err := backup.Decode(sentence)
	sentence = "" // strings may remain in Go heap; see README security limits
	if err != nil {
		return err
	}
	defer clear(entropy)
	fmt.Fprintln(t.out, green+"  Mnemonic word list and checksum: valid."+reset)
	fmt.Fprintln(t.out, "\n  BIP-39's '13th/25th word' is a separate PASS PHRASE, not a mnemonic word.")
	fmt.Fprintln(t.out, "  Usually keep it separate. Including it means m shares reveal BOTH factors.")
	include, err := t.choice("Include the BIP-39 passphrase in the shares?")
	if err != nil {
		return err
	}
	passphrase := ""
	if include {
		a, err := t.secret("BIP-39 passphrase (exact spelling/case/spaces)")
		if err != nil {
			return err
		}
		b, err := t.secret("Repeat passphrase")
		if err != nil {
			return err
		}
		if len(a) > share.MaxPassphraseBytes || !utf8.ValidString(a) || strings.IndexFunc(a, unicode.IsControl) >= 0 {
			return errors.New("passphrase must be printable UTF-8 text, at most 512 bytes (no control characters)")
		}
		if a == "" {
			return errors.New("empty passphrase: choose not to include it instead")
		}
		if subtle.ConstantTimeCompare([]byte(a), []byte(b)) != 1 {
			return errors.New("passphrase confirmation did not match")
		}
		passphrase = a
		a, b = "", ""
	}
	t.screen("GENERATION · 2 / 3 · THRESHOLD")
	fmt.Fprintln(t.out, "  Example: 3-of-5 → store 5 independent shares, any 3 restore the backup.")
	fmt.Fprintln(t.out, "  You can choose 2..16 total shares; minimum threshold is 2.")
	total, err := t.askInt("Number of shares (n)", 2, 16)
	if err != nil {
		return err
	}
	threshold, err := t.askInt("Shares required to recover (m)", 2, total)
	if err != nil {
		return err
	}
	inputBackup := share.Backup{Entropy: entropy, Passphrase: passphrase, IncludesPassphrase: include}
	originals, err := share.Generate(inputBackup, threshold, total)
	if err != nil {
		return err
	}
	defer share.Clear(originals)
	if err := share.VerifyBackup(inputBackup, originals); err != nil {
		return fmt.Errorf("generation self-check failed: %w", err)
	}
	passphrase, inputBackup.Passphrase = "", ""
	verified := false
	selected, page := 0, 0
    showingWords := false
	for {
		width, height, sizeErr := term.GetSize(int(os.Stdout.Fd()))
		if sizeErr != nil {
			width, height = 80, 24
		}
		if width < 80 || height < 24 {
			fmt.Fprint(t.out, "\033[2J\033[HResize to at least 80 columns by 24 rows.\n")
			if _, err := t.ask("Enter to redraw"); err != nil {
				return err
			}
			continue
		}
		t.screen("GENERATION · 3 / 3 · YOUR SHARES")
		fmt.Fprintf(t.out, "  Backup ID: %x     Policy: %d of %d     Passphrase included: %t\n", originals[0].ID, threshold, total, include)
		if verified {
			fmt.Fprintln(t.out, green+"  Backup verification: PASSED (all n supplied shares matched)."+reset)
		} else {
			fmt.Fprintln(t.out, gold+"  Backup verification: NOT YET PERFORMED."+reset)
		}
		fmt.Fprintln(t.out, "  Sensitive: keep shares on separate media. Tokens are shown in pages.")
        var lines []string
        var pages int
        if showingWords {
            words, err := originals[selected].Words()
            if err != nil {
                return err
            }
            lines, pages = wordPage(words, height, page)
        } else {
            token, err := originals[selected].Token()
            if err != nil {
                return err
            }
            lines, pages = tokenPage(token, width, height, page)
        }
        if page >= pages {
            page = pages-1
            if showingWords {
                words, err := originals[selected].Words()
                if err != nil {
                    return err
                }
                lines, pages = wordPage(words, height, page)
            } else {
                token, err := originals[selected].Token()
                if err != nil {
                    return err
                }
                lines, pages = tokenPage(token, width, height, page)
            }
        }
        representation := "B39SSS1: token"
        if showingWords {
            representation = "B39WORDS1: English words"
        }
        fmt.Fprintf(t.out, "  SHARE %d/%d · %s · page %d/%d\n", selected+1, total, representation, page+1, pages)
        for _, line := range lines {
            fmt.Fprintln(t.out, "  "+line)
        }
        fmt.Fprintln(t.out, "  n/p: share · ]/[: page · t: toggle Base64 / English words")
        fmt.Fprintln(t.out, "  s: save token · w: save words · a: export all tokens")
        fmt.Fprintln(t.out, "  e: export all words · v: verify all · q: quit")
		command, err := t.ask("Choose")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(command)) {
		case "n":
			selected = (selected + 1) % total
			page = 0
		case "p":
			selected = (selected + total - 1) % total
			page = 0
		case "]":
			if page+1 < pages {
				page++
			}
		case "[":
			if page > 0 {
				page--
			}
		case "q":
			if !verified {
				answer, err := t.ask("Backup NOT verified. Type DISCARD to leave without checking all shares")
				if err != nil {
					return err
				}
				if answer != "DISCARD" {
					continue
				}
			}
			return nil
        case "t":
            showingWords = !showingWords
            page = 0
        case "s", "w":
            i, err := t.askInt("Share index to save", 1, total)
			if err != nil {
				return err
			}
			path, err := t.ask("Absolute or relative new file path (will not overwrite)")
			if err != nil {
				return err
			}
            var saveErr error
            if strings.ToLower(strings.TrimSpace(command)) == "w" {
                saveErr = saveWords(strings.TrimSpace(path), originals[i-1])
            } else {
                saveErr = saveShare(strings.TrimSpace(path), originals[i-1])
            }
            if saveErr != nil {
                fmt.Fprintln(t.out, red+"  Export failed: "+safeError(saveErr)+reset)
            } else {
                fmt.Fprintln(t.out, green+"  Share saved with restrictive permissions."+reset)
            }
			if _, err := t.ask("Enter to continue"); err != nil {
				return err
			}
		case "a", "e":
			fmt.Fprintln(t.out, red+"  WARNING: Storing the entire share set together defeats physical separation!"+reset)
			confirm, err := t.ask("Type EXPORT ALL to create a staging folder")
			if err != nil {
				return err
			}
			if confirm != "EXPORT ALL" {
				continue
			}
			folder, err := t.ask("Name of NEW private folder")
			if err != nil {
				return err
			}
            var exportErr error
            if strings.ToLower(strings.TrimSpace(command)) == "e" {
                exportErr = saveAllWords(strings.TrimSpace(folder), originals)
            } else {
                exportErr = saveAll(strings.TrimSpace(folder), originals)
            }
            if exportErr != nil {
                fmt.Fprintln(t.out, red+"  Export failed: "+safeError(exportErr)+reset)
            } else {
                fmt.Fprintln(t.out, green+"  Export complete. Move shares to independent media; DO NOT retain an entire set together."+reset)
            }
			if _, err := t.ask("Enter to continue"); err != nil {
				return err
			}
		case "v":
			verified = false
			if err := t.validateAll(originals); err != nil {
				if fatalInput(err) {
					return err
				}
				fmt.Fprintln(t.out, red+"  Validation failed: "+safeError(err)+reset)
			} else {
				verified = true
				fmt.Fprintln(t.out, green+"  SUCCESS: all n saved/pasted shares exactly match; m-of-n reconstruction works."+reset)
			}
			if _, err := t.ask("Enter to continue"); err != nil {
				return err
			}
		}
	}
}

// Input method is either a paste of the entire B39SSS1: token, or @/path/file.
func (t *terminal) readShare(prompt string) (share.Share, error) {
	var empty share.Share
	for {
		s, err := t.secret(prompt + " (paste token or @file; q cancels)")
		if err != nil {
			return empty, err
		}
		s = strings.TrimSpace(s)
		if s == "q" {
			return empty, errors.New("cancelled")
		}
		if strings.HasPrefix(s, "@") {
			path := strings.TrimPrefix(s, "@")
			data, err := readShareFile(path)
			if err != nil {
				fmt.Fprintln(t.out, red+"  Cannot read share: "+safeError(err)+reset)
				continue
			}
			s = string(data)
			clear(data)
		}
		parsed, err := share.ParseInput(s)
		if err != nil {
			fmt.Fprintln(t.out, red+"  Invalid share: "+safeError(err)+reset)
			continue
		}
		return parsed, nil
	}
}

func (t *terminal) validateAll(originals []share.Share) error {
	t.screen("VERIFY BACKUP · ALL n SHARES")
	fmt.Fprintf(t.out, "  Read the %d shares from their ACTUAL saved destinations, in any order.\n", len(originals))
	fmt.Fprintln(t.out, "  This is a transcription/export check, plus cryptographic reconstruction.")
	fmt.Fprintln(t.out, "  Do not just paste the originals shown in memory if you intend to test files.")
	received := make([]share.Share, 0, len(originals))
	defer func() { share.Clear(received) }()
	used := map[byte]bool{}
	for len(received) < len(originals) {
		sh, err := t.readShare(fmt.Sprintf("Verified %d/%d", len(received), len(originals)))
		if err != nil {
			return err
		}
		if used[sh.Index] {
			clear(sh.Value)
			fmt.Fprintln(t.out, red+"  That share index was already provided."+reset)
			continue
		}
		if sh.ID != originals[0].ID || sh.Total != originals[0].Total || sh.Threshold != originals[0].Threshold {
			clear(sh.Value)
			fmt.Fprintln(t.out, red+"  Share belongs to a different backup set or threshold."+reset)
			continue
		}
		// Fail fast for a bad share rather than asking for the rest unnecessarily.
		if subtle.ConstantTimeCompare(sh.Value, originals[int(sh.Index)-1].Value) != 1 {
			clear(sh.Value)
			fmt.Fprintln(t.out, red+"  This share does not match the generated share; check your backup."+reset)
			continue
		}
		used[sh.Index] = true
		received = append(received, sh)
		fmt.Fprintf(t.out, green+"  Share %d is an exact match.\n"+reset, sh.Index)
	}
	return share.VerifyAll(originals, received)
}

func (t *terminal) recover() error {
	t.screen("RECOVERY · COLLECT SHARES")
	fmt.Fprintln(t.out, "  Collect ANY m DISTINCT shares from the SAME backup set.")
	fmt.Fprintln(t.out, "  Accepts B39SSS1: tokens or B39WORDS1: English shares; NOT SLIP-39.")
	first, err := t.readShare("Share 1")
	if err != nil {
		return err
	}
	received := []share.Share{first}
	defer func() { share.Clear(received) }()
	fmt.Fprintf(t.out, "\n  Set ID: %x     Threshold: %d of %d\n", first.ID, first.Threshold, first.Total)
	used := map[byte]bool{first.Index: true}
	for len(received) < int(first.Threshold) {
		sh, err := t.readShare(fmt.Sprintf("Share %d/%d", len(received)+1, first.Threshold))
		if err != nil {
			return err
		}
		if sh.ID != first.ID || sh.Threshold != first.Threshold || sh.Total != first.Total || len(sh.Value) != len(first.Value) {
			clear(sh.Value)
			fmt.Fprintln(t.out, red+"  Different backup set or incompatible share parameters; try again."+reset)
			continue
		}
		if used[sh.Index] {
			clear(sh.Value)
			fmt.Fprintln(t.out, red+"  Duplicate share index; enter another one."+reset)
			continue
		}
		used[sh.Index] = true
		received = append(received, sh)
	}
	restored, err := share.Recover(received)
	if err != nil {
		return err
	}
	defer clear(restored.Entropy)
	mnemonic, err := backup.Encode(restored.Entropy)
	if err != nil {
		return fmt.Errorf("BIP-39 mnemonic regeneration failed: %w", err)
	}
	t.screen("RECOVERY · SUCCESS")
	fmt.Fprintf(t.out, green+"  Successfully reconstructed %d-word BIP-39 mnemonic.\n"+reset, len(strings.Fields(mnemonic)))
	if restored.IncludesPassphrase {
		fmt.Fprintln(t.out, "  This backup ALSO contains the original BIP-39 passphrase.")
	} else {
		fmt.Fprintln(t.out, gold+"  No BIP-39 passphrase was included in this backup."+reset)
	}
	fmt.Fprintln(t.out, "\n  Your secrets are hidden until explicitly revealed.")
	confirm, err := t.ask("Type REVEAL to show them on-screen")
	if err != nil {
		return err
	}
	if confirm != "REVEAL" {
		return nil
	}
	defer t.screen("WALLET MATERIAL HIDDEN")
	t.screen("RECOVERED WALLET MATERIAL · PRIVATE")
	fmt.Fprintln(t.out, red+"  Warning: screen capture, terminal logging, and observers can steal secrets."+reset)
	fmt.Fprintln(t.out, "\n  BIP-39 mnemonic:")
	words := strings.Fields(mnemonic)
	for i, w := range words {
		fmt.Fprintf(t.out, "  %2d. %-14s", i+1, w)
		if i%3 == 2 {
			fmt.Fprintln(t.out)
		}
	}
	if len(words)%3 != 0 {
		fmt.Fprintln(t.out)
	}
	if restored.IncludesPassphrase {
		if _, err := t.ask("Enter to view the included passphrase on a separate screen"); err != nil {
			return err
		}
		quoted := strconv.QuoteToASCII(restored.Passphrase)
		page := 0
		for {
			t.screen("RECOVERED BIP-39 PASSPHRASE · PRIVATE")
			width, height, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				width, height = 80, 24
			}
			lines, pages := tokenPage(quoted, width, height, page)
			page = min(page, pages-1)
			fmt.Fprintf(t.out, "  Exact UTF-8 length: %d bytes · page %d/%d\n", len(restored.Passphrase), page+1, pages)
			for _, line := range lines {
				fmt.Fprintln(t.out, "  "+line)
			}
			fmt.Fprintln(t.out, "  Go-quoted text: join pages, remove outer quotes, decode escapes.")
			fmt.Fprintln(t.out, "  Example: \\t means a tab; \\u00e9 means é. Spaces and case matter.")
			command, err := t.ask("n/p: next/previous page · Enter: erase and finish")
			if err != nil {
				return err
			}
			if command == "n" {
				page = min(page+1, pages-1)
				continue
			}
			if command == "p" {
				page = max(0, page-1)
				continue
			}
			if command == "" {
				break
			}
		}
	} else {
		fmt.Fprintln(t.out, "\n  BIP-39 passphrase: NOT PRESENT in this share set.")
		fmt.Fprintln(t.out, "  If the wallet used a separate passphrase, you MUST still supply it.")
		if _, err = t.ask("Enter to erase the display and return to the menu"); err != nil {
			return err
		}
	}
	return err
}

func (t *terminal) help() error {
	t.screen("SECURITY / FORMATS / RECOVERY")
	fmt.Fprintln(t.out, "  • A 12-word BIP-39 mnemonic encodes 128 bits of entropy; 24 encodes 256.")
	fmt.Fprintln(t.out, "  • '13th'/'25th word' refers informally to a separate BIP-39 passphrase.")
	fmt.Fprintln(t.out, "  • Shamir splits the original entropy, and optionally the passphrase.")
	fmt.Fprintln(t.out, "  • If included, ANY m shares disclose both mnemonic and passphrase.")
	fmt.Fprintln(t.out, "  • A single share (or fewer than m) is insufficient to reconstruct.")
	fmt.Fprintln(t.out, "  • Toggle B39SSS1: tokens / B39WORDS1: words using t.")
    fmt.Fprintln(t.out, "  • Neither custom format is SLIP-39 / AirGap-compatible.")
	fmt.Fprintln(t.out, "  • Restore requires this software or a compatible B39SSS1 decoder.")
	fmt.Fprintln(t.out, "  • Test your backup using independently stored shares and a disposable wallet.")
	fmt.Fprintln(t.out, "  • Never enter real wallet words on an internet-exposed or compromised PC.")
	fmt.Fprintln(t.out, "  • Your machine/terminal can capture keys; Go does not guarantee RAM wiping.")
	fmt.Fprintln(t.out, "  • Keep each share offline in different physical locations/holders.")
	fmt.Fprintln(t.out, "  • Do not upload shares to cloud storage or send them to chat/email.")
	fmt.Fprintln(t.out, "  • Reviewed and tested, but NOT a professional security audit. See REVIEW.md.")
	_, err := t.ask("Enter to return")
	return err
}

// Reserve screen space for the menu; paginate even a maximum-length token.
// wordPage breaks on whole dictionary words so no screen line splits a word.
// The prefix is shown on every page and must be retained when transcribing.
func wordPage(input string, height, page int) ([]string, int) {
    parts := strings.Fields(input)
    if len(parts) < 2 {
        return []string{"Invalid word share"}, 1
    }
    const perLine = 6 // BIP-39 English words are short; fits an 80-column terminal.
    rows := max(1, height-17)
    wordsPerPage := perLine*rows
    words := parts[1:]
    pages := max(1, (len(words)+wordsPerPage-1)/wordsPerPage)
    page = min(max(page, 0), pages-1)
    start := page*wordsPerPage
    end := min(start+wordsPerPage, len(words))
    lines := []string{parts[0]}
    for i := start; i < end; i += perLine {
        lines = append(lines, strings.Join(words[i:min(i+perLine, end)], " "))
    }
    return lines, pages
}

func tokenPage(token string, width, height, page int) ([]string, int) {
	columns, rows := max(1, width-4), max(1, height-16)
	size := columns * rows
	pages := max(1, (len(token)+size-1)/size)
	page = min(max(0, page), pages-1)
	end := min(len(token), (page+1)*size)
	var lines []string
	for at := page * size; at < end; at += columns {
		lines = append(lines, token[at:min(end, at+columns)])
	}
	return lines, pages
}
