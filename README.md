# ShardVault

**ShardVault** is a local Go terminal application for backing up BIP-39 wallet recovery material with Shamir’s Secret Sharing. The CLI executable is `shardvault`.

Back up a **12- or 24-word English BIP-39 mnemonic**, optionally with its BIP-39 passphrase, as 2–16 Shamir shares. Any `m` distinct shares from an `m`-of-`n` set recover the original material. The app supports individual file export, all-share backup verification, and recovery.

**Reviewed revision, 2026-10-13.** See [REVIEW.md](REVIEW.md) for findings, fixes, test evidence, and remaining limitations. This remains a custom, educational implementation—not professionally audited wallet software. Test with disposable wallet material before considering real use.

## Build and run

Requirements: **Go 1.26 or newer**, Linux or macOS, and a trusted interactive terminal. Use a window of at least **80 columns × 24 rows**. Python 3 is needed only for integration tests, not for the application.

Dependencies, their licenses, and `go.sum` are included. A local Go installation can build and test without downloading modules:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -mod=vendor ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -mod=vendor -buildvcs=false -trimpath -o shardvault ./cmd/shardvault
./shardvault
```

Or use `make build`, `make test`, and `make integration`. The compiled application makes no network requests. The offline environment variables prevent module/toolchain downloads during the commands above; they do not sandbox the application or the operating system.

The app refuses pipelines and non-terminal devices. It accepts no wallet secrets through command-line flags or environment variables. `stty` is no longer required.

## Input and display

- **All input is hidden**, including menu choices and file paths. Press Enter to submit. Backspace removes a character; Ctrl-U clears the line; Ctrl-C or Ctrl-D exits.
- Bracketed paste is supported. Pasted content is held as one input; press Enter after pasting. Avoid pasting multiple separate answers at once. Terminals without bracketed-paste support cannot reliably distinguish pasted newlines from submitted answers.
- Secrets are handled in raw terminal mode so kernel canonical-line limits do not silently truncate them. Inputs above 16 KiB cancel the session after the line is consumed.
- Exact prior terminal settings are restored on normal exit, input cancellation, SIGINT, SIGTERM, SIGHUP, and SIGTSTP. External suspension requests terminate the app. SIGKILL, power loss, or a terminal-driver failure cannot be cleaned up; run `reset` or `stty sane` if necessary.
- An alternate screen limits ordinary scrollback exposure. It does not prevent screen recording, clipboard capture, remote-terminal logging, or a compromised OS.

## Generate and verify a backup

1. Choose **1**. Enter the complete 12- or 24-word English mnemonic. The app checks the word list and BIP-39 checksum. Errors identify the position of an invalid word without printing the word.
2. Choose whether to include the BIP-39 passphrase. The default is **No**. If included, enter it twice. Generation accepts printable UTF-8 text, including spaces, up to **512 bytes**; control characters are refused. Leading/trailing spaces, case, and Unicode bytes are preserved. The app does not normalize the passphrase or derive a wallet seed.
3. Set total shares `n` and recovery threshold `m`, with `2 <= m <= n <= 16`.
4. The app reconstructs the generated set and compares it against your original entropy and passphrase before displaying any shares.
5. View **one share at a time**. Use `n`/`p` for the next/previous share, and `]`/`[` for long-token pages. Page breaks are display formatting, not token contents. File export is preferable to manually joining token pages.
6. Export:
   - `s`: save one chosen share to a new file. Its parent directory must already exist and must not be group/other-writable.
   - `a`: export all shares to a new private directory after typing `EXPORT ALL`. This creates a complete, recoverable secret in one place; use it only for temporary staging and separate the shares afterward.
7. Choose **v**. Supply **all `n` shares**, in any order, from their actual storage destinations. Paste a complete token or enter `@/path/to/share.txt`. Every value must exactly match its generated share, and all points must form a consistent reconstructable set.
8. An unverified session requires `DISCARD` before a normal return to the main menu. Ctrl-C remains an emergency exit. Verification cannot prove that you used independent media; the software can only check the supplied bytes.
9. Perform a cold recovery drill: restart, choose recovery, and use any `m` independently stored shares. Separately verify a known wallet address or fingerprint with trusted wallet software.

A valid **test-only** mnemonic is `abandon` repeated 11 times followed by `about`. Never use public test vectors for funds.

## Recovery

1. Choose **2** and enter the first share token or `@file`. The app shows its declared set ID and threshold.
2. Provide `m−1` additional, distinct shares from the same set.
3. The app interpolates the protected payload, checks its internal SHA-256 digest, and reconstructs the original mnemonic. The library additionally checks consistency of surplus shares if more than `m` are provided.
4. Type **REVEAL** to display the mnemonic. A backed-up passphrase is shown on a separate paginated screen.
5. Passphrases are shown as **Go-quoted ASCII text**, so control characters, non-ASCII characters, quotes, and backslashes cannot manipulate the terminal. Remove the two-space display indentation and display-only line breaks, join pages, remove the outer quotes, and decode escapes: `\t` is a tab, `\u00e9` is `é`, and `\\` is a single backslash. Do not enter the escaped representation literally into a wallet. Recovery supports all valid legacy payload passphrases, including control characters that the revised generation UI refuses.
6. If the backup excludes the passphrase, recovery cannot tell whether the wallet used one. You still need any separately stored passphrase.

Share files must be regular files. Symlinks, pipes, devices, directories, oversized files, malformed tokens, duplicate indices, inconsistent points, and mixed sets are rejected.

## The “13th/25th word”

BIP-39 defines a separate optional **passphrase**, rather than an extra mnemonic word. Every passphrase produces a wallet seed; there is no checksum that identifies the intended passphrase. Confirmation only detects differing entries, not a consistently mistyped passphrase.

This app shares the **original 16/32-byte entropy**, plus the passphrase when selected. It does not share the 64-byte derived seed. A conforming wallet applies BIP-39's NFKD normalization during seed derivation; this backup program preserves the entered bytes for exact recovery.

Including the passphrase means **any `m` shares reveal both factors**. Excluding it means losing the separately held passphrase can still make the wallet inaccessible.

## Compatibility and security limits

- **The format is unchanged: `B39SSS1:`.** Valid backups generated by the original version remain recoverable. These are custom base64url tokens, **not SLIP-39 mnemonic shares**, and cannot be entered into hardware wallets as SLIP-39 backups. Keep this source and [FORMAT.md](docs/FORMAT.md) for future recovery.
- Independent CSPRNG coefficients are sampled uniformly from GF(256), including zero. Given fewer than `m` correctly generated shares, the payload bytes are hidden; public metadata and payload length remain visible. The length can reveal or constrain mnemonic/passphrase lengths. There is no fixed-size padding.
- The wrapper and payload use **unkeyed checksums**, not signatures or MACs. They detect accidental damage and most inconsistent recovery attempts; they do not establish who created a backup or that it is your wallet. Metadata is not cryptographically bound into the inner payload. An attacker can relabel a complete set's ID/total, and an attacker who replaces the entire set can substitute a valid different wallet. Compare wallet identity separately and keep custody of original shares.
- Export opens a new file exclusively, enforces/checks `0600` **before writing**, syncs the file and destination directory, and does not overwrite an existing target or final symlink. Directory handles anchor writes. Use trusted, existing parent paths. Mode checks are OS-level checks, not proof that removable media is encrypted or inaccessible on another machine. Filesystems that cannot enforce the requested permissions are refused.
- An export error can leave a private partial staging set or a fully written file whose directory sync failed. Errors explicitly report this. No claim of secure deletion is made.
- Go strings, buffered readers, library internals, swap, core dumps, SSD history, and clipboard contents cannot be reliably erased by this application. Mutable buffers are cleared on a best-effort basis. File permissions do not protect against the account owner, administrators, malware, or physical access to unencrypted media.
- The project does not implement wallet transactions, seed derivation, encrypted share files, automatic error correction, QR codes, hardware-wallet integration, or threshold changes. Generate a fresh independent set to change a threshold; never mix sets.

## Verification

Completed on Linux amd64 using **Go 1.27.2**, with the real dependencies:

- Complete tests, race detector, `go vet`, and module checksum verification.
- Offline vendored build and tests.
- All 16 applicable official English BIP-39 vectors and exhaustive GF(256) multiplication checks.
- Every supported `m,n` policy, rotating share selections, corruption/mixing/duplicate rejection, and independent Python-created format fixtures.
- Three real-PTY generation/export/verification/recovery workflows, including 24 words with a 512-byte passphrase and Unicode with significant spaces.
- Terminal restoration, cancellation/signals, oversized input, non-TTY rejection, file permissions, no-overwrite behavior, symlink/FIFO rejection, and token pagination.
- Three 15-second fuzz runs: parser, inner payload, and recovery; over 780,000 aggregate executions with no failure.
- Cross-compilation for Linux arm64 and macOS amd64/arm64. **macOS runtime behavior has not been exercised here.**

`govulncheck` found no affected imported packages or reachable functions. It reported module advisory GO-2026-5932 for unused `golang.org/x/crypto/openpgp`; the app does not import that package. This is a snapshot check, not a promise about future advisories.

The report explains these checks and their limits. Testing and this review do not replace a specialist cryptographic audit.

## Layout

```text
cmd/shardvault/       Interactive application, raw input, file operations
internal/backup/          BIP-39 entropy/mnemonic conversion and official vectors
internal/shamir/          GF(256) sharing and interpolation
internal/share/           Versioned tokens, protected payload, recovery checks
tests/                    Public-data Python oracle and real-PTY integration tests
docs/FORMAT.md            Full compatible v1 format specification
REVIEW.md                 Findings and verification evidence
vendor/                   Pinned dependencies and their licenses
```

References: [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [reference vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json), [SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md), [Go terminal package](https://pkg.go.dev/golang.org/x/term), [Cosmos BIP-39 encoder](https://github.com/cosmos/go-bip39).
