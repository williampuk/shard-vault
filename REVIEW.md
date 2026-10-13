# ShardVault implementation review and fixes

**Reviewed: 2026-10-13.** Scope: the pre-ShardVault source in the original `bip39-share-tui-source.zip`, including cryptography, serialization, BIP-39 conversion, secret input/output, file handling, documentation, dependencies, and tests.

The original implementation builds and its original tests pass against the real `github.com/cosmos/go-bip39` dependency. A fresh source review found defects that those tests did not cover. They are addressed in this revision. No flaw was found in the core GF(256) multiplication, interpolation, or uniform CSPRNG coefficient sampling. That finding is bounded by the review and tests below; it is not a proof of security or a professional third-party audit.

## Findings and remedies

Priorities describe impact in this application, not CVSS ratings.

| Priority | Finding in the original | Change and evidence |
|---|---|---|
| High, on permissive filesystems | `saveShare` wrote the token before checking whether file permissions were private. A successful `Chmod` did not establish that the requested mode was enforced. | Inspect the open file's type and exact `0600` mode before writing secret bytes. All-share directories are checked before creating share files. File permission and rejection tests added. Filesystem-emulated permissions remain a stated limitation. |
| Medium | `backup.Decode` included a mistyped secret word in its returned error, which the UI printed after accepting hidden input. | Return the word position only. A regression test and PTY test ensure a unique secret typo never appears in output. The regression was reproduced against the original source. |
| Medium | `VerifyAll` accepted an `m`-share subset if both arguments contained that subset—even though the declared set contained `n > m` shares. | Require exactly the declared total, validate expected entries, reject duplicates, compare every value, and reconstruct/check all points. The old implementation demonstrably accepted 2 of a declared 3. The original UI supplied all generated shares, so this was a library-contract defect rather than a demonstrated UI bypass. |
| Medium | “Verification” compared reconstructions of identical share data rather than checking generation against the user's original material. | Add `VerifyBackup`, and perform a generation self-check against the original entropy, passphrase, and inclusion flag. A negative test supplies different original entropy. External backup verification still compares every saved share. |
| Medium | Terminal cleanup ran `stty echo`, losing the original terminal configuration and using an external executable located through PATH. Device detection accepted any character device, including `/dev/null`. | Use `golang.org/x/term` for actual terminal detection and saved-state restoration. No `stty` subprocess. Restore on ordinary/error exits and handled signals; refuse non-TTY streams. PTY tests check exact state restoration, including a terminal whose echo was already off. |
| Medium | Input reading could stop at the 16 KiB limit without consuming the remainder; partial EOF input was accepted. Kernel canonical-mode limits could also precede the application limit. | One bounded raw-mode reader owns input for the whole session. Echo never becomes enabled between prompts. Drain the oversized line/paste before cancellation, reject incomplete EOF, validate UTF-8, support bracketed paste and basic editing, and test boundary behavior. |
| Medium | Recovery could block indefinitely opening a FIFO and could read devices or symlink targets as share files. | Nonblocking, no-follow open; inspect the opened descriptor; read only bounded regular files. Tests cover FIFO, symlink, directory, and oversized-file rejection. Remote/network-filesystem I/O can still block at the OS/filesystem layer; this app does not impose I/O deadlines. |
| Medium | Printing every share in an alternate screen could make earlier shares inaccessible; long tokens/passphrases also overflowed screens. | Display one selected share and page long tokens. Require a usable generation viewport. Reveal the passphrase separately with paging. Tests verify every token byte survives pagination and exercise real terminal navigation. |
| Medium | Passphrase display instructions said only to remove surrounding quotes, despite escaping backslashes and control characters. Following that instruction could restore a different passphrase. | Document Go escaping explicitly and render quoted ASCII safely. Generation UI accepts printable UTF-8 only; recovery retains exact legacy UTF-8 payload support, including controls. Unicode, composed/decomposed forms, quotes, backslashes, significant spaces, and maximum byte length are covered. |
| Medium, internal API | `Share.Token` serialized invalid structures and truncated lengths to uint16, so programmatic callers could create unrecoverable tokens. | `Token` now returns `(string, error)` and validates policy/index/payload bounds first. Parse and Recover enforce valid payload size. Existing valid serialized tokens are unchanged. |
| Low | Parsers accepted noncanonical embedded newlines because Go's base64 decoder ignores CR/LF even in strict mode; limits were much larger than the actual format. | Require one complete token line, bound before trimming/decoding, and derive bounds from the documented payload maximum. Malformed-wrapper tests recompute checksums to reach structural validation. |
| Low | Generated/read share buffers and several failed-path temporary buffers were not cleared. | Clear owned mutable buffers on success, cancellation, rejection, and error paths. Clear partially produced Shamir points on RNG failure. Random-source injection is now private to its package for tests. Go strings/buffered readers cannot be reliably wiped; this is best-effort hygiene. |
| Low | After one successful verification, a subsequent failed verification could leave the previous PASSED flag visible; unverified normal exit required no acknowledgement. | Reset the status before every attempt and require `DISCARD` for normal unverified exit. Emergency cancellation remains available. |
| Low | Export synced file contents but not the containing directory; it created parent directories implicitly and did not anchor later operations to an opened directory. | Require existing, non-group/other-writable parents; use `os.Root` directory handles; sync the file and directory. Exclusive creation remains. Report partial staging exports and unconfirmed durability explicitly. |
| Low | Filesystem error strings could contain terminal control sequences from filenames, and some prompt errors were ignored. | Escape untrusted error text, propagate input errors, and clear revealed material when recovery leaves through an error path. |
| Build/reviewability | No `go.sum`, no vendored dependencies, only a dependency-stub build in the original report, and minimal failure-case/terminal coverage. | Build against real dependencies, add checksum lock data and dependency sources/licenses, update pinned Go support packages, and add unit, independent-vector, fuzz, filesystem, and PTY coverage. Source-only archive can build offline with a local Go 1.26+ installation. |

## What the tests establish

The original tests first passed unchanged using the real dependency. Two targeted tests then failed against the original source, reproducing the incomplete-set verification and secret-in-error defects. The fixed tests pass in the revised source.

Crypto and format checks include:

- All **65,536 GF(256) multiplication pairs**, checked against an independently expressed polynomial-long-multiplication implementation; all 255 nonzero inverses; a literal known polynomial vector.
- Existing exhaustive subset tests for several policies, plus **every supported threshold/total pair** (2 through 16), with rotating selections that exercise every share position. This does not enumerate every subset of every policy.
- Explicit acceptance of zero polynomial coefficients, preserving unbiased sampling; rejecting a zero leading coefficient would change the distribution and is not an appropriate “fix.”
- All **16 applicable official English BIP-39 entropy/mnemonic vectors**, covering 12 and 24 words, with checksum/error tests.
- Two complete v1 token fixtures generated by the independent Python oracle, recovered in Go using all ten 3-of-5 subsets per fixture.
- Fresh, randomly generated Go shares recovered by the independent Python oracle during three real terminal workflows (all ten 3-of-5 subsets per workflow).
- Correct-checksum malformed payloads/wrappers, invalid thresholds/indices/lengths, duplicate/mixed sets, inconsistent surplus points, exact passphrase bytes, and 512-byte boundaries.

The test oracle is deliberately test-only and uses public disposable data. It is not a second supported production wallet recovery interface.

## Executed verification

Environment: **Linux amd64, Go 1.27.2**. No real wallet secrets were used.

| Check | Result |
|---|---|
| `go test -race -cover ./...` | Passed for all packages. Statement coverage: BIP-39 96.9%; Shamir 91.8%; share format 92.4%; main package 25.7%. Separate PTY workflows are not included in those Go coverage numbers. |
| `go vet ./...` | Passed. |
| `go mod verify` | All downloaded modules verified against checksum metadata. |
| Offline `-mod=vendor` build/test | Passed with module downloads disabled. |
| Parser fuzz, 15 seconds, 2 workers | Passed; 63,539 executions. |
| Payload fuzz, 15 seconds, 2 workers | Passed; 377,343 executions. |
| Recovery fuzz, 15 seconds, 2 workers | Passed; 343,225 executions. |
| Real PTY workflows | Passed: 24 words + 512-byte passphrase; 12 words without passphrase; 12 words + Unicode/quotes/backslash/significant spaces. Each includes export, all-share validation, and recovery. |
| Terminal lifecycle | Passed for normal exit, initially disabled echo, Ctrl-C, SIGTERM, SIGTSTP, overlong input, hidden-input errors, and non-TTY rejection. |
| Cross-builds | Linux arm64, macOS amd64, macOS arm64 passed. Linux amd64 was built and run. |
| `govulncheck` v1.9.0 | No affected imported packages or reachable functions. One module-level advisory for unused `x/crypto/openpgp`: GO-2026-5932, no available fixed version. OpenPGP is not imported or included by the application. |

Fuzzing is finite, not exhaustive. Native macOS execution, crash/power-loss testing, hostile/removable filesystems, independent hardware-wallet verification, and specialist cryptanalysis were **not** performed. Permission enforcement before writing is enforced by control flow and ordinary-filesystem checks; an actual filesystem that lies about its permissions was not emulated.

Reproduce locally:

```bash
make test
make vet
make integration
make fuzz
# Optional online, current vulnerability database:
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -show verbose ./...
```

## Project naming

The reviewed application is now **ShardVault**, with executable and command directory `shardvault`, and Go module `github.com/williampuk/shard-vault`. Naming does not change the backup serialization.

## Compatibility and remaining design limits

**No serialization version changed.** The project still writes and recovers `B39SSS1`. Private Go API changes are internal to this source tree: `Share.Token` now returns an error, and deterministic RNG injection is unexported. No wallet seed or mnemonic migration is needed for valid original backups.

The custom format remains **non-SLIP-39**. Keeping v1 compatibility also preserves its visible payload length and unauthenticated metadata. The checksums are not authentication. A complete valid replacement share set cannot be distinguished from your original set without independently trusted wallet identity/custody information. Metadata such as ID/total can be relabeled without changing the protected secret. These limits are now explicit; adding a checksum alone would not solve them.

Likewise, no TUI can protect secrets from its host administrator, compromised OS, terminal recorder, swap, or physical examination of unencrypted exported media. Secret memory erasure and secure deletion are not guaranteed. Passing this review's tests is not certification for protecting significant funds.
