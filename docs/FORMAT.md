# B39SSS1 serialization format (v1)

**Not SLIP-39 or a standardized interchange format.** Documented to make independent recovery possible, rather than depending exclusively on a single compiled binary.

All multibyte integers: **big-endian**. All strings: **UTF-8**, with no Unicode normalization during share storage (BIP-39 seed derivation must perform NFKD per BIP-39). Share tokens use unpadded RFC 4648 **base64url** (`-` and `_` alphabet) of raw serialized bytes, prefixed with the ASCII literal `B39SSS1:`.

## Cleartext share wrapper (metadata and one Shamir point)

| Offset | Width | Field |
|---|---:|---|
| 0 | 7 | ASCII `B39SHR1` |
| 7 | 1 | Threshold `m`, 2..16 |
| 8 | 1 | Total number `n`, `m..16` |
| 9 | 1 | Share x-index, 1..n |
| 10 | 16 | Uniform random backup-set ID |
| 26 | 2 | Big-endian length L of Shamir y-bytes |
| 28 | L | Y-byte vector at x-index, in GF(256) |
| 28+L | 32 | SHA-256 of all preceding share-wrapper bytes |

`B39SSS1:` + `base64.RawURLEncoding.EncodeToString(wrapper)` + newline for saved files.

An individual share exposes its threshold, total, index, set ID, and Y-byte length. **Never mix separate backup sets**, even if they have matching thresholds. The share checksum is a **public accidental-corruption check** (not a MAC or digital signature).

## Inner payload (Shamir-protected; readable only after m shares)

| Offset | Width | Field |
|---|---:|---|
| 0 | 7 | ASCII `B39PAY1` |
| 7 | 1 | `0` = no passphrase included, `1` = passphrase included |
| 8 | 1 | BIP-39 entropy length: 16 or 32 bytes |
| 9 | 16 / 32 | Original BIP-39 entropy, NOT the 64-byte PBKDF2 derived seed |
| 9+E | 2 | Big-endian passphrase byte length P (0..512) |
| 11+E | P | Exact UTF-8 passphrase, if included |
| 11+E+P | 32 | SHA-256 of all preceding payload bytes |

The `passphrase included` flag is `0` exactly when `P==0`, and `1` exactly when `P>0`. A backup with no included passphrase does not reveal whether the wallet actually used a separately held passphrase.

## Shamir primitive

- Field: GF(2^8) modulo irreducible polynomial `x^8+x^4+x^3+x+1` (hex polynomial `0x11B`).
- For every payload byte `s[j]`, independently choose `m-1` random coefficient bytes `a1 ... a(m-1)` using a CSPRNG, uniformly from the entire field (zero is valid).
- Polynomial for byte j: `f_j(x) = s[j] + a1*x + a2*x^2 + ... + a(m-1)*x^(m-1)` with addition as XOR and multiplication in that field.
- For each index `x=1..n`, output point `y[j]=f_j(x)` for all j (share's Y-byte vector).
- Recover each payload byte by Lagrange interpolation at **x=0** from any **m distinct shares**.
- If more than m shares are provided to the low-level recovery function, independently evaluate the reconstructed polynomial at all surplus x-coordinates and reject inconsistencies.

The app's share wrapper checksum is checked before polynomial recovery, followed by payload SHA-256 integrity checking. Only after checking the payload is the BIP-39 mnemonic regenerated from entropy.

## Recovery pseudocode

```text
for each token:
    require prefix B39SSS1:
    decode base64url; parse fields; verify full SHA-256
    require matching ID, m, n, share payload length, unique x
require >=m points
payload := InterpolateGF256(points[:m], x=0)
require payload magic B39PAY1 and valid payload SHA-256
read entropy (16/32B), optional passphrase (0..512 UTF-8 bytes)
regenerate English BIP-39 mnemonic from ENT + checksum (SHA-256)
return mnemonic and optional passphrase
```

Test vectors are available in `internal/shamir/shamir_test.go`, `internal/share/share_test.go`, and `internal/backup/bip39_test.go`. Complete independently generated v1 fixtures are included in `internal/share/testdata/v1-vectors.json`; their test-only generator and interpolation oracle are in `tests/reference_format.py`. These are project fixtures, not a formally standardized format.


## Revised implementation bounds and compatibility

The 2026-10-13 review revision preserves all valid v1 payloads and tokens. The
payload length is 59..587 bytes. The largest raw wrapper is 647 bytes, and the
largest prefixed, unpadded token is 871 ASCII bytes (plus LF or CRLF in a file).
The parser permits surrounding whitespace within its bounded input but rejects
embedded CR/LF, padding, noncanonical base64 trailing bits, malformed lengths,
and invalid threshold/index parameters. The library validates before encoding.

The generation TUI accepts printable single-line UTF-8 passphrases of at most
512 bytes; it rejects control characters. The underlying v1 payload format and
recovery still support all valid UTF-8 byte strings allowed by v1, including
control characters. Significant spaces and original Unicode normalization form
are preserved. An empty passphrase must be represented as excluded.

## Integrity is not origin authentication

Neither digest is keyed. The inner digest does not bind the public set ID,
threshold, or total. Relabeling metadata on a consistent set can succeed; a
completely substituted, internally valid share set will also recover. Keep
independently trusted wallet identity information and protect share custody.
Payload length is public and can constrain/reveal mnemonic or passphrase length.
Changing these properties requires a separately designed format/version; no
silent, incompatible change has been made to v1.
