package share

import (
    "bytes"
    "strings"
    "testing"
)

func TestWordSharesRoundTripAndMixedRecovery(t *testing.T) {
    cases := []struct {
        name string
        entropy int
        passphrase string
    }{
        {"12 words no passphrase", 16, ""},
        {"24 words no passphrase", 32, ""},
        {"Unicode spaces", 16, "  café \\ \" 🔐  "},
        {"maximum passphrase", 32, strings.Repeat("z", MaxPassphraseBytes)},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            backup := Backup{Entropy: make([]byte, tc.entropy), Passphrase: tc.passphrase, IncludesPassphrase: tc.passphrase != ""}
            shares, err := Generate(backup, 3, 5)
            if err != nil {
                t.Fatal(err)
            }
            defer Clear(shares)
            mixed := make([]Share, 0, 3)
            for i, s := range shares {
                token, err := s.Token()
                if err != nil {
                    t.Fatal(err)
                }
                words, err := s.Words()
                if err != nil {
                    t.Fatal(err)
                }
                if !strings.HasPrefix(words, WordPrefix+" ") {
                    t.Fatal("missing word-format marker")
                }
                if len(words) > MaxWordTokenBytes {
                    t.Fatal("word format exceeds input limit")
                }
                // Human-formatted multiline shares must round trip identically.
                w := strings.Fields(words)
                multiline := w[0]+"\n"+strings.Join(w[1:], "  \n")
                decoded, err := ParseInput(multiline)
                if err != nil {
                    t.Fatalf("word roundtrip %d: %v", i, err)
                }
                back, err := decoded.Token()
                if err != nil || back != token {
                    t.Fatalf("word encoding changed binary share %d", i)
                }
                if i < 3 {
                    if i%2 == 0 {
                        mixed = append(mixed, decoded)
                    } else {
                        legacy, err := ParseInput(token)
                        if err != nil {
                            t.Fatal(err)
                        }
                        mixed = append(mixed, legacy)
                    }
                }
            }
            defer Clear(mixed)
            out, err := Recover(mixed)
            if err != nil {
                t.Fatal(err)
            }
            defer clear(out.Entropy)
            if !bytes.Equal(out.Entropy, backup.Entropy) || out.Passphrase != backup.Passphrase || out.IncludesPassphrase != backup.IncludesPassphrase {
                t.Fatal("mixed-format recovery differs from original")
            }
        })
    }
}

// Every permitted passphrase byte length exercises a different set of 11-bit
// boundaries. This specifically checks the canonical final padding bits.
func TestWordEncodingAllPayloadLengths(t *testing.T) {
    for length := 0; length <= MaxPassphraseBytes; length++ {
        backup := Backup{Entropy: make([]byte, 32)}
        if length != 0 {
            backup.Passphrase = strings.Repeat("p", length)
            backup.IncludesPassphrase = true
        }
        shares, err := Generate(backup, 2, 2)
        if err != nil {
            t.Fatal(err)
        }
        original, err := shares[0].Token()
        if err != nil {
            t.Fatal(err)
        }
        words, err := shares[0].Words()
        if err != nil {
            t.Fatal(err)
        }
        restored, err := ParseWords(words)
        if err != nil {
            t.Fatalf("passphrase length %d: %v", length, err)
        }
        token, err := restored.Token()
        if err != nil || token != original {
            t.Fatalf("passphrase length %d changed serialized share", length)
        }
        clear(restored.Value)
        Clear(shares)
    }
}

func TestWordShareRejectsCorruptionAndNoncanonicalEncoding(t *testing.T) {
    shares, err := Generate(Backup{Entropy: make([]byte, 16)}, 2, 3)
    if err != nil {
        t.Fatal(err)
    }
    defer Clear(shares)
    words, err := shares[0].Words()
    if err != nil {
        t.Fatal(err)
    }
    pieces := strings.Fields(words)
    tamper := func(p []string) string { return strings.Join(p, " ") }
    testInvalid := func(label, input string) {
        t.Helper()
        if _, err := ParseWords(input); err == nil {
            t.Fatalf("%s was accepted", label)
        }
    }
    testInvalid("missing prefix", strings.TrimPrefix(words, WordPrefix))
    testInvalid("too long", words+strings.Repeat(" ", MaxWordTokenBytes+1))
    original := append([]string(nil), pieces...)
    original[1] = "not-a-bip39-word"
    testInvalid("bad word", tamper(original))
    original = append([]string(nil), pieces[:len(pieces)-1]...)
    testInvalid("truncated words", tamper(original))
    original = append([]string(nil), pieces...)
    original = append(original, "abandon")
    testInvalid("extra words", tamper(original))
    original = append([]string(nil), pieces...)
    if original[2] == "abandon" {
        original[2] = "ability"
    } else {
        original[2] = "abandon"
    }
    testInvalid("changed wrapper", tamper(original))
    // 119-byte wrapper for 12 words w/o a passphrase has five padding bits.
    original = append([]string(nil), pieces...)
    last := len(original)-1
    idx := englishWordIndex[original[last]]
    original[last] = bip39IndexWord(idx | 1)
    testInvalid("nonzero padding", tamper(original))
    testInvalid("missing words", WordPrefix)
    testInvalid("too many words", WordPrefix+" "+strings.Repeat("abandon ", maxWordCount+1))
}

func bip39IndexWord(i int) string {
    // Reuse the exact same dictionary as the encoder without a second import.
    for word, index := range englishWordIndex {
        if index == i {
            return word
        }
    }
    panic("word index missing")
}
