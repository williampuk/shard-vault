package share

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerationRecovery(t *testing.T) {
	for _, length := range []int{16, 32} {
		for _, pass := range []string{"", "páss Phrase 🔐"} {
			b := Backup{Entropy: bytes.Repeat([]byte{0x19}, length), Passphrase: pass, IncludesPassphrase: pass != ""}
			shares, err := Generate(b, 3, 5)
			if err != nil {
				t.Fatal(err)
			}
			received := make([]Share, len(shares))
			for i, s := range shares {
				received[i], err = Parse(mustToken(t, s))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = VerifyAll(shares, received); err != nil {
				t.Fatal(err)
			}
			recovered, err := Recover([]Share{received[0], received[2], received[4]})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recovered.Entropy, b.Entropy) || recovered.Passphrase != pass || recovered.IncludesPassphrase != b.IncludesPassphrase {
				t.Fatal("wrong recovered values")
			}
			if _, err := Recover(received[:2]); err == nil {
				t.Fatal("2 shares recovered 3-of-5")
			}
			bad := received[1]
			bad.Value = append([]byte{}, bad.Value...)
			bad.Value[0] ^= 1
			if _, err := Recover([]Share{received[0], received[2], received[4], bad}); err == nil {
				t.Fatal("inconsistent additional share")
			}
			text := mustToken(t, shares[0])
			if _, err := Parse(text[:len(text)-2] + "AA"); err == nil {
				t.Fatal("accepted corrupted token")
			}
			if _, err := Parse("SLIP39:" + strings.TrimPrefix(text, Prefix)); err == nil {
				t.Fatal("accepted unsupported encoding")
			}
		}
	}
}

func TestMixingSets(t *testing.T) {
	b := Backup{Entropy: bytes.Repeat([]byte{2}, 16)}
	first, _ := Generate(b, 2, 3)
	second, _ := Generate(b, 2, 3)
	if _, err := Recover([]Share{first[0], second[1]}); err == nil {
		t.Fatal("accepted different groups")
	}
	if _, err := Recover([]Share{first[0], first[0]}); err == nil {
		t.Fatal("accepted duplicate")
	}
}

func TestPackIntegrity(t *testing.T) {
	b := Backup{Entropy: bytes.Repeat([]byte{3}, 16), Passphrase: "abc", IncludesPassphrase: true}
	raw, err := pack(b)
	if err != nil {
		t.Fatal(err)
	}
	raw[15] ^= 1
	if _, err := unpack(raw); err == nil {
		t.Fatal("accepted corrupt secret payload")
	}
	if _, err := pack(Backup{Entropy: b.Entropy, Passphrase: "oops"}); err == nil {
		t.Fatal("silently discarded passphrase")
	}
}

func mustToken(t *testing.T, s Share) string {
	t.Helper()
	token, err := s.Token()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
