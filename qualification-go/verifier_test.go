package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/sha3"
)

// This test package exercises PR #13's pinned verifier dependency, not its VM.
// All corpus fields are public and all local messages are synthetic.
type vector struct {
	ID        string `json:"id"`
	Index     int    `json:"index"`
	PublicKey string `json:"public_key_hex"`
	Message   string `json:"message_hex"`
	Signature string `json:"signature_hex"`
	Valid     bool   `json:"valid"`
}

func loadVectors(t *testing.T, path string, count int) []vector {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != count {
		t.Fatalf("expected %d vectors, got %d", count, len(corpus.Vectors))
	}
	return corpus.Vectors
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifies(publicKey, message, signature []byte) bool {
	key, err := schnorr.ParsePubKey(publicKey)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(signature)
	return err == nil && sig.Verify(message, key)
}

func TestOfficialBIP340CorpusAndLegacyMessageBoundary(t *testing.T) {
	// Vectors 15-18 extend BIP340 to variable-length messages. This pinned old
	// verifier requires exactly 32 bytes, as the proposed Zenon contract supplies.
	for i, v := range loadVectors(t, "../tests/fixtures/bip340_public_vectors.json", 19) {
		if v.Index != i {
			t.Fatal("official corpus order or index changed")
		}
		t.Run(strconv.Itoa(v.Index), func(t *testing.T) {
			msg := decode(t, v.Message)
			want := v.Valid && len(msg) == 32
			if got := verifies(decode(t, v.PublicKey), msg, decode(t, v.Signature)); got != want {
				t.Fatalf("verification = %v, expected %v", got, want)
			}
		})
	}
}

func completed(t *testing.T) []vector {
	t.Helper()
	return loadVectors(t, "../qualification/fixtures/completed_signatures.json", 4)
}

func TestRustCompletedSignaturesAndNegativeControls(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range completed(t) {
		if v.ID == "" || seen[v.ID] || !v.Valid {
			t.Fatal("invalid completed-vector identity or expectation")
		}
		seen[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			key, msg, sig := decode(t, v.PublicKey), decode(t, v.Message), decode(t, v.Signature)
			if len(key) != 32 || len(msg) != 32 || len(sig) != 64 {
				t.Fatal("completed vector has unexpected width")
			}
			if !verifies(key, msg, sig) {
				t.Fatal("Rust-completed signature rejected")
			}
			changedMessage := append([]byte(nil), msg...)
			changedMessage[0] ^= 1
			changedSignature := append([]byte(nil), sig...)
			changedSignature[63] ^= 1
			for name, input := range map[string]struct{ key, msg, sig []byte }{
				"changed-message":   {key, changedMessage, sig},
				"changed-signature": {key, msg, changedSignature},
				"short-key":         {key[:31], msg, sig},
				"long-key":          {append([]byte{2}, key...), msg, sig},
				"short-signature":   {key, msg, sig[:63]},
				"long-signature":    {key, msg, append(append([]byte(nil), sig...), 0)},
			} {
				t.Run(name, func(t *testing.T) {
					if verifies(input.key, input.msg, input.sig) {
						t.Fatal("negative control unexpectedly accepted")
					}
				})
			}
		})
	}
}

func TestZenonDigestAndClaimBinding(t *testing.T) {
	id := decode(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	destination := decode(t, "000102030405060708090a0b0c0d0e0f10111213")
	preimage := append(append([]byte(nil), id...), destination...)
	digest := sha3.Sum256(preimage)
	var claim *vector
	for _, v := range completed(t) {
		if v.ID == "musig2-aggregate-znn-contract-digest" {
			copy := v
			claim = &copy
		}
	}
	if claim == nil || !bytes.Equal(digest[:], decode(t, claim.Message)) {
		t.Fatal("missing claim vector or contract digest mismatch")
	}
	key, sig := decode(t, claim.PublicKey), decode(t, claim.Signature)
	if !verifies(key, digest[:], sig) {
		t.Fatal("signature rejected for source-derived Zenon message")
	}
	for _, offset := range []int{0, len(id)} {
		changed := append([]byte(nil), preimage...)
		changed[offset] ^= 1
		wrong := sha3.Sum256(changed)
		if verifies(key, wrong[:], sig) {
			t.Fatal("signature authorized changed entry or destination")
		}
	}
	keccak := sha3.NewLegacyKeccak256()
	_, _ = keccak.Write(preimage)
	if verifies(key, keccak.Sum(nil), sig) {
		t.Fatal("signature accepted with Keccak instead of SHA3-256")
	}
}
