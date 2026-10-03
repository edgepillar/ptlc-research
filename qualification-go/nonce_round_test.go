package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// The old pinned verifier checks public final signatures and point encodings.
// It does not verify adaptor partials, session commitments, or nonce freshness.
type nonceRoundVector struct {
	Leg                 string   `json:"leg"`
	RoundID             string   `json:"round_id_hex"`
	BindingDigest       string   `json:"binding_digest_hex"`
	RoundDigest         string   `json:"round_digest_hex"`
	PublicKey           string   `json:"public_key_hex"`
	Message             string   `json:"message_hex"`
	PublicNonces        []string `json:"public_nonces_hex"`
	NonceCommitments    []string `json:"nonce_commitments_hex"`
	PartialSignatures   []string `json:"partial_signatures_hex"`
	AdaptorPreSignature string   `json:"adaptor_presignature_hex"`
	Signature           string   `json:"signature_hex"`
	Valid               bool     `json:"valid"`
}

func nonceRoundVectors(t *testing.T) []nonceRoundVector {
	t.Helper()
	data, err := os.ReadFile("../qualification/fixtures/nonce_rounds.json")
	if err != nil {
		t.Fatal("public nonce fixture unavailable")
	}
	var corpus struct {
		Schema  string             `json:"schema"`
		Note    string             `json:"note"`
		Vectors []nonceRoundVector `json:"vectors"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal("invalid public nonce fixture schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing nonce fixture data")
	}
	if corpus.Schema != "ptlc-public-nonce-round-fixture-v1" || len(corpus.Vectors) != 2 {
		t.Fatal("unexpected nonce fixture identity or count")
	}
	return corpus.Vectors
}

func nonceField(t *testing.T, value string, width int) []byte {
	t.Helper()
	decoded := decode(t, value)
	if len(decoded) != width || hex.EncodeToString(decoded) != value {
		t.Fatal("nonce fixture has a noncanonical or incorrectly sized field")
	}
	return decoded
}

func TestPublicNonceRoundsAndCompletedSignaturesUnderLegacyVerifier(t *testing.T) {
	seen := make(map[string]bool)
	for index, v := range nonceRoundVectors(t) {
		if v.Leg != []string{"bitcoin", "zenon"}[index] || !v.Valid {
			t.Fatal("nonce fixture leg order or validity expectation changed")
		}
		if !bytes.Equal(nonceField(t, v.RoundID, 32), bytes.Repeat([]byte{byte(61 + index)}, 32)) {
			t.Fatal("nonce fixture round tag changed")
		}
		t.Run(v.Leg, func(t *testing.T) {
			key := nonceField(t, v.PublicKey, 32)
			message := nonceField(t, v.Message, 32)
			signature := nonceField(t, v.Signature, 64)
			if len(v.PublicNonces) != 2 || len(v.NonceCommitments) != 2 || len(v.PartialSignatures) != 2 {
				t.Fatal("expected two participant entries per round")
			}
			for _, nonceHex := range v.PublicNonces {
				nonce := nonceField(t, nonceHex, 66)
				if seen[nonceHex] {
					t.Fatal("four fixture public nonces must have distinct encodings")
				}
				seen[nonceHex] = true
				for _, component := range [][]byte{nonce[:33], nonce[33:]} {
					if component[0] != 2 && component[0] != 3 {
						t.Fatal("public nonce components must be compressed points")
					}
					point, err := btcec.ParsePubKey(component)
					if err != nil || !bytes.Equal(point.SerializeCompressed(), component) {
						t.Fatal("public nonce component rejected by the legacy curve parser")
					}
				}
			}
			if !verifies(key, message, signature) {
				t.Fatal("completed nonce-round signature rejected by the legacy verifier")
			}
			t.Run("changed-message", func(t *testing.T) {
				changed := append([]byte(nil), message...)
				changed[0] ^= 1
				if verifies(key, changed, signature) {
					t.Fatal("signature accepted a changed message")
				}
			})
			t.Run("changed-signature", func(t *testing.T) {
				changed := append([]byte(nil), signature...)
				changed[63] ^= 1
				if verifies(key, message, changed) {
					t.Fatal("changed signature unexpectedly accepted")
				}
			})
		})
	}
	if len(seen) != 4 {
		t.Fatal("expected all four distinct public nonce encodings")
	}
}
