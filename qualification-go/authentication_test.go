package qualification

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// An independent verifier and message reconstruction over the public fixture.
// This does not turn the historical compatibility dependency into an auth service.
func TestAuthenticationEnvelopeUnderIndependentVerifier(t *testing.T) {
	data, err := os.ReadFile("../qualification/fixtures/authentication.json")
	if err != nil {
		t.Fatal("authentication fixture unavailable")
	}
	type authCase struct {
		Request struct {
			Context   map[string]string `json:"context"`
			Payload   string            `json:"payload_hex"`
			Signature string            `json:"signature_hex"`
		} `json:"request"`
		Digest string `json:"message_digest_hex"`
	}
	var corpus struct {
		authCase
		Invalid authCase `json:"authenticated_invalid_completion"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal("invalid authentication fixture")
	}
	for index, c := range []authCase{corpus.authCase, corpus.Invalid} {
		t.Run([]string{"completion", "invalid-inner-signature"}[index], func(t *testing.T) {
			context, err := json.Marshal(c.Request.Context)
			if err != nil || len(c.Request.Context) != 11 {
				t.Fatal("invalid context")
			}
			payload := decode(t, c.Request.Payload)
			if len(payload) != 9841 {
				t.Fatal("unexpected public payload length")
			}
			message := func(body []byte) []byte {
				hash := sha256.New()
				hash.Write([]byte("PTLC/completion-auth/signature/v1\x00"))
				hash.Write(context)
				hash.Write([]byte{0})
				var length [4]byte
				binary.BigEndian.PutUint32(length[:], uint32(len(body)))
				hash.Write(length[:])
				hash.Write(body)
				return hash.Sum(nil)
			}
			digest := message(payload)
			if hex.EncodeToString(digest) != c.Digest {
				t.Fatal("message reconstruction disagrees with fixture")
			}
			key := decode(t, c.Request.Context["alice_auth_key_hex"])
			signature := decode(t, c.Request.Signature)
			if !verifies(key, digest, signature) {
				t.Fatal("independent verifier rejected authentication signature")
			}
			payload[0] ^= 1
			if verifies(key, message(payload), signature) ||
				verifies(decode(t, c.Request.Context["bob_auth_key_hex"]), digest, signature) {
				t.Fatal("authentication signature accepted a changed payload or sender key")
			}
		})
	}
}
