// All scalar and signing inputs below are public synthetic test constants.
// This package has no application signing API and does not implement the VM.
package compatibility

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"testing"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/sha3"
)

const profile = "zenon-ptlc-unlock:v1"
const core = "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced"
const contract = "01b3b6e5adcb4c15ff06318c6318c6318c6318c6"

type context struct {
	Profile     string `json:"profile"`
	Chain       string `json:"chain_id"`
	Point       int    `json:"point_type"`
	Entry       string `json:"entry_id_hex"`
	Destination string `json:"destination_hex"`
}
type messageVector struct {
	ID       string  `json:"id"`
	Context  context `json:"context"`
	Preimage string  `json:"preimage_hex"`
	Message  string  `json:"message_hex"`
	Legacy   string  `json:"legacy_message_hex"`
}
type witnessVector struct {
	ID           string `json:"id"`
	Point        int    `json:"point_type"`
	Key          string `json:"point_lock_hex"`
	Message      string `json:"message_hex"`
	Witness      string `json:"witness_hex"`
	ValidPoint   bool   `json:"valid_point"`
	ValidWitness bool   `json:"valid_witness"`
	SendSize     bool   `json:"send_size_allowed"`
}

func raw(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal("invalid fixture hex")
	}
	return result
}
func read(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}
func messages(t *testing.T) []messageVector {
	var data struct {
		Schema       string          `json:"schema"`
		Profile      string          `json:"profile"`
		Core         string          `json:"core_commit"`
		Contract     string          `json:"contract_hex"`
		Vectors      []messageVector `json:"message_vectors"`
		Destinations []struct {
			Point       int    `json:"point_type"`
			Destination string `json:"destination_hex"`
			Create      bool   `json:"create_allowed"`
			Payable     bool   `json:"payable"`
		} `json:"destination_vectors"`
	}
	read(t, "../fixtures/pr138_messages_v1.json", &data)
	if data.Schema != "zenon-pr138-message-corpus-v1" || data.Profile != profile || data.Core != core || data.Contract != contract || len(data.Vectors) != 48 || len(data.Destinations) != 15 {
		t.Fatal("profile boundary changed")
	}
	for _, v := range data.Destinations {
		d := raw(t, v.Destination)
		pay := len(d) == 20 && d[0] == 0 && !bytes.Equal(d, make([]byte, 20))
		create := pay || (v.Point < 2 && bytes.Equal(d, make([]byte, 20)))
		if pay != v.Payable || create != v.Create {
			t.Fatal("destination policy mismatch")
		}
	}
	return data.Vectors
}
func TestMessageCorpusAndReplayBoundaries(t *testing.T) {
	seen := make(map[string]bool)
	for _, v := range messages(t) {
		if v.Context.Profile != profile || seen[v.ID] {
			t.Fatal("profile or identity mismatch")
		}
		seen[v.ID] = true
		chain, err := strconv.ParseUint(v.Context.Chain, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		b := new(bytes.Buffer)
		b.WriteString(profile)
		if err := binary.Write(b, binary.BigEndian, chain); err != nil {
			t.Fatal(err)
		}
		b.Write(raw(t, contract))
		b.WriteByte(byte(v.Context.Point))
		b.Write(raw(t, v.Context.Entry))
		b.Write(raw(t, v.Context.Destination))
		if b.Len() != 101 || !bytes.Equal(b.Bytes(), raw(t, v.Preimage)) {
			t.Fatal("preimage mismatch")
		}
		digest := sha3.Sum256(b.Bytes())
		if !bytes.Equal(digest[:], raw(t, v.Message)) {
			t.Fatal("SHA3 mismatch")
		}
		old := sha3.Sum256(raw(t, v.Context.Entry+v.Context.Destination))
		if !bytes.Equal(old[:], raw(t, v.Legacy)) || old == digest {
			t.Fatal("legacy profile alias")
		}
		for _, offset := range []int{0, 20, 28, 48, 49, 81} {
			changed := append([]byte(nil), b.Bytes()...)
			changed[offset] ^= 1
			if sha3.Sum256(changed) == digest {
				t.Fatal("replay field not bound")
			}
		}
		keccak := sha3.NewLegacyKeccak256()
		keccak.Write(b.Bytes())
		if bytes.Equal(keccak.Sum(nil), digest[:]) {
			t.Fatal("Keccak alias")
		}
	}
}
func validPoint(point int, key []byte) bool {
	switch point {
	case 0:
		if len(key) != 32 {
			return false
		}
		decoded, err := new(edwards25519.Point).SetBytes(key)
		return err == nil && new(edwards25519.Point).MultByCofactor(decoded).Equal(edwards25519.NewIdentityPoint()) != 1
	case 1:
		if len(key) != 32 {
			return false
		}
		_, err := schnorr.ParsePubKey(key)
		return err == nil
	case 2:
		if len(key) != 33 || (key[0] != 2 && key[0] != 3) {
			return false
		}
		_, err := btcec.ParsePubKey(key)
		return err == nil
	default:
		return false
	}
}
func verifies(point int, key, message, witness []byte) bool {
	if !validPoint(point, key) || len(message) != 32 {
		return false
	}
	switch point {
	case 0:
		return len(witness) == 64 && ed25519.Verify(key, message, witness)
	case 1:
		if len(witness) != 64 {
			return false
		}
		pk, err := schnorr.ParsePubKey(key)
		if err != nil {
			return false
		}
		sig, err := schnorr.ParseSignature(witness)
		return err == nil && sig.Verify(message, pk)
	case 2:
		if len(witness) != 32 {
			return false
		}
		n := new(big.Int).SetBytes(witness)
		if n.Sign() <= 0 || n.Cmp(btcec.S256().N) >= 0 {
			return false
		}
		_, pk := btcec.PrivKeyFromBytes(witness)
		return bytes.Equal(pk.SerializeCompressed(), key)
	}
	return false
}
func publicWitnesses(t *testing.T) []witnessVector {
	var vectors []witnessVector
	base := messages(t)[16]
	msg := raw(t, base.Message)
	add := func(id string, point int, key, witness, message []byte, wantPoint, wantWitness bool) {
		vectors = append(vectors, witnessVector{id, point, hex.EncodeToString(key), hex.EncodeToString(message), hex.EncodeToString(witness), wantPoint, wantWitness, len(witness) == 32 || len(witness) == 64})
	}
	seed := bytes.Repeat([]byte{0x11}, 32)
	ed := ed25519.NewKeyFromSeed(seed)
	edKey := ed.Public().(ed25519.PublicKey)
	edSig := ed25519.Sign(ed, msg)
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x12}, 32))
	sig, err := schnorr.Sign(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	pk := schnorr.SerializePubKey(key.PubKey())
	bip := sig.Serialize()
	scalar := make([]byte, 32)
	scalar[31] = 3
	_, point := btcec.PrivKeyFromBytes(scalar)
	compressed := point.SerializeCompressed()
	add("ed-valid", 0, edKey, edSig, msg, true, true)
	add("bip340-valid", 1, pk, bip, msg, true, true)
	add("scalar-valid", 2, compressed, scalar, msg, true, true)
	changed := append([]byte(nil), msg...)
	changed[0] ^= 1
	add("ed-wrong-message", 0, edKey, edSig, changed, true, false)
	add("bip340-wrong-message", 1, pk, bip, changed, true, false)
	add("scalar-message-independent", 2, compressed, scalar, changed, true, true)
	for _, length := range []int{0, 31, 32, 63, 65} {
		add("bip340-witness-width-"+strconv.Itoa(length), 1, pk, make([]byte, length), msg, true, false)
	}
	add("ed-short-witness", 0, edKey, edSig[:63], msg, true, false)
	add("ed-identity", 0, append([]byte{1}, make([]byte, 31)...), edSig, msg, false, false)
	add("ed-noncanonical-identity", 0, append([]byte{0xee}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...), edSig, msg, false, false)
	add("bip340-invalid-key", 1, bytes.Repeat([]byte{0xff}, 32), bip, msg, false, false)
	add("bip340-compressed-key-refused", 1, key.PubKey().SerializeCompressed(), bip, msg, false, false)
	mutatedSig := append([]byte(nil), bip...)
	mutatedSig[63] ^= 1
	add("bip340-wrong-signature", 1, pk, mutatedSig, msg, true, false)
	legacy := raw(t, base.Legacy)
	oldSig, err := schnorr.Sign(key, legacy)
	if err != nil {
		t.Fatal(err)
	}
	add("legacy-signature-refused", 1, pk, oldSig.Serialize(), msg, true, false)
	for _, name := range []string{"zero", "order", "order-plus-one"} {
		n := new(big.Int)
		if name != "zero" {
			n.Set(btcec.S256().N)
		}
		if name == "order-plus-one" {
			n.Add(n, big.NewInt(1))
		}
		value := make([]byte, 32)
		n.FillBytes(value)
		add("scalar-"+name, 2, compressed, value, msg, true, false)
	}
	opposite := append([]byte(nil), compressed...)
	opposite[0] ^= 1
	add("scalar-opposite-parity", 2, opposite, scalar, msg, true, false)
	add("scalar-short", 2, compressed, scalar[:31], msg, true, false)
	add("scalar-long", 2, compressed, append(scalar, 0), msg, true, false)
	add("scalar-uncompressed-point", 2, point.SerializeUncompressed(), scalar, msg, false, false)
	add("unknown-type-send-size-only", 3, pk, bip, msg, false, false)
	return vectors
}
func TestPinnedWitnessCorpus(t *testing.T) {
	vectors := publicWitnesses(t)
	data := struct {
		Schema  string          `json:"schema"`
		Profile string          `json:"profile"`
		Core    string          `json:"core_commit"`
		Vectors []witnessVector `json:"vectors"`
	}{"zenon-pr138-witness-corpus-v1", profile, core, vectors}
	if os.Getenv("PTLC_REGENERATE_PUBLIC_PR138_V1") == "1" {
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("../fixtures/pr138_witnesses_v1.json", append(b, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var retained struct {
		Schema  string          `json:"schema"`
		Profile string          `json:"profile"`
		Core    string          `json:"core_commit"`
		Vectors []witnessVector `json:"vectors"`
	}
	read(t, "../fixtures/pr138_witnesses_v1.json", &retained)
	expected, _ := json.Marshal(data)
	actual, _ := json.Marshal(retained)
	if !bytes.Equal(expected, actual) {
		t.Fatal("public witness corpus drift")
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			key, msg, witness := raw(t, v.Key), raw(t, v.Message), raw(t, v.Witness)
			if validPoint(v.Point, key) != v.ValidPoint || verifies(v.Point, key, msg, witness) != v.ValidWitness {
				t.Fatal("pinned verifier mismatch")
			}
		})
	}
}
