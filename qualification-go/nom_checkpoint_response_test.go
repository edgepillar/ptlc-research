package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Independent packet-key mathematics only; actual openings and provisioned
// authority are separate Python/caller premises, never reconstructed here.
const checkpointAuthorityDomain = "ptlc-nom-checkpoint-response-authority-message-v1\x00"
const checkpointSignedDomain = "ptlc-nom-checkpoint-response-signed-message-v1\x00"
const checkpointRequestDomain = "ptlc-nom-checkpoint-response-request-v1\x00"

func checkpointResponseFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/nom_checkpoint_response.json")
	if err != nil {
		t.Fatal(err)
	}
	f := governorDecode(t, body)
	if f["schema"] != "ptlc-nom-checkpoint-response-public-vectors-v1" {
		t.Fatal("unexpected response vectors")
	}
	return f
}
func checkpointSignedMessage(r map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"schema": "ptlc-nom-checkpoint-response-signed-message-v1",
		"purpose": "checkpoint-candidate-or-outage-math-only", "declaration": r["declaration"],
		"query_digest_hex": r["query_digest_hex"], "discovery_message_digest_hex": r["discovery_message_digest_hex"]}
}
func checkpointResponseVerifies(t *testing.T, r map[string]interface{}) bool {
	t.Helper()
	if !governorObject(r, []string{"schema", "declaration", "query_digest_hex", "discovery_message_digest_hex", "root_signature_hex", "response_signature_hex"}) || r["schema"] != "ptlc-nom-checkpoint-response-request-v1" {
		return false
	}
	d, ok := r["declaration"].(map[string]interface{})
	if !ok || !governorObject(d, []string{"schema", "purpose", "algorithm", "authority_epoch", "root_key_hex", "service_selection", "service_selection_digest_hex", "work_scope_digest_hex", "root_transition"}) || d["schema"] != "ptlc-nom-checkpoint-response-authority-v1" || d["purpose"] != "checkpoint-candidate-response-role" || d["algorithm"] != "BIP340-SHA256" || d["root_transition"] != "independent-reprovisioning" || !governorNumber(d["authority_epoch"], (1<<53)-1) {
		return false
	}
	p, ok := d["service_selection"].(map[string]interface{})
	if !ok || !governorObject(p, []string{"schema", "purpose", "service_id_hex", "service_epoch", "checkpoint_key_hex", "realm", "max_snapshots"}) || p["schema"] != "ptlc-nom-checkpoint-service-selection-v1" || p["purpose"] != "external-reference-retention-only" || !governorNumber(p["service_epoch"], (1<<53)-1) || !governorNumber(p["max_snapshots"], 16) {
		return false
	}
	if _, ok := governorHex(p["service_id_hex"], 32); !ok {
		return false
	}
	realm, ok := p["realm"].(map[string]interface{})
	if !ok || !governorObject(realm, []string{"core_commit", "chain_id", "genesis_hash_hex", "binary_digest_hex", "spork_state_digest_hex", "canonicality_policy_digest_hex", "finality_policy_digest_hex", "freshness_policy_digest_hex", "restore_policy_digest_hex"}) || realm["core_commit"] != "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced" {
		return false
	}
	chain, ok := realm["chain_id"].(string)
	if !ok {
		return false
	}
	id, err := strconv.ParseUint(chain, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != chain {
		return false
	}
	for _, field := range []string{"genesis_hash_hex", "binary_digest_hex", "spork_state_digest_hex", "canonicality_policy_digest_hex", "finality_policy_digest_hex", "freshness_policy_digest_hex", "restore_policy_digest_hex"} {
		if _, ok := governorHex(realm[field], 32); !ok {
			return false
		}
	}
	if d["service_selection_digest_hex"] != hex.EncodeToString(enrollmentHash(t, "ptlc-nom-checkpoint-service-selection-v1\x00", p)) {
		return false
	}
	for _, field := range []string{"query_digest_hex", "discovery_message_digest_hex"} {
		if _, ok := governorHex(r[field], 32); !ok {
			return false
		}
	}
	if _, ok := governorHex(d["work_scope_digest_hex"], 32); !ok {
		return false
	}
	root, ok := governorHex(d["root_key_hex"], 32)
	if !ok {
		return false
	}
	response, ok := governorHex(p["checkpoint_key_hex"], 32)
	if !ok || bytes.Equal(root, response) {
		return false
	}
	for _, key := range [][]byte{root, response} {
		if _, err := schnorr.ParsePubKey(key); err != nil {
			return false
		}
	}
	for i, payload := range []interface{}{d, checkpointSignedMessage(r)} {
		field, domain, key := "root_signature_hex", checkpointAuthorityDomain, root
		if i == 1 {
			field, domain, key = "response_signature_hex", checkpointSignedDomain, response
		}
		sig, ok := governorHex(r[field], 64)
		if !ok || !verifies(key, enrollmentHash(t, domain, payload), sig) {
			return false
		}
	}
	return true
}
func checkpointResponseWire(t *testing.T, input []byte) bool {
	t.Helper()
	if len(input) == 0 || len(input) > 8192 {
		return false
	}
	depth, quoted, escaped := 0, false, false
	for _, b := range input {
		if b > 127 {
			return false
		}
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
		} else if b == '"' {
			quoted = true
		} else if b == '[' || b == '{' {
			depth++
			if depth > 12 {
				return false
			}
		} else if b == ']' || b == '}' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	if depth != 0 || quoted {
		return false
	}
	wire := bytes.TrimSuffix(input, []byte("\n"))
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	var r map[string]interface{}
	if err := decoder.Decode(&r); err != nil {
		return false
	}
	return bytes.Equal(enrollmentCanonical(t, r), wire) && checkpointResponseVerifies(t, r)
}
func TestNoMCheckpointResponseIndependentPublicMessagesAndResults(t *testing.T) {
	vectors := checkpointResponseFixture(t)["positive_vectors"].(map[string]interface{})
	if len(vectors) != 8 {
		t.Fatal("unexpected response vector count")
	}
	for name, value := range vectors {
		t.Run(name, func(t *testing.T) {
			v := value.(map[string]interface{})
			r := v["request"].(map[string]interface{})
			if !checkpointResponseVerifies(t, r) || !checkpointResponseWire(t, enrollmentCanonical(t, r)) {
				t.Fatal("valid response mathematics refused")
			}
			if v["declaration_message_digest_hex"] != hex.EncodeToString(enrollmentHash(t, checkpointAuthorityDomain, r["declaration"])) || v["signed_response_message_digest_hex"] != hex.EncodeToString(enrollmentHash(t, checkpointSignedDomain, checkpointSignedMessage(r))) {
				t.Fatal("message digest mismatch")
			}
			result := v["result"].(map[string]interface{})
			if !governorObject(result, []string{"schema", "request_digest_hex", "root_signature_valid", "response_signature_valid"}) || result["schema"] != "ptlc-nom-checkpoint-response-result-v1" || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, checkpointRequestDomain, r)) || result["root_signature_valid"] != true || result["response_signature_valid"] != true {
				t.Fatal("incomplete bound result")
			}
		})
	}
}
func TestNoMCheckpointResponseEachBindingRolesAndOldPermissionRefuse(t *testing.T) {
	f := checkpointResponseFixture(t)
	r := f["positive_vectors"].(map[string]interface{})["newer_candidate"].(map[string]interface{})["request"]
	for _, path := range [][]string{{}, {"declaration"}, {"declaration", "service_selection"}, {"declaration", "service_selection", "realm"}} {
		at := governorCopy(t, r)
		for _, p := range path {
			at = at[p].(map[string]interface{})
		}
		for field := range at {
			for _, mode := range []string{"missing", "changed", "wrong-type"} {
				changed := governorCopy(t, r)
				selected := changed
				for _, p := range path {
					selected = selected[p].(map[string]interface{})
				}
				switch mode {
				case "missing":
					delete(selected, field)
				case "changed":
					selected[field] = strings.Repeat("99", 32)
				default:
					selected[field] = []interface{}{}
				}
				if checkpointResponseVerifies(t, changed) {
					t.Fatalf("accepted changed %v/%s", path, field)
				}
			}
		}
	}
	for _, group := range []string{"wrong_domain_signatures", "wrong_role_signatures"} {
		for _, field := range []string{"root_signature_hex", "response_signature_hex"} {
			changed := governorCopy(t, r)
			changed[field] = f[group].(map[string]interface{})[field]
			if checkpointResponseVerifies(t, changed) {
				t.Fatal("cross-domain or role signature accepted")
			}
		}
	}
	changed := governorCopy(t, r)
	changed["response_signature_hex"] = strings.Repeat("00", 64)
	if checkpointResponseVerifies(t, changed) {
		t.Fatal("zero signature accepted")
	}
}
func TestNoMCheckpointResponseCanonicalBoundsAndAlternateSignature(t *testing.T) {
	f := checkpointResponseFixture(t)
	r := f["positive_vectors"].(map[string]interface{})["newer_candidate"].(map[string]interface{})["request"]
	wire := string(enrollmentCanonical(t, r))
	for _, bad := range []string{" " + wire, wire + "\n\n", strings.Replace(wire, "{", "{\"schema\":\"duplicate\",", 1), strings.Repeat("[", 13) + strings.Repeat("]", 13), strings.Repeat("x", 8193), "\u00e9"} {
		if checkpointResponseWire(t, []byte(bad)) {
			t.Fatal("malformed wire accepted")
		}
	}
	changed := governorCopy(t, r)
	changed["response_signature_hex"] = f["alternate_response_signature_hex"]
	if !checkpointResponseVerifies(t, changed) {
		t.Fatal("alternative valid encoding refused")
	}
	if bytes.Equal(enrollmentHash(t, checkpointRequestDomain, r), enrollmentHash(t, checkpointRequestDomain, changed)) || !bytes.Equal(enrollmentHash(t, checkpointSignedDomain, checkpointSignedMessage(r.(map[string]interface{}))), enrollmentHash(t, checkpointSignedDomain, checkpointSignedMessage(changed))) {
		t.Fatal("signature encoding does not bind its request separately")
	}
}
