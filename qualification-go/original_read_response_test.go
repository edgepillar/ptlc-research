package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Public test compatibility only; no signer, caller permission or source exists.
const originalReadResponseTag = "PTLC/observation-original-read-response/v1"
const originalReadResponseRequestDomain = "PTLC/observation-original-read-response-request/v1\x00"
const originalReadQueryDomain = "PTLC/observation-original-read-query/v1\x00"
const originalReadClaimDomain = "PTLC/observation-original-read-claim/v1\x00"

func publicOriginalResponseFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/original_read_response.json")
	if err != nil {
		t.Fatal(err)
	}
	v := governorDecode(t, body)
	if len(v) != 8 || v["schema"] != "ptlc-original-read-response-public-vectors-v1" {
		t.Fatal("unexpected original response fixture")
	}
	return v
}
func originalReadResponseMessage(t *testing.T, r interface{}) []byte {
	t.Helper()
	tag := sha256.Sum256([]byte(originalReadResponseTag))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(enrollmentCanonical(t, r))
	return h.Sum(nil)
}
func originalReadProfile(v interface{}) bool {
	p, ok := v.(map[string]interface{})
	if !ok || !governorObject(p, []string{"schema", "purpose", "role", "algorithm", "owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex", "max_attempt_limit", "max_target_limit"}) || p["schema"] != "ptlc-observation-governor-profile-v1" || p["purpose"] != "observation-enrollment" || p["role"] != "enrollment-governor" || p["algorithm"] != "BIP340-SHA256" {
		return false
	}
	for _, f := range []string{"owner_auth_key_hex", "resource_digest_hex", "authority_id_hex", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"} {
		if _, ok := governorHex(p[f], 32); !ok {
			return false
		}
	}
	if !governorNumber(p["authority_epoch"], (1<<53)-1) || !governorNumber(p["max_attempt_limit"], 64) || !governorNumber(p["max_target_limit"], 64) {
		return false
	}
	k, _ := governorHex(p["owner_auth_key_hex"], 32)
	_, err := schnorr.ParsePubKey(k)
	return err == nil
}
func originalRecordCheckpoint(v interface{}) bool {
	m, ok := v.(map[string]interface{})
	if !ok || !governorObject(m, []string{"retention_rule", "event_sequence", "record_lineage_digest_hex"}) || m["retention_rule"] != "retained-all-originals-in-incarnation-v1" || !responseNumber(m["event_sequence"], 0, (1<<53)-1) {
		return false
	}
	_, ok = governorHex(m["record_lineage_digest_hex"], 32)
	return ok
}
func originalReadQuery(t *testing.T, v interface{}, d map[string]interface{}) bool {
	t.Helper()
	q, ok := v.(map[string]interface{})
	if !ok || !governorObject(q, []string{"schema", "operation", "read_rule", "root_declaration_digest_hex", "source_context", "expected_checkpoint", "expected_record_checkpoint", "challenge_hex", "original_operation"}) || q["schema"] != "ptlc-observation-original-read-query-v1" || q["operation"] != "read-original-at-checkpoint" || q["read_rule"] != "same-incarnation-original-lookup-v1" || q["root_declaration_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceRootDomain, d)) || !reflect.DeepEqual(q["source_context"], d["source_context"]) || !responseCheckpoint(q["expected_checkpoint"]) || !originalRecordCheckpoint(q["expected_record_checkpoint"]) {
		return false
	}
	if _, ok := governorHex(q["challenge_hex"], 32); !ok {
		return false
	}
	o, ok := q["original_operation"].(map[string]interface{})
	if !ok || !governorObject(o, []string{"schema", "operation_id_hex", "expected_revision", "governor_profile", "proposal_digest_hex"}) || o["schema"] != "ptlc-observation-original-operation-v1" || !responseNumber(o["expected_revision"], 0, (1<<53)-1) || !originalReadProfile(o["governor_profile"]) {
		return false
	}
	for _, f := range []string{"operation_id_hex", "proposal_digest_hex"} {
		if _, ok := governorHex(o[f], 32); !ok {
			return false
		}
	}
	p := o["governor_profile"].(map[string]interface{})
	s := d["source_context"].(map[string]interface{})
	for _, f := range []string{"authority_id_hex", "resource_digest_hex", "role"} {
		if p[f] != s[f] {
			return false
		}
	}
	old, _ := o["expected_revision"].(json.Number).Int64()
	head, _ := q["expected_checkpoint"].(map[string]interface{})["revision"].(json.Number).Int64()
	return old <= head && (old != head || reflect.DeepEqual(p, d["governor_profile"]))
}
func originalReadClaim(t *testing.T, v interface{}, q, d map[string]interface{}) bool {
	t.Helper()
	c, ok := v.(map[string]interface{})
	if !ok || !governorObject(c, []string{"schema", "query_digest_hex", "root_declaration_digest_hex", "source_context_digest_hex", "challenge_hex", "observation", "claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"}) || c["schema"] != "ptlc-observation-original-read-claim-v1" || c["query_digest_hex"] != hex.EncodeToString(enrollmentHash(t, originalReadQueryDomain, q)) || c["source_context_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceContextDomain, q["source_context"])) || c["root_declaration_digest_hex"] != q["root_declaration_digest_hex"] || c["challenge_hex"] != q["challenge_hex"] {
		return false
	}
	if c["observation"] == "unavailable" {
		return c["claimed_checkpoint"] == nil && c["claimed_record_checkpoint"] == nil && c["head_policy"] == nil && c["original_record"] == nil
	}
	if !responseCheckpoint(c["claimed_checkpoint"]) || !originalRecordCheckpoint(c["claimed_record_checkpoint"]) || !reflect.DeepEqual(c["claimed_checkpoint"], q["expected_checkpoint"]) || !reflect.DeepEqual(c["claimed_record_checkpoint"], q["expected_record_checkpoint"]) {
		return false
	}
	policy, ok := c["head_policy"].(map[string]interface{})
	if !ok || !governorObject(policy, []string{"governor_profile", "active"}) || !reflect.DeepEqual(policy["governor_profile"], d["governor_profile"]) {
		return false
	}
	if _, ok := policy["active"].(bool); !ok {
		return false
	}
	if c["observation"] == "absent" {
		return c["original_record"] == nil
	}
	r, ok := c["original_record"].(map[string]interface{})
	if !ok || !governorObject(r, []string{"original_operation", "charge_sequence", "effect_sequence"}) || !reflect.DeepEqual(r["original_operation"], q["original_operation"]) {
		return false
	}
	sequence, _ := c["claimed_record_checkpoint"].(map[string]interface{})["event_sequence"].(json.Number).Int64()
	if !responseNumber(r["charge_sequence"], 1, uint64(sequence)) {
		return false
	}
	charge, _ := r["charge_sequence"].(json.Number).Int64()
	switch c["observation"] {
	case "pending":
		return r["effect_sequence"] == nil
	case "completed":
		return responseNumber(r["effect_sequence"], uint64(charge+1), uint64(sequence))
	default:
		return false
	}
}
func originalReadResponseVerifies(t *testing.T, p map[string]interface{}) bool {
	t.Helper()
	if !governorObject(p, []string{"schema", "root_envelope", "response", "response_signature_hex"}) || p["schema"] != "ptlc-observation-original-read-response-request-v1" {
		return false
	}
	s, ok := p["root_envelope"].(map[string]interface{})
	if !ok || !governorObject(s, []string{"schema", "declaration", "root_signature_hex"}) || s["schema"] != "ptlc-observation-source-root-envelope-v1" {
		return false
	}
	rr := governorCopy(t, s)
	rr["schema"] = "ptlc-observation-source-root-request-v1"
	if !sourceRootVerifies(t, rr) {
		return false
	}
	d := s["declaration"].(map[string]interface{})
	r, ok := p["response"].(map[string]interface{})
	if !ok || !governorObject(r, []string{"schema", "purpose", "algorithm", "read_rule", "root_declaration_digest_hex", "source_response_role", "source_response_key_hex", "source_context", "query", "claim", "claim_digest_hex"}) || r["schema"] != "ptlc-observation-original-read-response-v1" || r["purpose"] != "original-checkpoint-response" || r["algorithm"] != "BIP340-SHA256" || r["read_rule"] != "historical-original-checkpoint-read-v1" || r["source_response_role"] != "historical-original-responder" || r["root_declaration_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceRootDomain, d)) || r["source_response_key_hex"] != d["delegated_keys"].(map[string]interface{})["source_response_key_hex"] || !reflect.DeepEqual(r["source_context"], d["source_context"]) || !originalReadQuery(t, r["query"], d) {
		return false
	}
	if !originalReadClaim(t, r["claim"], r["query"].(map[string]interface{}), d) || r["claim_digest_hex"] != hex.EncodeToString(enrollmentHash(t, originalReadClaimDomain, r["claim"])) {
		return false
	}
	k, ok := governorHex(r["source_response_key_hex"], 32)
	if !ok {
		return false
	}
	sig, ok := governorHex(p["response_signature_hex"], 64)
	return ok && verifies(k, originalReadResponseMessage(t, r), sig)
}
func originalReadResponseWire(t *testing.T, wire []byte) bool {
	t.Helper()
	if len(wire) == 0 || len(wire) > 16384 {
		return false
	}
	for _, b := range wire {
		if b > 127 {
			return false
		}
	}
	wire = bytes.TrimSuffix(wire, []byte("\n"))
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	var p map[string]interface{}
	if err := decoder.Decode(&p); err != nil {
		return false
	}
	return bytes.Equal(enrollmentCanonical(t, p), wire) && originalReadResponseVerifies(t, p)
}
func originalResponsePrimary(t *testing.T) map[string]interface{} {
	return governorCopy(t, publicOriginalResponseFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"])
}
func originalResponseObjects(v map[string]interface{}, visit func([]string, map[string]interface{}), path []string) {
	visit(path, v)
	for f, c := range v {
		if m, ok := c.(map[string]interface{}); ok {
			p := append(append([]string{}, path...), f)
			originalResponseObjects(m, visit, p)
		}
	}
}
func originalResponseTarget(v map[string]interface{}, path []string) map[string]interface{} {
	for _, f := range path {
		v = v[f].(map[string]interface{})
	}
	return v
}

func TestOriginalResponsePublicTaggedMessagesAndTwoFlagResults(t *testing.T) {
	vs := publicOriginalResponseFixture(t)["positive_vectors"].(map[string]interface{})
	if len(vs) != 22 {
		t.Fatal("unexpected positive count")
	}
	for name, v := range vs {
		t.Run(name, func(t *testing.T) {
			v := v.(map[string]interface{})
			p := v["request"].(map[string]interface{})
			r := v["result"].(map[string]interface{})
			if !originalReadResponseVerifies(t, p) || !originalReadResponseWire(t, enrollmentCanonical(t, p)) || v["message_digest_hex"] != hex.EncodeToString(originalReadResponseMessage(t, v["response"])) || !governorObject(r, []string{"schema", "request_digest_hex", "root_signature_valid", "response_signature_valid"}) || r["schema"] != "ptlc-observation-original-read-response-result-v1" || r["root_signature_valid"] != true || r["response_signature_valid"] != true || r["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, originalReadResponseRequestDomain, p)) {
				t.Fatal("public response or complete result mismatch")
			}
		})
	}
}
func TestOriginalResponseValidMathematicsDoesNotExpandReadRules(t *testing.T) {
	vs := publicOriginalResponseFixture(t)["signed_refusal_vectors"].(map[string]interface{})
	if len(vs) != 43 {
		t.Fatal("unexpected refusal count")
	}
	for name, v := range vs {
		t.Run(name, func(t *testing.T) {
			p := v.(map[string]interface{})["request"].(map[string]interface{})
			r := p["response"].(map[string]interface{})
			k, _ := governorHex(r["source_response_key_hex"], 32)
			s, _ := governorHex(p["response_signature_hex"], 64)
			rr := governorCopy(t, p["root_envelope"])
			rr["schema"] = "ptlc-observation-source-root-request-v1"
			if !sourceRootVerifies(t, rr) || !verifies(k, originalReadResponseMessage(t, r), s) || originalReadResponseVerifies(t, p) {
				t.Fatal("signed malformed read rule was not isolated")
			}
		})
	}
}
func TestOriginalResponseEveryNestedMissingExtraAndTypedFieldRefuses(t *testing.T) {
	p := originalResponsePrimary(t)
	originalResponseObjects(p, func(path []string, o map[string]interface{}) {
		for f := range o {
			c := governorCopy(t, p)
			delete(originalResponseTarget(c, path), f)
			if originalReadResponseVerifies(t, c) {
				t.Fatal("missing field accepted")
			}
			c = governorCopy(t, p)
			originalResponseTarget(c, path)[f] = []interface{}{}
			if originalReadResponseVerifies(t, c) {
				t.Fatal("typed mutation accepted")
			}
		}
		c := governorCopy(t, p)
		originalResponseTarget(c, path)["authorized"] = true
		if originalReadResponseVerifies(t, c) {
			t.Fatal("extra privilege accepted")
		}
	}, nil)
}
func TestOriginalResponseEverySignatureByteAndScalarBoundsRefuse(t *testing.T) {
	p := originalResponsePrimary(t)
	for _, path := range [][]string{{"root_envelope", "root_signature_hex"}, {"response_signature_hex"}} {
		o := originalResponseTarget(p, path[:len(path)-1])
		f := path[len(path)-1]
		b, _ := governorHex(o[f], 64)
		for i := range b {
			sig := append([]byte{}, b...)
			sig[i] ^= 1
			c := governorCopy(t, p)
			originalResponseTarget(c, path[:len(path)-1])[f] = hex.EncodeToString(sig)
			if originalReadResponseVerifies(t, c) {
				t.Fatal("changed signature byte accepted")
			}
		}
		for _, bad := range []string{strings.Repeat("00", 64), strings.Repeat("ff", 64), strings.Repeat("AB", 64), strings.Repeat("00", 63)} {
			c := governorCopy(t, p)
			originalResponseTarget(c, path[:len(path)-1])[f] = bad
			if originalReadResponseVerifies(t, c) {
				t.Fatal("invalid signature accepted")
			}
		}
	}
}
func TestOriginalResponseWireAliasesDepthBoundsAndLegacyDomainsRefuse(t *testing.T) {
	p := originalResponsePrimary(t)
	w := string(enrollmentCanonical(t, p))
	if !originalReadResponseWire(t, []byte(w+"\n")) {
		t.Fatal("one LF refused")
	}
	for _, s := range []string{" " + w, w + "\n\n", strings.Replace(w, "\"response\":", "\"\\u0072esponse\":", 1), strings.Replace(w, "\"revision\":7", "\"revision\":7,\"revision\":7", 1), strings.Replace(w, "\"revision\":7", "\"revision\":7.0", 1), strings.Replace(w, "\"revision\":7", "\"revision\":7e0", 1), strings.Repeat("[", 512) + strings.Repeat("]", 512), strings.Repeat(" ", 16385), string([]byte{255}), ""} {
		if originalReadResponseWire(t, []byte(s)) {
			t.Fatal("noncanonical or bounded alias accepted")
		}
	}
	f := publicOriginalResponseFixture(t)
	for _, name := range []string{"wrong_plain_prefix_signature_hex", "wrong_legacy_domain_signature_hex"} {
		c := governorCopy(t, p)
		c["response_signature_hex"] = f[name]
		if originalReadResponseVerifies(t, c) {
			t.Fatal("wrong domain accepted")
		}
	}
	if originalReadResponseVerifies(t, publicSourceResponseFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"].(map[string]interface{})) {
		t.Fatal("legacy packet accepted")
	}
}
func TestOriginalResponseAlternateSignaturesRequireNewCompleteRequestResults(t *testing.T) {
	f := publicOriginalResponseFixture(t)
	p := originalResponsePrimary(t)
	old := enrollmentHash(t, originalReadResponseRequestDomain, p)
	for _, name := range []string{"alternate_root_signature_hex", "alternate_response_signature_hex"} {
		c := governorCopy(t, p)
		if name == "alternate_root_signature_hex" {
			c["root_envelope"].(map[string]interface{})["root_signature_hex"] = f[name]
		} else {
			c["response_signature_hex"] = f[name]
		}
		if !originalReadResponseVerifies(t, c) || bytes.Equal(old, enrollmentHash(t, originalReadResponseRequestDomain, c)) {
			t.Fatal("alternate signature request binding mismatch")
		}
	}
}
func TestOriginalResponseFreshChallengeCollisionsAndRestoredReplayRemainHistorical(t *testing.T) {
	vs := publicOriginalResponseFixture(t)["positive_vectors"].(map[string]interface{})
	old := originalResponsePrimary(t)
	for _, name := range []string{"new_challenge", "same_id_changed_proposal", "same_id_changed_revision", "different_id_same_proposal", "historical_different_profile", "new_head_profile", "new_incarnation", "alternate_root"} {
		if !originalReadResponseVerifies(t, vs[name].(map[string]interface{})["request"].(map[string]interface{})) || !originalReadResponseVerifies(t, old) || !originalReadResponseVerifies(t, governorCopy(t, old)) {
			t.Fatal("historical self-selection or replay refused")
		}
	}
}
