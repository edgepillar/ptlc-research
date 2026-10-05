package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Original public historical checks only; no signing or operational source.
const sourceResponseDomain = "PTLC/observation-source-response/v1\x00"
const sourceResponseRequestDomain = "PTLC/observation-source-response-request/v1\x00"
const sourceResponseClaimDomain = "PTLC/observation-policy-read-claim/v1\x00"
const sourceReadQueryDomain = "PTLC/observation-policy-read-query/v1\x00"
const sourceContextDomain = "PTLC/observation-policy-source-context/v1\x00"

var responseBinding = []string{"session_id", "terms_digest_hex", "bitcoin_context_digest_hex", "zenon_context_digest_hex", "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex", "release_digest_hex"}

func publicSourceResponseFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/source_response.json")
	if err != nil {
		t.Fatal(err)
	}
	f := governorDecode(t, body)
	if len(f) != 7 || f["schema"] != "ptlc-source-response-public-vectors-v1" {
		t.Fatal("unexpected response fixture")
	}
	return f
}
func responseNumber(value interface{}, min, max uint64) bool {
	n, ok := value.(json.Number)
	if !ok {
		return false
	}
	i, err := strconv.ParseUint(string(n), 10, 64)
	return err == nil && min <= i && i <= max && strconv.FormatUint(i, 10) == string(n)
}
func responseCheckpoint(value interface{}) bool {
	m, ok := value.(map[string]interface{})
	if !ok || !governorObject(m, []string{"revision", "policy_state_digest_hex"}) || !responseNumber(m["revision"], 0, (1<<53)-1) {
		return false
	}
	_, ok = governorHex(m["policy_state_digest_hex"], 32)
	return ok
}
func responseQuery(t *testing.T, value interface{}, d map[string]interface{}) bool {
	t.Helper()
	q, ok := value.(map[string]interface{})
	if !ok || !governorObject(q, []string{"schema", "operation", "source_context", "expected_checkpoint", "challenge_hex", "governor_signature_request", "decoded_scope", "retained_resource"}) || q["schema"] != "ptlc-observation-policy-read-query-v1" || q["operation"] != "read-assignment-at-checkpoint" || !reflect.DeepEqual(q["source_context"], d["source_context"]) || !responseCheckpoint(q["expected_checkpoint"]) {
		return false
	}
	if _, ok := governorHex(q["challenge_hex"], 32); !ok {
		return false
	}
	g, ok := q["governor_signature_request"].(map[string]interface{})
	if !ok || !governorVerifies(t, g) {
		return false
	}
	a := g["assignment"].(map[string]interface{})
	i := g["bound_intent"].(map[string]interface{})
	p := d["governor_profile"].(map[string]interface{})
	if !reflect.DeepEqual(a["governor_profile"], p) || a["issuer_auth_key_hex"] != d["delegated_keys"].(map[string]interface{})["governor_issuer_key_hex"] {
		return false
	}
	s, ok := q["decoded_scope"].(map[string]interface{})
	if !ok {
		return false
	}
	r, ok := q["retained_resource"].(map[string]interface{})
	if !ok {
		return false
	}
	sf := append([]string{"schema", "predicate", "authority_id_hex", "enrollment_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex", "attempt_limit", "target_limit"}, responseBinding...)
	rf := append([]string{"schema", "predicate", "resource_kind"}, responseBinding...)
	if !governorObject(s, sf) || s["schema"] != "ptlc-observation-authority-scope-v1" || s["predicate"] != "zenon-completion-v1" || !governorObject(r, rf) || r["schema"] != "ptlc-observation-retained-resource-v1" || r["predicate"] != s["predicate"] || r["resource_kind"] != "exact-paired-release-v1" {
		return false
	}
	for _, f := range sf[2:] {
		if f != "authority_epoch" && f != "attempt_limit" && f != "target_limit" {
			if _, ok := governorHex(s[f], 32); !ok {
				return false
			}
		}
	}
	if !responseNumber(s["authority_epoch"], 1, (1<<53)-1) {
		return false
	}
	for f, cap := range map[string]string{"attempt_limit": "max_attempt_limit", "target_limit": "max_target_limit"} {
		n, _ := strconv.ParseUint(string(p[cap].(json.Number)), 10, 64)
		if !responseNumber(s[f], 1, n) {
			return false
		}
	}
	for _, f := range []string{"authority_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"} {
		if !reflect.DeepEqual(s[f], p[f]) {
			return false
		}
	}
	for _, f := range responseBinding {
		if _, ok := governorHex(r[f], 32); !ok || r[f] != s[f] {
			return false
		}
	}
	return i["scope_digest_hex"] == hex.EncodeToString(enrollmentHash(t, "PTLC/observation-authority-scope/v1\x00", s)) && i["resource_digest_hex"] == hex.EncodeToString(enrollmentHash(t, "PTLC/observation-retained-resource/v1\x00", r))
}
func responseClaim(t *testing.T, value interface{}, q map[string]interface{}) bool {
	t.Helper()
	c, ok := value.(map[string]interface{})
	if !ok || !governorObject(c, []string{"schema", "query_digest_hex", "source_context_digest_hex", "challenge_hex", "observation", "claimed_checkpoint", "assignment_digest_hex"}) || c["schema"] != "ptlc-observation-policy-read-claim-v1" || c["query_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceReadQueryDomain, q)) || c["source_context_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceContextDomain, q["source_context"])) || c["challenge_hex"] != q["challenge_hex"] {
		return false
	}
	if c["observation"] == "unavailable" {
		return c["claimed_checkpoint"] == nil && c["assignment_digest_hex"] == nil
	}
	if !responseCheckpoint(c["claimed_checkpoint"]) || !reflect.DeepEqual(c["claimed_checkpoint"], q["expected_checkpoint"]) {
		return false
	}
	switch c["observation"] {
	case "absent":
		return c["assignment_digest_hex"] == nil
	case "active", "revoked":
		return c["assignment_digest_hex"] == q["governor_signature_request"].(map[string]interface{})["bound_intent"].(map[string]interface{})["governor_assignment_digest_hex"]
	default:
		return false
	}
}
func sourceResponseVerifies(t *testing.T, request map[string]interface{}) bool {
	t.Helper()
	if !governorObject(request, []string{"schema", "root_envelope", "response", "response_signature_hex"}) || request["schema"] != "ptlc-observation-source-response-request-v1" {
		return false
	}
	s, ok := request["root_envelope"].(map[string]interface{})
	if !ok || !governorObject(s, []string{"schema", "declaration", "root_signature_hex"}) || s["schema"] != "ptlc-observation-source-root-envelope-v1" {
		return false
	}
	rootRequest := governorCopy(t, s)
	rootRequest["schema"] = "ptlc-observation-source-root-request-v1"
	if !sourceRootVerifies(t, rootRequest) {
		return false
	}
	d := s["declaration"].(map[string]interface{})
	r, ok := request["response"].(map[string]interface{})
	if !ok || !governorObject(r, []string{"schema", "purpose", "algorithm", "read_rule", "root_declaration_digest_hex", "source_response_role", "source_response_key_hex", "source_context", "query", "claim", "claim_digest_hex"}) || r["schema"] != "ptlc-observation-source-response-v1" || r["purpose"] != "source-checkpoint-response" || r["algorithm"] != "BIP340-SHA256" || r["read_rule"] != "exact-profile-checkpoint-read-v1" || r["source_response_role"] != "checkpoint-responder" {
		return false
	}
	if r["root_declaration_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceRootDomain, d)) || r["source_response_key_hex"] != d["delegated_keys"].(map[string]interface{})["source_response_key_hex"] || !reflect.DeepEqual(r["source_context"], d["source_context"]) || !responseQuery(t, r["query"], d) {
		return false
	}
	if !responseClaim(t, r["claim"], r["query"].(map[string]interface{})) || r["claim_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceResponseClaimDomain, r["claim"])) {
		return false
	}
	k, ok := governorHex(r["source_response_key_hex"], 32)
	if !ok {
		return false
	}
	sig, ok := governorHex(request["response_signature_hex"], 64)
	return ok && verifies(k, enrollmentHash(t, sourceResponseDomain, r), sig)
}
func sourceResponseWire(t *testing.T, wire []byte) bool {
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
	var request map[string]interface{}
	if err := decoder.Decode(&request); err != nil {
		return false
	}
	return bytes.Equal(enrollmentCanonical(t, request), wire) && sourceResponseVerifies(t, request)
}

func TestSourceResponsePublicResponsesDomainsAndCompleteResults(t *testing.T) {
	positives := publicSourceResponseFixture(t)["positive_vectors"].(map[string]interface{})
	if len(positives) != 17 {
		t.Fatal("unexpected positive count")
	}
	for name, value := range positives {
		t.Run(name, func(t *testing.T) {
			v := value.(map[string]interface{})
			r := v["request"].(map[string]interface{})
			if !sourceResponseVerifies(t, r) || !sourceResponseWire(t, enrollmentCanonical(t, r)) {
				t.Fatal("valid public response refused")
			}
			if v["message_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceResponseDomain, v["response"])) {
				t.Fatal("message mismatch")
			}
			result := v["result"].(map[string]interface{})
			if !governorObject(result, []string{"schema", "request_digest_hex", "root_signature_valid", "issuer_signature_valid", "owner_signature_valid", "response_signature_valid"}) || result["schema"] != "ptlc-observation-source-response-result-v1" || result["root_signature_valid"] != true || result["response_signature_valid"] != true || result["issuer_signature_valid"] != true || result["owner_signature_valid"] != true || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceResponseRequestDomain, r)) {
				t.Fatal("complete result mismatch")
			}
		})
	}
}

func TestSourceResponseValidSignaturesDoNotExpandReadPowers(t *testing.T) {
	refused := publicSourceResponseFixture(t)["signed_refusal_vectors"].(map[string]interface{})
	if len(refused) != 25 {
		t.Fatal("unexpected refusal count")
	}
	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			r := value.(map[string]interface{})["request"].(map[string]interface{})
			c := r["response"].(map[string]interface{})
			k, _ := governorHex(c["source_response_key_hex"], 32)
			sig, _ := governorHex(r["response_signature_hex"], 64)
			if !verifies(k, enrollmentHash(t, sourceResponseDomain, c), sig) {
				t.Fatal("refusal vector lacks valid mathematics under its claimed key")
			}
			if sourceResponseVerifies(t, r) {
				t.Fatal("signed forbidden read accepted")
			}
		})
	}
}

func sourceResponsePrimary(t *testing.T) map[string]interface{} {
	t.Helper()
	return publicSourceResponseFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"].(map[string]interface{})
}

func TestSourceResponseCompleteObjectsAndEveryFieldAreBound(t *testing.T) {
	request := sourceResponsePrimary(t)
	for _, path := range [][]string{{}, {"response"}, {"response", "source_context"}, {"response", "query"}, {"response", "query", "source_context"}, {"response", "query", "expected_checkpoint"}, {"response", "query", "governor_signature_request"}, {"response", "query", "governor_signature_request", "assignment"}, {"response", "query", "governor_signature_request", "assignment", "governor_profile"}, {"response", "query", "governor_signature_request", "bound_intent"}, {"response", "query", "decoded_scope"}, {"response", "query", "retained_resource"}, {"response", "claim"}, {"response", "claim", "claimed_checkpoint"}, {"root_envelope"}, {"root_envelope", "declaration"}, {"root_envelope", "declaration", "source_context"}, {"root_envelope", "declaration", "governor_profile"}, {"root_envelope", "declaration", "delegated_keys"}} {
		old := request
		for _, p := range path {
			old = old[p].(map[string]interface{})
		}
		for field := range old {
			for _, mode := range []string{"missing", "changed", "wrong-type"} {
				r := governorCopy(t, request)
				target := r
				for _, p := range path {
					target = target[p].(map[string]interface{})
				}
				switch mode {
				case "missing":
					delete(target, field)
				case "changed":
					target[field] = strings.Repeat("ee", 32)
				case "wrong-type":
					target[field] = nil
				}
				if sourceResponseVerifies(t, r) {
					t.Fatalf("unbound %v/%s/%s", path, field, mode)
				}
			}
		}
		r := governorCopy(t, request)
		target := r
		for _, p := range path {
			target = target[p].(map[string]interface{})
		}
		target["authorized"] = true
		if sourceResponseVerifies(t, r) {
			t.Fatal("extra authority claim accepted")
		}
	}
}

func TestSourceResponseWrongRoleDomainAndBothSignatureArraysRefuse(t *testing.T) {
	f := publicSourceResponseFixture(t)
	request := sourceResponsePrimary(t)
	wrong := f["wrong_role_signatures"].(map[string]interface{})
	wrong["domain"] = f["wrong_domain_response_signature_hex"]
	for _, sig := range wrong {
		r := governorCopy(t, request)
		r["response_signature_hex"] = sig
		if sourceResponseVerifies(t, r) {
			t.Fatal("wrong role or domain accepted")
		}
	}
	for _, path := range [][]string{{"response_signature_hex"}, {"root_envelope", "root_signature_hex"}, {"response", "query", "governor_signature_request", "issuer_signature_hex"}, {"response", "query", "governor_signature_request", "owner_signature_hex"}} {
		old := request
		for _, p := range path[:len(path)-1] {
			old = old[p].(map[string]interface{})
		}
		original, _ := hex.DecodeString(old[path[len(path)-1]].(string))
		bad := []string{strings.Repeat("00", 64), strings.Repeat("ff", 64), strings.Repeat("ff", 32) + strings.Repeat("00", 32), strings.Repeat("00", 32) + strings.Repeat("ff", 32)}
		for i := range original {
			s := append([]byte{}, original...)
			s[i] ^= 1
			bad = append(bad, hex.EncodeToString(s))
		}
		for _, sig := range bad {
			r := governorCopy(t, request)
			target := r
			for _, p := range path[:len(path)-1] {
				target = target[p].(map[string]interface{})
			}
			target[path[len(path)-1]] = sig
			if sourceResponseVerifies(t, r) {
				t.Fatal("invalid signature accepted")
			}
		}
	}
}

func TestSourceResponseSignatureVariantsChangeCompleteRequestBinding(t *testing.T) {
	f := publicSourceResponseFixture(t)
	request := sourceResponsePrimary(t)
	for _, field := range []string{"alternate_response_signature_hex", "alternate_root_signature_hex"} {
		r := governorCopy(t, request)
		if field == "alternate_response_signature_hex" {
			r["response_signature_hex"] = f[field]
		} else {
			r["root_envelope"].(map[string]interface{})["root_signature_hex"] = f[field]
		}
		if !sourceResponseVerifies(t, r) || bytes.Equal(enrollmentHash(t, sourceResponseRequestDomain, r), enrollmentHash(t, sourceResponseRequestDomain, request)) {
			t.Fatal("alternate signature complete binding failed")
		}
	}
}

func TestSourceResponseCanonicalAliasesRevisionsAndHistoricalReplay(t *testing.T) {
	request := sourceResponsePrimary(t)
	wire := enrollmentCanonical(t, request)
	for _, bad := range [][]byte{nil, []byte("\xff"), []byte(strings.Repeat(" ", 16385)), append(append([]byte{}, wire...), '\n', '\n'), append([]byte(" "), wire...), bytes.Replace(wire, []byte(`"response":`), []byte(`"\u0072esponse":`), 1), bytes.Replace(wire, []byte(`"revision":0`), []byte(`"revision":0,"revision":0`), 1), bytes.Replace(wire, []byte(`"revision":0`), []byte(`"revision":0e0`), 1)} {
		if sourceResponseWire(t, bad) {
			t.Fatal("noncanonical wire accepted")
		}
	}
	for _, bad := range []interface{}{true, json.Number("-1"), json.Number("0.0"), json.Number("0e0"), json.Number("9007199254740992"), "0"} {
		r := governorCopy(t, request)
		r["response"].(map[string]interface{})["query"].(map[string]interface{})["expected_checkpoint"].(map[string]interface{})["revision"] = bad
		if sourceResponseVerifies(t, r) {
			t.Fatal("revision alias or overflow accepted")
		}
	}
	vectors := publicSourceResponseFixture(t)["positive_vectors"].(map[string]interface{})
	for _, name := range []string{"alternate_root", "alternate_admin", "new_incarnation", "new_root_revision", "new_checkpoint", "revoked"} {
		r := vectors[name].(map[string]interface{})["request"].(map[string]interface{})
		if !sourceResponseVerifies(t, r) || !sourceResponseVerifies(t, request) || !sourceResponseVerifies(t, governorCopy(t, request)) {
			t.Fatal("historical math became a freshness decision")
		}
		changed := governorCopy(t, r)
		changed["response_signature_hex"] = request["response_signature_hex"]
		if sourceResponseVerifies(t, changed) {
			t.Fatal("old signature followed a changed response")
		}
	}
	if !sourceResponseWire(t, append(append([]byte{}, wire...), '\n')) {
		t.Fatal("single terminator refused")
	}
}
