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

// Historical public command checks only; no signer, service or state mutation.
const sourceAdminDomain = "PTLC/observation-source-admin-command/v1\x00"
const sourceAdminRequestDomain = "PTLC/observation-source-admin-request/v1\x00"

func publicSourceAdminFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/source_admin_command.json")
	if err != nil {
		t.Fatal(err)
	}
	f := governorDecode(t, body)
	if len(f) != 7 || f["schema"] != "ptlc-source-admin-public-vectors-v1" {
		t.Fatal("unexpected command fixture")
	}
	return f
}

func sourceAdminProfile(p, anchor map[string]interface{}) bool {
	if len(p) != len(anchor) {
		return false
	}
	for f, v := range anchor {
		if f == "max_attempt_limit" || f == "max_target_limit" {
			if !governorNumber(p[f], 64) {
				return false
			}
			n, _ := strconv.ParseUint(string(p[f].(json.Number)), 10, 64)
			ceiling, _ := strconv.ParseUint(string(v.(json.Number)), 10, 64)
			if n > ceiling {
				return false
			}
		} else if !reflect.DeepEqual(p[f], v) {
			return false
		}
	}
	return true
}

func sourceAdminVerifies(t *testing.T, request map[string]interface{}) bool {
	t.Helper()
	if !governorObject(request, []string{"schema", "root_envelope", "command", "admin_signature_hex"}) || request["schema"] != "ptlc-observation-source-admin-request-v1" {
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
	c, ok := request["command"].(map[string]interface{})
	if !ok || !governorObject(c, []string{"schema", "purpose", "algorithm", "administration_rule", "source_context", "root_declaration_digest_hex", "administrator_role", "administrator_key_hex", "original_command_id_hex", "expected_policy_revision", "old_profile", "new_profile", "old_active", "new_active", "operation"}) || c["schema"] != "ptlc-observation-source-admin-command-v1" || c["purpose"] != "source-policy-command" || c["algorithm"] != "BIP340-SHA256" || c["administration_rule"] != "attenuate-or-revoke-v1" || c["administrator_role"] != "policy-administrator" {
		return false
	}
	if !reflect.DeepEqual(c["source_context"], d["source_context"]) || c["root_declaration_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceRootDomain, d)) || c["administrator_key_hex"] != d["delegated_keys"].(map[string]interface{})["policy_admin_key_hex"] {
		return false
	}
	if _, ok := governorHex(c["original_command_id_hex"], 32); !ok {
		return false
	}
	n, ok := c["expected_policy_revision"].(json.Number)
	if !ok {
		return false
	}
	revision, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil || revision > (1<<53)-2 || strconv.FormatUint(revision, 10) != string(n) {
		return false
	}
	old, ok := c["old_profile"].(map[string]interface{})
	if !ok {
		return false
	}
	next, ok := c["new_profile"].(map[string]interface{})
	if !ok {
		return false
	}
	anchor := d["governor_profile"].(map[string]interface{})
	if !sourceAdminProfile(old, anchor) || !sourceAdminProfile(next, anchor) || c["old_active"] != true {
		return false
	}
	active, ok := c["new_active"].(bool)
	if !ok {
		return false
	}
	switch c["operation"] {
	case "reduce-limits":
		reduced := false
		for _, f := range []string{"max_attempt_limit", "max_target_limit"} {
			a, _ := strconv.ParseUint(string(old[f].(json.Number)), 10, 64)
			b, _ := strconv.ParseUint(string(next[f].(json.Number)), 10, 64)
			if b > a {
				return false
			}
			reduced = reduced || b < a
		}
		if !active || !reduced {
			return false
		}
	case "revoke":
		if active || !reflect.DeepEqual(old, next) {
			return false
		}
	default:
		return false
	}
	k, ok := governorHex(c["administrator_key_hex"], 32)
	if !ok {
		return false
	}
	sig, ok := governorHex(request["admin_signature_hex"], 64)
	return ok && verifies(k, enrollmentHash(t, sourceAdminDomain, c), sig)
}

func sourceAdminWire(t *testing.T, wire []byte) bool {
	t.Helper()
	if len(wire) == 0 || len(wire) > 8192 {
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
	return bytes.Equal(enrollmentCanonical(t, request), wire) && sourceAdminVerifies(t, request)
}

func TestSourceAdminPublicCommandsDomainsAndCompleteResults(t *testing.T) {
	positives := publicSourceAdminFixture(t)["positive_vectors"].(map[string]interface{})
	if len(positives) != 12 {
		t.Fatal("unexpected positive count")
	}
	for name, value := range positives {
		t.Run(name, func(t *testing.T) {
			v := value.(map[string]interface{})
			r := v["request"].(map[string]interface{})
			if !sourceAdminVerifies(t, r) || !sourceAdminWire(t, enrollmentCanonical(t, r)) {
				t.Fatal("valid public command refused")
			}
			if v["message_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceAdminDomain, v["command"])) {
				t.Fatal("message mismatch")
			}
			result := v["result"].(map[string]interface{})
			if !governorObject(result, []string{"schema", "request_digest_hex", "root_signature_valid", "administrator_signature_valid"}) || result["schema"] != "ptlc-observation-source-admin-result-v1" || result["root_signature_valid"] != true || result["administrator_signature_valid"] != true || result["request_digest_hex"] != hex.EncodeToString(enrollmentHash(t, sourceAdminRequestDomain, r)) {
				t.Fatal("complete result mismatch")
			}
		})
	}
}

func TestSourceAdminValidSignaturesDoNotExpandTransitionPowers(t *testing.T) {
	refused := publicSourceAdminFixture(t)["signed_refusal_vectors"].(map[string]interface{})
	if len(refused) != 18 {
		t.Fatal("unexpected refusal count")
	}
	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			r := value.(map[string]interface{})["request"].(map[string]interface{})
			c := r["command"].(map[string]interface{})
			k, _ := governorHex(c["administrator_key_hex"], 32)
			sig, _ := governorHex(r["admin_signature_hex"], 64)
			if !verifies(k, enrollmentHash(t, sourceAdminDomain, c), sig) {
				t.Fatal("refusal vector lacks valid mathematics under its claimed key")
			}
			if sourceAdminVerifies(t, r) {
				t.Fatal("signed forbidden transition accepted")
			}
		})
	}
}

func sourceAdminPrimary(t *testing.T) map[string]interface{} {
	t.Helper()
	return publicSourceAdminFixture(t)["positive_vectors"].(map[string]interface{})["primary"].(map[string]interface{})["request"].(map[string]interface{})
}

func TestSourceAdminCompleteObjectsAndEveryFieldAreBound(t *testing.T) {
	request := sourceAdminPrimary(t)
	for _, path := range [][]string{{}, {"command"}, {"command", "source_context"}, {"command", "old_profile"}, {"command", "new_profile"}, {"root_envelope"}, {"root_envelope", "declaration"}, {"root_envelope", "declaration", "source_context"}, {"root_envelope", "declaration", "governor_profile"}, {"root_envelope", "declaration", "delegated_keys"}} {
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
				if sourceAdminVerifies(t, r) {
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
		if sourceAdminVerifies(t, r) {
			t.Fatal("extra authority claim accepted")
		}
	}
}

func TestSourceAdminWrongRoleDomainAndBothSignatureArraysRefuse(t *testing.T) {
	f := publicSourceAdminFixture(t)
	request := sourceAdminPrimary(t)
	wrong := f["wrong_role_signatures"].(map[string]interface{})
	wrong["domain"] = f["wrong_domain_admin_signature_hex"]
	for _, sig := range wrong {
		r := governorCopy(t, request)
		r["admin_signature_hex"] = sig
		if sourceAdminVerifies(t, r) {
			t.Fatal("wrong role or domain accepted")
		}
	}
	for _, path := range [][]string{{"admin_signature_hex"}, {"root_envelope", "root_signature_hex"}} {
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
			if sourceAdminVerifies(t, r) {
				t.Fatal("invalid signature accepted")
			}
		}
	}
}

func TestSourceAdminSignatureVariantsChangeCompleteRequestBinding(t *testing.T) {
	f := publicSourceAdminFixture(t)
	request := sourceAdminPrimary(t)
	for _, field := range []string{"alternate_admin_signature_hex", "alternate_root_signature_hex"} {
		r := governorCopy(t, request)
		if field == "alternate_admin_signature_hex" {
			r["admin_signature_hex"] = f[field]
		} else {
			r["root_envelope"].(map[string]interface{})["root_signature_hex"] = f[field]
		}
		if !sourceAdminVerifies(t, r) || bytes.Equal(enrollmentHash(t, sourceAdminRequestDomain, r), enrollmentHash(t, sourceAdminRequestDomain, request)) {
			t.Fatal("alternate signature complete binding failed")
		}
	}
}

func TestSourceAdminCanonicalAliasesRevisionsAndHistoricalReplay(t *testing.T) {
	request := sourceAdminPrimary(t)
	wire := enrollmentCanonical(t, request)
	for _, bad := range [][]byte{nil, []byte("\xff"), []byte(strings.Repeat(" ", 8193)), append(append([]byte{}, wire...), '\n', '\n'), append([]byte(" "), wire...), bytes.Replace(wire, []byte(`"command":`), []byte(`"\u0063ommand":`), 1), bytes.Replace(wire, []byte(`"expected_policy_revision":0`), []byte(`"expected_policy_revision":0,"expected_policy_revision":0`), 1), bytes.Replace(wire, []byte(`"expected_policy_revision":0`), []byte(`"expected_policy_revision":0e0`), 1)} {
		if sourceAdminWire(t, bad) {
			t.Fatal("noncanonical wire accepted")
		}
	}
	for _, bad := range []interface{}{true, json.Number("-1"), json.Number("0.0"), json.Number("0e0"), json.Number("9007199254740991"), "0"} {
		r := governorCopy(t, request)
		r["command"].(map[string]interface{})["expected_policy_revision"] = bad
		if sourceAdminVerifies(t, r) {
			t.Fatal("revision alias or overflow accepted")
		}
	}
	vectors := publicSourceAdminFixture(t)["positive_vectors"].(map[string]interface{})
	for _, name := range []string{"alternate_root", "alternate_admin", "new_incarnation", "new_root_revision", "new_policy_revision", "revoke"} {
		r := vectors[name].(map[string]interface{})["request"].(map[string]interface{})
		if !sourceAdminVerifies(t, r) || !sourceAdminVerifies(t, request) || !sourceAdminVerifies(t, governorCopy(t, request)) {
			t.Fatal("historical math became a freshness decision")
		}
		changed := governorCopy(t, r)
		changed["admin_signature_hex"] = request["admin_signature_hex"]
		if sourceAdminVerifies(t, changed) {
			t.Fatal("old signature followed a changed command")
		}
	}
	if !sourceAdminWire(t, append(append([]byte{}, wire...), '\n')) {
		t.Fatal("single terminator refused")
	}
}
