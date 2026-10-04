package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// This is an independent public-fixture check, not an enrollment parser,
// authorization service, signer or recommendation of a production dependency.
const (
	enrollmentIntentDomain   = "PTLC/observation-enrollment-owner-intent/v1\x00"
	enrollmentRequestDomain  = "PTLC/observation-enrollment-signature-request/v1\x00"
	enrollmentResourceDomain = "PTLC/observation-retained-resource/v1\x00"
	enrollmentScopeDomain    = "PTLC/observation-authority-scope/v1\x00"
)

type enrollmentPacket struct {
	Schema       string            `json:"schema"`
	Intent       map[string]string `json:"intent"`
	SignatureHex string            `json:"signature_hex"`
}

type enrollmentVector struct {
	Intent           map[string]string `json:"intent"`
	Envelope         enrollmentPacket  `json:"envelope"`
	Request          enrollmentPacket  `json:"request"`
	MessageDigestHex string            `json:"message_digest_hex"`
	Result           struct {
		Schema           string `json:"schema"`
		RequestDigestHex string `json:"request_digest_hex"`
		SignatureValid   bool   `json:"signature_valid"`
	} `json:"result"`
}

type enrollmentFixture struct {
	enrollmentVector
	Resource                map[string]string          `json:"resource"`
	Scope                   map[string]json.RawMessage `json:"scope"`
	AlternateOwner          enrollmentVector           `json:"alternate_owner"`
	SelfSelectedSource      enrollmentVector           `json:"self_selected_source"`
	AlternateSignatureHex   string                     `json:"alternate_signature_hex"`
	WrongDomainSignatureHex string                     `json:"wrong_domain_signature_hex"`
}

func publicEnrollmentFixture(t *testing.T) enrollmentFixture {
	t.Helper()
	body, err := os.ReadFile("../qualification/fixtures/enrollment_signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture enrollmentFixture
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func enrollmentCanonical(t *testing.T, value interface{}) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func enrollmentBytesHash(domain string, body []byte) []byte {
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write(body)
	return hash.Sum(nil)
}

func enrollmentHash(t *testing.T, domain string, value interface{}) []byte {
	t.Helper()
	return enrollmentBytesHash(domain, enrollmentCanonical(t, value))
}

func copyEnrollmentIntent(intent map[string]string) map[string]string {
	copy := make(map[string]string, len(intent))
	for key, value := range intent {
		copy[key] = value
	}
	return copy
}

func scopeEnrollmentResource(t *testing.T, scope map[string]json.RawMessage) map[string]string {
	t.Helper()
	resource := map[string]string{
		"schema":        "ptlc-observation-retained-resource-v1",
		"predicate":     "zenon-completion-v1",
		"resource_kind": "exact-paired-release-v1",
	}
	for _, key := range []string{"session_id", "terms_digest_hex", "bitcoin_context_digest_hex", "zenon_context_digest_hex", "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex", "release_digest_hex"} {
		var value string
		if err := json.Unmarshal(scope[key], &value); err != nil {
			t.Fatal(err)
		}
		resource[key] = value
	}
	return resource
}

func TestEnrollmentFixtureFramingAndIndependentSignatures(t *testing.T) {
	f := publicEnrollmentFixture(t)
	for _, vector := range []struct {
		name  string
		value enrollmentVector
	}{{"primary", f.enrollmentVector}, {"alternate_owner", f.AlternateOwner}, {"self_selected_source", f.SelfSelectedSource}} {
		t.Run(vector.name, func(t *testing.T) {
			v := vector.value
			if len(v.Intent) != 8 || v.Intent["schema"] != "ptlc-observation-enrollment-intent-v1" || v.Intent["purpose"] != "observation-enrollment" || v.Intent["role"] != "enrollment-governor" || v.Intent["algorithm"] != "BIP340-SHA256" {
				t.Fatal("unexpected public intent shape")
			}
			for _, key := range []string{"resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex"} {
				if len(decode(t, v.Intent[key])) != 32 || v.Intent[key] != strings.ToLower(v.Intent[key]) {
					t.Fatal("unexpected public intent encoding")
				}
			}
			if v.Envelope.Schema != "ptlc-observation-enrollment-signature-envelope-v1" || v.Request.Schema != "ptlc-observation-enrollment-signature-request-v1" || !reflect.DeepEqual(v.Envelope.Intent, v.Intent) || !reflect.DeepEqual(v.Request.Intent, v.Intent) || v.Envelope.SignatureHex != v.Request.SignatureHex {
				t.Fatal("fixture packet does not match its intent")
			}
			message := enrollmentHash(t, enrollmentIntentDomain, v.Intent)
			if hex.EncodeToString(message) != v.MessageDigestHex {
				t.Fatal("independent intent message differs")
			}
			// Struct field order is not canonical sorted-key order. Rebuild the
			// request as a map rather than hashing json.Marshal(v.Request).
			request := map[string]interface{}{"schema": v.Request.Schema, "intent": v.Request.Intent, "signature_hex": v.Request.SignatureHex}
			if v.Result.Schema != "ptlc-observation-enrollment-signature-result-v1" || !v.Result.SignatureValid || hex.EncodeToString(enrollmentHash(t, enrollmentRequestDomain, request)) != v.Result.RequestDigestHex {
				t.Fatal("independent full request digest differs")
			}
			if !verifies(decode(t, v.Intent["owner_auth_key_hex"]), message, decode(t, v.Request.SignatureHex)) {
				t.Fatal("locked Go backend rejected public enrollment signature")
			}
		})
	}
}

func TestEnrollmentResourceAndScopeCommitments(t *testing.T) {
	f := publicEnrollmentFixture(t)
	if len(f.Scope) != 18 || !reflect.DeepEqual(scopeEnrollmentResource(t, f.Scope), f.Resource) || hex.EncodeToString(enrollmentHash(t, enrollmentResourceDomain, f.Resource)) != f.Intent["resource_digest_hex"] || hex.EncodeToString(enrollmentHash(t, enrollmentScopeDomain, f.Scope)) != f.Intent["scope_digest_hex"] {
		t.Fatal("independent resource or complete scope differs")
	}
	fields := []string{"session_id", "terms_digest_hex", "bitcoin_context_digest_hex", "zenon_context_digest_hex", "bitcoin_bundle_digest_hex", "zenon_bundle_digest_hex", "release_digest_hex", "authority_id_hex", "enrollment_id_hex", "authority_epoch", "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex", "attempt_limit", "target_limit"}
	for index, field := range fields {
		t.Run(field, func(t *testing.T) {
			scope := make(map[string]json.RawMessage, len(f.Scope))
			for key, value := range f.Scope {
				scope[key] = append(json.RawMessage(nil), value...)
			}
			if field == "authority_epoch" || field == "attempt_limit" || field == "target_limit" {
				var number int
				if err := json.Unmarshal(scope[field], &number); err != nil {
					t.Fatal(err)
				}
				scope[field] = enrollmentCanonical(t, number+1)
			} else {
				scope[field] = enrollmentCanonical(t, strings.Repeat("99", 32))
			}
			resourceDigest := hex.EncodeToString(enrollmentHash(t, enrollmentResourceDomain, scopeEnrollmentResource(t, scope)))
			scopeDigest := hex.EncodeToString(enrollmentHash(t, enrollmentScopeDomain, scope))
			if (resourceDigest != f.Intent["resource_digest_hex"]) != (index < 7) || scopeDigest == f.Intent["scope_digest_hex"] {
				t.Fatal("content and scope selections were conflated")
			}
			intent := copyEnrollmentIntent(f.Intent)
			intent["resource_digest_hex"], intent["scope_digest_hex"] = resourceDigest, scopeDigest
			if verifies(decode(t, intent["owner_auth_key_hex"]), enrollmentHash(t, enrollmentIntentDomain, intent), decode(t, f.Request.SignatureHex)) {
				t.Fatal("old signature accepted changed resource or scope")
			}
		})
	}
}

func TestEnrollmentIntentFieldAndDomainBindings(t *testing.T) {
	f := publicEnrollmentFixture(t)
	for _, field := range []string{"schema", "purpose", "role", "algorithm", "resource_digest_hex", "scope_digest_hex", "owner_auth_key_hex", "request_id_hex"} {
		t.Run(field, func(t *testing.T) {
			intent := copyEnrollmentIntent(f.Intent)
			if field == "owner_auth_key_hex" {
				intent[field] = f.AlternateOwner.Intent[field]
			} else if field == "resource_digest_hex" || field == "scope_digest_hex" || field == "request_id_hex" {
				intent[field] = strings.Repeat("99", 32)
			} else {
				intent[field] += "_changed"
			}
			message := enrollmentHash(t, enrollmentIntentDomain, intent)
			if bytes.Equal(message, decode(t, f.MessageDigestHex)) || verifies(decode(t, intent["owner_auth_key_hex"]), message, decode(t, f.Request.SignatureHex)) {
				t.Fatal("old signature accepted a changed signed field")
			}
		})
	}
	wrongDomain := "PTLC/completion-auth/signature/v1\x00"
	wrongMessage := enrollmentHash(t, wrongDomain, f.Intent)
	key := decode(t, f.Intent["owner_auth_key_hex"])
	wrongSignature := decode(t, f.WrongDomainSignatureHex)
	if !verifies(key, wrongMessage, wrongSignature) || verifies(key, decode(t, f.MessageDigestHex), wrongSignature) || verifies(key, wrongMessage, decode(t, f.Request.SignatureHex)) {
		t.Fatal("independent wrong-domain control differs")
	}
	pretty, err := json.MarshalIndent(f.Intent, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range [][]byte{enrollmentHash(t, strings.TrimSuffix(enrollmentIntentDomain, "\x00"), f.Intent), enrollmentBytesHash(enrollmentIntentDomain, pretty), enrollmentBytesHash(enrollmentIntentDomain, append(enrollmentCanonical(t, f.Intent), '\n'))} {
		if verifies(key, message, decode(t, f.Request.SignatureHex)) {
			t.Fatal("changed domain or serialized bytes accepted")
		}
	}
}

func TestEnrollmentAlternativeSignatureRequestBinding(t *testing.T) {
	f := publicEnrollmentFixture(t)
	if f.AlternateSignatureHex == f.Request.SignatureHex || !verifies(decode(t, f.Intent["owner_auth_key_hex"]), enrollmentHash(t, enrollmentIntentDomain, f.Intent), decode(t, f.AlternateSignatureHex)) {
		t.Fatal("independent alternate valid signature control differs")
	}
	request := map[string]interface{}{"schema": f.Request.Schema, "intent": f.Intent, "signature_hex": f.AlternateSignatureHex}
	if hex.EncodeToString(enrollmentHash(t, enrollmentRequestDomain, request)) == f.Result.RequestDigestHex {
		t.Fatal("stale result digest matched another valid signature request")
	}
	// Both signatures use the same signed request ID. Full transport digest
	// inequality therefore does not establish registry uniqueness or freshness.
	if request["intent"].(map[string]string)["request_id_hex"] != f.Intent["request_id_hex"] {
		t.Fatal("alternate signature unexpectedly changed the signed request ID")
	}
}

func TestEnrollmentMalformedKeysAndSignatureMutations(t *testing.T) {
	f := publicEnrollmentFixture(t)
	key, message, signature := decode(t, f.Intent["owner_auth_key_hex"]), decode(t, f.MessageDigestHex), decode(t, f.Request.SignatureHex)
	for index, badKey := range [][]byte{nil, key[:31], append(append([]byte(nil), key...), 0), make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} {
		t.Run("key_"+strconv.Itoa(index), func(t *testing.T) {
			if verifies(badKey, message, signature) {
				t.Fatal("malformed key accepted")
			}
		})
	}
	rAtFieldLimit := append(decode(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), signature[32:]...)
	sAtOrderLimit := append(append([]byte(nil), signature[:32]...), decode(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")...)
	for index, badSignature := range [][]byte{nil, signature[:63], append(append([]byte(nil), signature...), 0), make([]byte, 64), bytes.Repeat([]byte{0xff}, 64), rAtFieldLimit, sAtOrderLimit} {
		t.Run("encoding_"+strconv.Itoa(index), func(t *testing.T) {
			if verifies(key, message, badSignature) {
				t.Fatal("invalid signature length, point or scalar accepted")
			}
		})
	}
	for index := range signature {
		t.Run("signature_byte_"+strconv.Itoa(index), func(t *testing.T) {
			changed := append([]byte(nil), signature...)
			changed[index] ^= 1
			if verifies(key, message, changed) {
				t.Fatal("mutated signature accepted")
			}
		})
	}
	for _, badMessage := range [][]byte{nil, message[:31], append(append([]byte(nil), message...), 0)} {
		if verifies(key, badMessage, signature) {
			t.Fatal("historical 32-byte message boundary changed")
		}
	}
}

func TestEnrollmentReplayAndSelfSelectedAuthorityLimits(t *testing.T) {
	f := publicEnrollmentFixture(t)
	for _, vector := range []enrollmentVector{f.enrollmentVector, f.AlternateOwner, f.SelfSelectedSource} {
		if vector.Intent["request_id_hex"] != f.Intent["request_id_hex"] || vector.Intent["role"] != "enrollment-governor" {
			t.Fatal("reused ID or self-asserted role control differs")
		}
		for repeat := 0; repeat < 3; repeat++ {
			if !verifies(decode(t, vector.Intent["owner_auth_key_hex"]), enrollmentHash(t, enrollmentIntentDomain, vector.Intent), decode(t, vector.Request.SignatureHex)) {
				t.Fatal("public replay unexpectedly acquired a freshness check")
			}
		}
	}
	if reflect.DeepEqual(f.Intent, f.AlternateOwner.Intent) || f.Intent["owner_auth_key_hex"] == f.AlternateOwner.Intent["owner_auth_key_hex"] || f.Intent["resource_digest_hex"] != f.AlternateOwner.Intent["resource_digest_hex"] || reflect.DeepEqual(f.Intent, f.SelfSelectedSource.Intent) || f.Intent["resource_digest_hex"] == f.SelfSelectedSource.Intent["resource_digest_hex"] || f.Intent["scope_digest_hex"] == f.SelfSelectedSource.Intent["scope_digest_hex"] {
		t.Fatal("valid alternate intent unexpectedly matches local selection")
	}
	// Standalone mathematics accepted all three. Existing Python expectation
	// matching refuses substitution; neither result establishes governor trust.
}

func TestEnrollmentIntentSignatureDoesNotAuthenticateOuterFields(t *testing.T) {
	f := publicEnrollmentFixture(t)
	for _, change := range []string{"schema", "upper_case_signature", "extra_permission"} {
		t.Run(change, func(t *testing.T) {
			request := map[string]interface{}{"schema": f.Request.Schema, "intent": f.Intent, "signature_hex": f.Request.SignatureHex}
			switch change {
			case "schema":
				request["schema"] = f.Envelope.Schema
			case "upper_case_signature":
				request["signature_hex"] = strings.ToUpper(f.Request.SignatureHex)
			case "extra_permission":
				request["authorization"] = true
			}
			if hex.EncodeToString(enrollmentHash(t, enrollmentRequestDomain, request)) == f.Result.RequestDigestHex || !verifies(decode(t, f.Intent["owner_auth_key_hex"]), enrollmentHash(t, enrollmentIntentDomain, f.Intent), decode(t, request["signature_hex"].(string))) {
				t.Fatal("signed intent and outer framing were conflated")
			}
			// The unchanged exact application parser must refuse these packets.
			// This raw Go primitive check neither parses nor authorizes them.
		})
	}
}
