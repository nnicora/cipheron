package client

// statement.go — a profile's key statement for verifiers that never talk to cipheron: exported by an application
// that holds a Client, imported and checked offline against the profile's pinned fingerprint, viewed as a JWKS.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nnicora/cipheron/wire/transport"
)

// ErrKeyStatement (transport.ErrKeyStatement, the same value): a key statement that is not one, is not the profile's
// (its identity is not the pinned fingerprint's, or its signature is not its response key's), or is older than the
// maximum age the verifier allows.
var ErrKeyStatement = transport.ErrKeyStatement

// KeyStatement is a profile's verified key statement: what cipheron states about the profile's keys at IssuedAt —
// identity, tenancy, key-context digest, signing keys with their states and algorithms — signed by its response key
// without a nonce, so anyone holding the profile's fingerprint can check it offline. It proves no freshness: a
// verifier bounds its age (ImportKeyStatement's maxAge), and one that saw a key revoked keeps it revoked.
type KeyStatement struct {
	transport.KeyStatement

	// Fingerprint is the profile's fingerprint the statement verified against.
	Fingerprint string
	// Raw and Signature are the statement's bytes and the response key's signature over them.
	Raw, Signature []byte
}

// KeyStatement is the profile's key statement as this Client verified it with the profile's keys, which it asks
// cipheron for now (Keys: held to the pins in force when it returns, so a statement of a key context the pins narrowed
// away while the fetch was in flight is ErrContextDigest): the most recent statement whose signing keys are the list
// this Client holds, states included — a revocation this Client learnt from any answer is in that list for its life —
// while that statement is younger than WithKeysMaxAge (measured from when this Client verified it, on the monotonic
// clock). It NEVER hands out a statement that lists as usable a key this Client holds revoked: a replica that lags a
// revocation answers one, and an offline verifier that imported it would accept the key's signatures. When no
// statement agrees with the list, it is ErrSigningKeyRevoked if the statements this Client was answered list a key it
// holds revoked as usable, and ErrKeysStale otherwise; so is an agreeing statement older than the maximum age. Ask
// again once the replicas agree.
func (c *Client) KeyStatement(ctx context.Context, profile string) (_ *KeyStatement, err error) {
	k, err := c.Keys(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer func() { err = c.finish(ctx, profile, err) }()
	switch age := c.now().Sub(k.statementAt); {
	case k.Statement == nil && k.statementRevoked:
		return nil, fmt.Errorf("%w (profile %q): the key statements cipheron answered list as usable a signing key this "+
			"client holds revoked (a replica that lags the revocation): none is handed out", ErrSigningKeyRevoked, profile)
	case k.Statement == nil:
		return nil, fmt.Errorf("%w (profile %q): no key statement this client verified agrees with the signing-key list "+
			"it holds (states included): none is handed out", ErrKeysStale, profile)
	case age > c.keysMaxAge || age < 0:
		return nil, fmt.Errorf("%w (profile %q): the newest key statement that agrees with the signing-key list this client "+
			"holds was verified %s ago, and the maximum is %s: it is not handed out", ErrKeysStale, profile,
			age.Round(time.Second), c.keysMaxAge)
	}
	st, err := transport.VerifyKeyStatement(transport.Release(), k.Statement, k.StatementSignature, profile, k.Fingerprint)
	if err != nil {
		return nil, err
	}
	return &KeyStatement{KeyStatement: *st, Fingerprint: k.Fingerprint, Raw: bytes.Clone(k.Statement),
		Signature: bytes.Clone(k.StatementSignature)}, nil
}

// Export is the statement as a JSON document to publish: {"format": "cipheron-key-statement/1", "profile",
// "fingerprint", "statement": base64, "signature": base64}.
func (s *KeyStatement) Export() ([]byte, error) {
	return transport.ExportKeyStatement(transport.Release(), s.Profile, s.Fingerprint, s.Raw, s.Signature)
}

// ImportKeyStatement reads an exported statement (Export) and verifies it offline for profile against fingerprint —
// the profile's PINNED fingerprint, never the one the document carries: the identity inside must have it, and the
// signature must be its response key's (transport.VerifyKeyStatement). It refuses a statement issued more than
// maxAge before now (or more than a minute after it). maxAge must be positive: 0 (or less) is refused, never read as
// "any age" — a verifier that really has another way to know the statement is current says so by calling
// ImportKeyStatementAnyAge. Any failure is ErrKeyStatement.
func ImportKeyStatement(exported []byte, profile, fingerprint string, maxAge time.Duration, now time.Time) (*KeyStatement, error) {
	if maxAge <= 0 {
		return nil, fmt.Errorf("%w: maxAge is %s; it must be positive (ImportKeyStatementAnyAge checks no age)",
			ErrKeyStatement, maxAge)
	}
	return importKeyStatement(exported, profile, fingerprint, maxAge, now)
}

// ImportKeyStatementAnyAge is ImportKeyStatement WITHOUT the age check: a statement of any age that verifies is
// accepted, a statement replayed after a revocation included. Only for a verifier that has another way to know the
// statement is current (it fetched it itself, just now, from a source it trusts).
func ImportKeyStatementAnyAge(exported []byte, profile, fingerprint string) (*KeyStatement, error) {
	return importKeyStatement(exported, profile, fingerprint, 0, time.Time{})
}

// importKeyStatement is ImportKeyStatement's work; maxAge 0 checks no age.
func importKeyStatement(exported []byte, profile, fingerprint string, maxAge time.Duration, now time.Time) (*KeyStatement, error) {
	raw, sig, err := transport.ReadKeyStatementExport(transport.Release(), exported)
	switch {
	case errors.Is(err, transport.ErrKeyStatementExport):
		return nil, fmt.Errorf("%w: not an exported key statement (%s)", ErrKeyStatement,
			transport.KeyStatementExportFormat)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrKeyStatement, err)
	}
	st, err := transport.VerifyKeyStatement(transport.Release(), raw, sig, profile, fingerprint)
	if err != nil {
		return nil, err
	}
	if maxAge > 0 {
		if age := now.Sub(st.IssuedAt()); age > maxAge || age < -time.Minute {
			return nil, fmt.Errorf("%w: issued at %s, which is not within %s of %s", ErrKeyStatement,
				st.IssuedAt().UTC().Format(time.RFC3339), maxAge, now.UTC().Format(time.RFC3339))
		}
	}
	return &KeyStatement{KeyStatement: *st, Fingerprint: fingerprint, Raw: raw, Signature: sig}, nil
}

// jwk is one key of a JWKS (RFC 7517) of an Ed25519 key (RFC 8037).
type jwk struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Kid    string   `json:"kid"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
}

// JWKS is the statement's signing keys as a JSON Web Key Set (RFC 7517; OKP Ed25519 keys, RFC 8037): for each
// ACTIVE or VERIFY_ONLY Ed25519 key, {"kty": "OKP", "crv": "Ed25519", "x": base64url(public key), "kid": the hex key
// id, "alg": "EdDSA", "use": "sig", "key_ops": ["verify"]}. A REVOKED key, and one of an algorithm this client does
// not implement, is LEFT OUT: a JWKS has no way to say "listed but refused", and a consumer that finds the key would
// accept its signatures. A JWKS consumer therefore cannot tell a revoked key from an unknown one; one that must is
// given the statement itself (Verify). A wrapped profile's statement has no signing keys: its JWKS is empty. A
// derived profile's signatures are over transport.TenantSignedMessage, not the data: a JWKS consumer verifies that
// message.
func (s *KeyStatement) JWKS() ([]byte, error) {
	keys := make([]jwk, 0, len(s.SigningKeys))
	for _, k := range s.SigningKeys {
		if !k.Usable() {
			continue
		}
		keys = append(keys, jwk{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(k.PublicKey),
			Kid: hex.EncodeToString(k.KeyID), Alg: "EdDSA", Use: "sig", KeyOps: []string{"verify"}})
	}
	return json.MarshalIndent(struct {
		Keys []jwk `json:"keys"`
	}{keys}, "", "  ")
}

// Verify checks a signature of a SHARED profile under the statement's key keyID, honouring its state: (true, nil)
// only for a signature that verifies under an active or verify-only key; (false, ErrSigningKeyRevoked) for a key
// the statement lists revoked, whatever the bytes; ErrInvalidKeyList for a key of an algorithm this client does not
// implement; ErrUnknownSigningKey for a key id it does not list. A statement of a profile that is not shared is
// ErrTenancy, and nothing is verified: a derived profile's keys sign transport.TenantSignedMessage only (VerifyTenant),
// so a raw signature under one is never that profile's over the data.
func (s *KeyStatement) Verify(data, sig, keyID []byte) (bool, error) {
	if t := s.Identity.Tenancy; t != transport.TenancyShared {
		return false, fmt.Errorf("%w: the key statement of profile %q is %s: Verify checks a shared profile's signature "+
			"(VerifyTenant a derived profile's)", ErrTenancy, s.Profile, t)
	}
	return VerifyWithKeys(s.SigningKeys, data, sig, keyID)
}

// VerifyTenant is Verify for a DERIVED profile's tenant: the signature is over transport.TenantSignedMessage(profile,
// tenant, data). A statement of a profile that is not perTenant derived is ErrTenancy, and nothing is verified: a
// shared profile's keys sign the raw data, and a signature of theirs over bytes built as a TenantSignedMessage is never
// a derived profile's.
func (s *KeyStatement) VerifyTenant(tenant string, data, sig, keyID []byte) (bool, error) {
	if t := s.Identity.Tenancy; t != transport.TenancyPerTenantDerived {
		return false, fmt.Errorf("%w: the key statement of profile %q is %s: VerifyTenant checks a derived profile's "+
			"signature (Verify a shared profile's)", ErrTenancy, s.Profile, t)
	}
	return VerifyTenantWithKeys(s.SigningKeys, s.Profile, tenant, data, sig, keyID)
}
