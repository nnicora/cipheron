package client

// tenant.go — a perTenant profile's calls. Every request names the tenant, bound into the request digest, the HPKE
// info string and so the response signature (wire/transport); in a WRAPPED profile it carries the tenant's
// key blob too, which the application stores. Every answer is verified as a shared profile's is, and more:
//
//   - CreateTenantKey's answer is signed by the profile's response key over the request (its nonce, its tenant)
//     and the blob, its public key and its fingerprint; the blob (of a version the tenant key family reads: version
//     1, the one layout) must name the profile and the tenant asked for and carry the public key and fingerprint
//     answered; a blob of any other version is ErrBadResponse;
//   - RewrapTenantKey's must be the SAME tenant key: the same key id, signing public key, fingerprint and creation
//     time as the blob sent; a blob of a version the family reads;
//   - Encrypt's and ReEncrypt's ciphertext must be in format 3 under the blob's key id (wrapped; ReEncrypt: the
//     target blob's) or in format 4 (derived);
//   - Sign's signature must verify under the key the mode says: wrapped, the blob's own signing key — sound,
//     because the answer is signed over the request, whose digest holds the blob, so cipheron answered for (and
//     opened) exactly this blob, whose header's public key is then the key inside; derived, the profile signing
//     key the answer's key id names in the profile's AUTHENTICATED list, over transport.TenantSignedMessage.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	cipheronv1 "github.com/nnicora/cipheron/proto/v1"
	"github.com/nnicora/cipheron/wire/transport"
)

// TenantKey is a tenant key as CreateTenantKey or RewrapTenantKey answered it.
type TenantKey struct {
	// Blob is the tenant key, wrapped (a version-1 blob): the application stores it with its tenant record and
	// hands it to Tenant. Deleting it — and every older blob of the same key — erases the tenant's keys.
	Blob []byte
	// KeyID is the tenant key's id (16 bytes): what its format-3 ciphertexts and its signatures name. A rewrap
	// keeps it.
	KeyID []byte
	// SigningPublicKey is the tenant key's Ed25519 public key: the tenant's signatures verify under it.
	SigningPublicKey ed25519.PublicKey
	// Fingerprint is the tenant key's fingerprint (transport.TenantFingerprint), which WithTenantFingerprint
	// pins. A rewrap keeps it.
	Fingerprint string
}

// wrappedKeys returns a perTenant wrapped profile's cached keys, and ErrTenancy for any other.
func (c *Client) wrappedKeys(ctx context.Context, profile string) (*Keys, error) {
	k, err := c.cached(ctx, profile)
	if err != nil {
		return nil, err
	}
	if !k.Tenancy.Wrapped() {
		return nil, fmt.Errorf("%w: profile %q is %s: it has no tenant key blobs", ErrTenancy, profile, k.Tenancy)
	}
	return k, nil
}

// checkBlob reads a tenant key blob a caller hands over: of this tenant in this profile, and the pinned key when
// there is a pin.
func (c *Client) checkBlob(profile, tenant string, blob []byte) (*transport.TenantKeyHeader, error) {
	if !transport.ValidTenant(tenant) {
		return nil, fmt.Errorf("%w: %s is not a tenant id (1 to %d bytes of printable ASCII, 0x21 to 0x7E)", ErrTenantKey, tenantForError(tenant),
			transport.MaxTenantLen)
	}
	h, err := transport.CheckTenantKey(transport.Release(), blob, profile, tenant)
	if err != nil {
		return nil, fmt.Errorf("%w: the blob given for tenant %q of profile %q: %w", ErrTenantKey, tenant, profile, err)
	}
	if pin, ok := c.tenantPins[tenantRef{profile, tenant}]; ok && !transport.MatchesTenantFingerprint(h, pin) {
		return nil, fmt.Errorf("%w: the blob given for tenant %q of profile %q is the key %s, not the pinned %s",
			ErrTenantKey, tenant, profile, h.Fingerprint(), pin)
	}
	return h, nil
}

// tenantKeyAnswer checks a CreateTenantKey or RewrapTenantKey answer's blob against what the answer says: a blob of
// a version the tenant key family reads — CheckTenantKey refuses any other, and the refusal is ErrBadResponse; a read
// version the family does not write is accepted, so a client that reads a version before it writes it takes the
// answers of a cipheron that writes it — of this tenant in this profile, with the public key and fingerprint answered.
func tenantKeyAnswer(profile, tenant string, blob, pub []byte, fp string) (*transport.TenantKeyHeader, error) {
	h, err := transport.CheckTenantKey(transport.Release(), blob, profile, tenant)
	if err != nil || !bytes.Equal(h.SigningPublicKey, pub) || h.Fingerprint() != fp {
		return nil, fmt.Errorf("%w: the tenant key answered for tenant %q of profile %q is not the one its answer names",
			ErrBadResponse, tenant, profile)
	}
	return h, nil
}

func tenantKeyOf(h *transport.TenantKeyHeader, blob []byte) *TenantKey {
	return &TenantKey{Blob: bytes.Clone(blob), KeyID: bytes.Clone(h.KeyID), SigningPublicKey: bytes.Clone(h.SigningPublicKey),
		Fingerprint: h.Fingerprint()}
}

// CreateTenantKey has cipheron make a new key for tenant in the perTenant wrapped profile and returns it, after
// verifying the answer: signed by the profile's response key over this request and the key, and a blob of a version
// the tenant key family reads naming the profile and tenant with the public key and fingerprint answered (else
// ErrBadResponse). Each call makes another key: store the one returned. It is never sent twice by the client itself (not even WithRetry: a second
// execution is a second key), so the caller decides whether to call again — except after cipheron's start barrier
// refusal (CIPHERON_STARTING), which says nothing ran: then it is signed again and sent once more (retry.go).
func (c *Client) CreateTenantKey(ctx context.Context, profile, tenant string) (_ *TenantKey, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	if !transport.ValidTenant(tenant) {
		return nil, fmt.Errorf("%w: %s is not a tenant id (1 to %d bytes of printable ASCII, 0x21 to 0x7E)", ErrTenantKey, tenantForError(tenant),
			transport.MaxTenantLen)
	}
	k, err := c.wrappedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	// Sent once — and once more only after cipheron's start barrier refusal, which says nothing ran (afterStart).
	return afterStart(ctx, c, profile, func(ctx context.Context) (*TenantKey, error) {
		return c.createTenantKeyOnce(ctx, profile, tenant, k)
	})
}

func (c *Client) createTenantKeyOnce(ctx context.Context, profile, tenant string, k *Keys) (*TenantKey, error) {
	nonce := newNonce()
	reqDigest := transport.ProvisionDigest(tenant)
	auth, err := c.auth(profile, transport.OpProvision, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().CreateTenantKey(ctx, &cipheronv1.CreateTenantKeyRequest{
		Profile: profile, Tenant: tenant, RequestNonce: nonce, Auth: auth,
	})
	if err != nil {
		return nil, err
	}
	blob, pub, fp := resp.GetTenantKey(), resp.GetSigningPublicKey(), resp.GetFingerprint()
	if err := c.verifyResponse(ctx, profile, k, transport.OpProvision, nonce, auth, reqDigest,
		transport.TenantKeyResponseDigest(blob, pub, fp), resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	h, err := tenantKeyAnswer(profile, tenant, blob, pub, fp)
	if err != nil {
		return nil, err
	}
	if err := c.checkWriter(profile, h.WrappingVersion, "a tenant key blob"); err != nil {
		return nil, err
	}
	return tenantKeyOf(h, blob), nil
}

// RewrapTenantKey has cipheron open tenant's key blob and return the SAME tenant key wrapped under the profile's
// current tenant-wrapping version, after verifying the answer: signed by the profile's response key over
// this request (which holds the blob sent), and a blob of a version the family reads with the same key id, signing public key,
// fingerprint and creation time (else ErrBadResponse). The old blob keeps opening while its wrapping version is listed; store the new one in its
// place. The caller's entry needs the provision operation. Like CreateTenantKey, it is never sent twice by the
// client itself, but after cipheron's start barrier refusal.
func (c *Client) RewrapTenantKey(ctx context.Context, profile, tenant string, blob []byte) (_ *TenantKey, err error) {
	defer func() { err = c.finish(ctx, profile, err) }()
	if err := c.open(); err != nil {
		return nil, err
	}
	old, err := c.checkBlob(profile, tenant, blob)
	if err != nil {
		return nil, err
	}
	if err := c.fits(profile, 2*len(blob)+len(tenant)); err != nil {
		return nil, err
	}
	k, err := c.wrappedKeys(ctx, profile)
	if err != nil {
		return nil, err
	}
	// Sent once — and once more only after cipheron's start barrier refusal, which says nothing ran (afterStart).
	return afterStart(ctx, c, profile, func(ctx context.Context) (*TenantKey, error) {
		return c.rewrapTenantKeyOnce(ctx, profile, tenant, blob, old, k)
	})
}

func (c *Client) rewrapTenantKeyOnce(ctx context.Context, profile, tenant string, blob []byte, old *transport.TenantKeyHeader,
	k *Keys) (*TenantKey, error) {
	nonce := newNonce()
	reqDigest := transport.RewrapTenantKeyDigest(tenant, blob)
	auth, err := c.auth(profile, transport.OpRewrapTenantKey, nonce, reqDigest)
	if err != nil {
		return nil, err
	}
	resp, err := c.pick().RewrapTenantKey(ctx, &cipheronv1.RewrapTenantKeyRequest{
		Profile: profile, Tenant: tenant, TenantKey: blob, RequestNonce: nonce, Auth: auth,
	})
	if err != nil {
		return nil, err
	}
	nb, pub, fp := resp.GetTenantKey(), resp.GetSigningPublicKey(), resp.GetFingerprint()
	if err := c.verifyResponse(ctx, profile, k, transport.OpRewrapTenantKey, nonce, auth, reqDigest,
		transport.TenantKeyResponseDigest(nb, pub, fp), resp.GetResponseSignature()); err != nil {
		return nil, err
	}
	h, err := rewrapAnswer(profile, tenant, old, nb, pub, fp)
	if err != nil {
		return nil, err
	}
	if err := c.checkWriter(profile, h.WrappingVersion, "a tenant key blob"); err != nil {
		return nil, err
	}
	return tenantKeyOf(h, nb), nil
}

// rewrapAnswer checks a rewrapped blob (a RewrapTenantKey answer, or a RewrapTenantKeyBatch item's) against the
// blob sent, whose header is old.
func rewrapAnswer(profile, tenant string, old *transport.TenantKeyHeader, nb, pub []byte, fp string) (*transport.TenantKeyHeader, error) {
	h, err := tenantKeyAnswer(profile, tenant, nb, pub, fp)
	if err != nil {
		return nil, err
	}
	// Both blobs parsed, so both record a creation time (transport.ParseTenantKey refuses none).
	if !transport.SameKeyID(h.KeyID, old.KeyID) || !bytes.Equal(h.SigningPublicKey, old.SigningPublicKey) ||
		fp != old.Fingerprint() || !h.Created.Equal(old.Created) {
		return nil, fmt.Errorf("%w: the rewrapped key answered for tenant %q of profile %q is not the key sent "+
			"(a rewrap keeps the key id, the signing key, the fingerprint and the creation time)", ErrBadResponse,
			tenant, profile)
	}
	return h, nil
}

// Tenant is one tenant of a perTenant profile: every call carries the tenant, and in a wrapped profile its key
// blob. Make one with Client.Tenant; it is safe for concurrent use and costs nothing to make.
type Tenant struct {
	c       *Client
	profile string
	tenant  string
	blob    []byte                     // nil for a derived profile's tenant
	h       *transport.TenantKeyHeader // blob's header
	err     error                      // the handle's refusal, answered by every call
}

// Tenant is the handle of tenant in the perTenant profile: with its key blob in a WRAPPED profile, with blob nil in
// a DERIVED one (whose tenants have no stored key). A blob is copied and read here (checkBlob) — a tenant key of
// that tenant and profile, and the key pinned for the tenant when there is a pin (WithTenantFingerprint) — and
// every call of the handle fails with ErrTenantKey when it is not, before anything is sent. That check comes
// first and needs no keys, so it holds whatever the profile's tenancy: a blob of another profile or tenant given
// for a derived profile's tenant is ErrTenantKey, not ErrTenancy. Which tenancy the profile has is learnt from its
// authenticated keys at the first call (scope): a blob that passed checkBlob, given for a derived profile, is
// ErrTenancy — such a blob names the derived profile, which never makes one: it comes from a wrapped profile of the
// same name (re-created as derived, or another deployment's) — and a nil blob for a wrapped profile ErrTenantKey.
func (c *Client) Tenant(profile, tenant string, blob []byte) *Tenant {
	t := &Tenant{c: c, profile: profile, tenant: tenant}
	switch {
	case !transport.ValidTenant(tenant):
		t.err = fmt.Errorf("%w: %s is not a tenant id (1 to %d bytes of printable ASCII, 0x21 to 0x7E)", ErrTenantKey, tenantForError(tenant), transport.MaxTenantLen)
	case blob != nil:
		t.blob = bytes.Clone(blob)
		t.h, t.err = c.checkBlob(profile, tenant, t.blob)
	}
	return t
}

// Profile and Name are the handle's profile and tenant.
func (t *Tenant) Profile() string { return t.profile }
func (t *Tenant) Name() string    { return t.tenant }

// Fingerprint is a wrapped tenant key's fingerprint as its blob says (transport.TenantFingerprint), computed here
// without cipheron: what the blob claims, which a pin (WithTenantFingerprint) or cipheron (any call with the
// blob) confirms. A derived profile's tenant has no key of its own: ErrTenancy.
func (t *Tenant) Fingerprint() (string, error) {
	if t.err != nil {
		return "", t.err
	}
	if t.h == nil {
		return "", fmt.Errorf("%w: tenant %q of profile %q has no key blob (a derived profile's tenants have none)",
			ErrTenancy, t.tenant, t.profile)
	}
	return t.h.Fingerprint(), nil
}

// scope is the handle's checks, then the profile's keys: a perTenant profile's, matching the handle (a blob for a
// wrapped profile, none for a derived one).
func (t *Tenant) scope(ctx context.Context, payload int) (scope, error) {
	if err := t.c.open(); err != nil {
		return scope{}, err
	}
	if t.err != nil {
		return scope{}, t.err
	}
	if err := t.c.fits(t.profile, payload+len(t.blob)+len(t.tenant)); err != nil {
		return scope{}, err
	}
	k, fresh, err := t.c.cachedOrFetched(ctx, t.profile)
	if err != nil {
		return scope{}, err
	}
	switch k.Tenancy {
	case transport.TenancyPerTenantWrapped:
		if t.blob == nil {
			return scope{}, fmt.Errorf("%w: tenant %q of profile %q: a wrapped profile's calls carry the tenant's key blob",
				ErrTenantKey, t.tenant, t.profile)
		}
	case transport.TenancyPerTenantDerived:
		if t.blob != nil {
			return scope{}, fmt.Errorf("%w: profile %q is %s: its tenants have no key blob (Tenant with a nil blob)",
				ErrTenancy, t.profile, k.Tenancy)
		}
	default:
		return scope{}, fmt.Errorf("%w: profile %q is %s: it has no tenants", ErrTenancy, t.profile, k.Tenancy)
	}
	return scope{profile: t.profile, k: k, tenant: t.tenant, blob: t.blob, h: t.h, fresh: fresh}, nil
}

// Encrypt has cipheron encrypt plaintext for the tenant and returns the ciphertext to store, after checking the
// answer's response signature and the ciphertext: format 3 under the blob's key (wrapped), format 4 (derived).
func (t *Tenant) Encrypt(ctx context.Context, plaintext []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	s, err := t.scope(ctx, len(plaintext)+len(co.aad)+maxCiphertextOverhead())
	if err != nil {
		return nil, err
	}
	return t.c.encrypt(ctx, s, plaintext, co)
}

// Decrypt has cipheron decrypt a ciphertext of the tenant and returns the plaintext after checking the answer's
// response signature. A ciphertext of another tenant key — another tenant's, or another key of this tenant — or
// of another tenant of a derived profile is refused by cipheron (INVALID_ARGUMENT).
func (t *Tenant) Decrypt(ctx context.Context, ciphertext []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	s, err := t.scope(ctx, len(ciphertext)+len(co.aad))
	if err != nil {
		return nil, err
	}
	return t.c.decrypt(ctx, s, ciphertext, co)
}

// ReEncrypt has cipheron decrypt a stored ciphertext of the tenant and encrypt the same plaintext again — in a
// derived profile under the current master version (to must be nil), in a wrapped profile under the
// tenant key blob to (of the same tenant: usually its new key, from CreateTenantKey; the handle's own blob to
// move nothing but the salt) — without the plaintext leaving cipheron, and returns the new ciphertext after
// checking the answer: format 4, or format 3 under to's key id (5 or 6 with associated data).
// WithTargetAssociatedData must be WithAssociatedData's: the new ciphertext keeps the binding (reencryptOpts).
func (t *Tenant) ReEncrypt(ctx context.Context, ciphertext, to []byte, opts ...CallOption) (_ []byte, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	s, err := t.scope(ctx, len(ciphertext)+len(to)+len(co.aad)+len(co.toAAD)+maxCiphertextOverhead())
	if err != nil {
		return nil, err
	}
	toHeader, err := t.target(s, to)
	if err != nil {
		return nil, err
	}
	return t.c.reencrypt(ctx, s, ciphertext, bytes.Clone(to), toHeader, co)
}

// target checks ReEncrypt's target blob to: required in a wrapped profile (the same tenant's, of this profile), refused
// in a derived one. It returns the blob's header, and nil with no error in a profile that is not wrapped: it has no target.
func (t *Tenant) target(s scope, to []byte) (*transport.TenantKeyHeader, error) {
	switch {
	case s.k.Tenancy.Wrapped() && to == nil:
		return nil, fmt.Errorf("%w: ReEncrypt for %s: a wrapped profile re-encrypts under a tenant key blob (to)", ErrTenantKey, s.who())
	case s.k.Tenancy.Wrapped():
		// Not held to the tenant's pin: the target is usually the tenant's NEW key.
		h, err := transport.CheckTenantKey(transport.Release(), to, t.profile, t.tenant)
		if err != nil {
			return nil, fmt.Errorf("%w: the target blob given for %s: %w", ErrTenantKey, s.who(), err)
		}
		return h, nil
	case to != nil:
		return nil, fmt.Errorf("%w: profile %q is %s: ReEncrypt has no target blob", ErrTenancy, t.profile, s.k.Tenancy)
	}
	return nil, nil //nolint:nilnil // target's contract: an unwrapped profile has no target header (reencrypt takes nil)
}

// Sign has cipheron sign data for the tenant and returns the signature and the id of the key that made it, after
// verifying the answer's response signature and the signature: in a wrapped profile under the blob's signing key
// (its key id the blob's), in a derived profile over transport.TenantSignedMessage under the profile signing key its
// id names in the profile's authenticated list.
func (t *Tenant) Sign(ctx context.Context, data []byte) (_ Signature, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	s, err := t.scope(ctx, len(data))
	if err != nil {
		return Signature{}, err
	}
	return t.c.sign(ctx, s, data)
}

// Verify reports whether sig is the tenant's signature over data under the key keyID: in a derived profile the
// profile signing key keyID names (over transport.TenantSignedMessage), fetched again (at most every
// minVerifyRefresh) when the cached list does not name it; in a wrapped profile the blob's signing key, when keyID is
// the blob's — the key AS THE BLOB SAYS, which a tenant pin (WithTenantFingerprint) authenticates, and so does any
// answer cipheron gave for the blob. The check itself is local.
//
// DERIVED: as Client.Verify. It answers (false, nil) only when keyID names a usable key of the profile this Client
// knows and sig does not verify under it; a key the profile revoked is ErrSigningKeyRevoked and a key of an algorithm
// this client does not implement ErrBadResponse, whatever the bytes; a list older than WithKeysMaxAge that cannot be fetched
// again is ErrKeysStale; a key id it cannot resolve is ErrUnknownSigningKey, and nothing was verified (the list not
// fetched again yet, the fetch failed, or a fresh list that does not name it).
//
// WRAPPED: the handle has exactly one key, its blob's, and nothing is ever fetched or learnt, so there is no
// "unknown yet" — and no revocation: cipheron publishes none for tenant keys (an application retires a tenant key
// itself: CreateTenantKey, ReEncrypt, then it stops accepting the old key id). (true, nil) when keyID is the
// blob's key id and sig verifies under the blob's signing key, and
// (false, nil) otherwise — a signature that does not verify, and ALSO a key id that is not the blob's. The second
// is not a verdict on the signature: a signature by another key of the tenant (its key before the service rotated
// it, or after) names that key's id and verifies with THAT key's blob. A caller that keeps several keys of a
// tenant picks the blob by the signature's key id (ReadTenantKey(blob).KeyID) before it calls Verify.
//
// The other errors are the handle's (ErrTenantKey), ErrTenancy, the first fetch of the profile's keys, ErrClosed
// and the context's.
func (t *Tenant) Verify(ctx context.Context, data, sig, keyID []byte) (_ bool, err error) {
	defer func() { err = t.c.finish(ctx, t.profile, err) }()
	s, err := t.scope(ctx, 0)
	if err != nil {
		return false, err
	}
	if s.k.Tenancy.Wrapped() {
		return transport.SameKeyID(keyID, s.h.KeyID) && Verify(s.h.SigningPublicKey, data, sig), nil
	}
	return t.c.verify(ctx, s, data, sig, keyID)
}

// TenantKeyInfo is what a tenant key blob says about itself, read without cipheron.
type TenantKeyInfo struct {
	// Version is the blob's layout version: 1 (wrapped under a key derived for this blob alone, from a salt in its
	// header); a blob of any other version is not read.
	Version          int
	Profile          string
	Tenant           string
	KeyID            []byte
	SigningPublicKey ed25519.PublicKey
	Fingerprint      string
	// WrappingVersion names the master version whose tenant-wrapping key the blob is wrapped under. RewrapTenantKey
	// moves a blob to the current one.
	WrappingVersion string
	// Created is the tenant key's creation time (every blob records one): a service applies its own rotation
	// interval to its tenant keys with it.
	Created time.Time
}

// ReadTenantKey reads a tenant key blob's header: its profile, tenant, key id, signing public key,
// fingerprint, wrapping version, and creation time. IT IS NOT AUTHENTICATED: anyone can write a blob
// header that names any public key; cipheron proves it by opening the blob (CreateTenantKey's and
// RewrapTenantKey's answers are signed over it). Use it offline where the fingerprint is pinned — compare
// Fingerprint with the one CreateTenantKey answered — or where the blob's origin is trusted.
func ReadTenantKey(blob []byte) (*TenantKeyInfo, error) {
	h, err := transport.ParseTenantKey(transport.Release(), blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTenantKey, err)
	}
	return &TenantKeyInfo{Version: int(h.Version), Profile: h.Profile, Tenant: h.Tenant, KeyID: bytes.Clone(h.KeyID),
		SigningPublicKey: bytes.Clone(h.SigningPublicKey), Fingerprint: h.Fingerprint(),
		WrappingVersion: h.WrappingVersion, Created: h.Created}, nil
}

// TenantKeyEvidence is what the erasure evidence record keeps of one tenant key blob copy (cipheron's tenancy documentation,
// "The erasure evidence record"): its header's fields, in the form the record writes them, and the SHA-256 of the blob
// itself, which names the copy read. It is read offline from the header, which is NOT authenticated
// (HeaderAuthenticated is always false, so the record says so): compare Fingerprint with the one kept from
// CreateTenantKey's answer.
type TenantKeyEvidence struct {
	Profile string `json:"profile"`
	Tenant  string `json:"tenant"`
	// Version is the blob's layout version (1).
	Version int `json:"version"`
	// KeyID is the tenant key's id, hex; Fingerprint its fingerprint ("sha256:...").
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
	// WrappingVersion names the master version whose tenant-wrapping key the copy is wrapped under: destroying that
	// master version ends the copy wherever it is kept.
	WrappingVersion string `json:"wrappingVersion"`
	// Created is the tenant key's creation time, RFC 3339 in UTC.
	Created string `json:"created"`
	// BlobSHA256 is the hex SHA-256 of the blob as read: two copies of one key (a rewrap, another region) differ here.
	BlobSHA256 string `json:"blobSha256"`
	// HeaderAuthenticated is false: the header was read without cipheron, which alone proves it by opening the blob.
	HeaderAuthenticated bool `json:"headerAuthenticated"`
}

// ReadTenantKeyEvidence reads a tenant key blob's header as an erasure evidence entry (TenantKeyEvidence), offline.
func ReadTenantKeyEvidence(blob []byte) (*TenantKeyEvidence, error) {
	info, err := ReadTenantKey(blob)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	return &TenantKeyEvidence{Profile: info.Profile, Tenant: info.Tenant, Version: info.Version,
		KeyID: hex.EncodeToString(info.KeyID), Fingerprint: info.Fingerprint, WrappingVersion: info.WrappingVersion,
		Created:    info.Created.UTC().Format(time.RFC3339),
		BlobSHA256: hex.EncodeToString(sum[:])}, nil
}

// tenantForError is an invalid tenant id as a refusal names it: quoted (%q, so no byte of it reaches a log raw), and,
// when longer than 32 bytes, only its first 32 and its length — a refusal never floods a log with what it refused.
func tenantForError(tenant string) string {
	const most = 32
	if len(tenant) <= most {
		return fmt.Sprintf("%q", tenant)
	}
	return fmt.Sprintf("%q… (%d bytes)", tenant[:most], len(tenant))
}
