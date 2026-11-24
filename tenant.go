package cipheron

// tenant.go — a perTenant profile: wrapped (a key per tenant, which the application stores as a blob) or derived
// (keys derived per tenant, nothing stored).
//
//	// wrapped
//	tk, err := c.CreateTenantKey(ctx, "documents", "t_01HV…")   // the provisioning service, once per tenant
//	// store tk.Blob with the tenant's record; tk.Fingerprint may be pinned (WithTenantFingerprint)
//	t := c.Tenant("documents", "t_01HV…", blob)                // the blob read back from the tenant's record
//	// derived
//	t := c.Tenant("customers", "t_01HV…", nil)
//
//	ct, err := t.Encrypt(ctx, plaintext)
//	pt, err := t.Decrypt(ctx, ct)
//	sig, err := t.Sign(ctx, document)
//	ok, err := t.Verify(ctx, document, sig.Bytes, sig.KeyID)
//
// Deleting a wrapped tenant's blobs erases the tenant: its ciphertexts no longer decrypt and its key no longer
// signs (cipheron's cache of unwrapped tenant keys forgets the key within its ttl). A derived tenant has nothing to
// delete: its keys derive from the profile's and the tenant id, so stopping it is the application's (it no longer
// sends that tenant).
//
// ROTATION, wrapped. cipheron's tenant-wrapping key rotates with its master versions: old blobs keep
// opening while their wrapping version is listed, and RewrapTenantKey moves a blob to the current one (the same
// tenant key inside: same key id, fingerprint and signatures). The tenant's OWN key is rotated by the service:
// CreateTenantKey again, then Tenant(old blob).ReEncrypt(ctx, ct, newBlob) for each of the tenant's rows — KeyID
// names the blob a row needs — and the old blob is kept until no row needs it. ReadTenantKey reports a blob's
// creation time, for the service's own interval.
//
// A NEW TENANT KEY HAS A NEW FINGERPRINT, AND PINS ARE FIXED FOR THE CLIENT'S LIFE. A Client made with
// WithTenantFingerprint for the tenant holds the OLD key's fingerprint and cannot be given another: Tenant(new
// blob) fails every call with ErrTenantKey on that Client ("not the pinned key"), and so does RewrapTenantKey of
// the new blob. The new blob as ReEncrypt's TARGET is accepted (the target is not held to the pin), so the sweep
// above runs on the old Client; reading the moved rows needs a Client made with the new pin (or with none for
// that tenant). Plan a tenant-key rotation with that in mind: pin tenant keys only where the Clients are re-made
// when a pin changes, or leave them unpinned and protect the blobs in the store. A tenant's signatures name the
// key that made them (Signature.KeyID): after the rotation the old ones verify with the OLD blob's handle (or
// with Verify and the old key's public key). A handle of the tenant's OTHER key answers (false, nil) for them —
// "not this blob's key", not "forged": pick the blob by the signature's key id (ReadTenantKey(blob).KeyID) first.

import (
	"context"
	"crypto/ed25519"

	"github.com/nnicora/cipheron/internal/client"
)

// TenantKey is a tenant key of a wrapped profile: the blob to store, its key id, its signing public key and its
// fingerprint.
type TenantKey struct {
	// Blob is the tenant key, wrapped under the profile's tenant-wrapping key. Store it with the tenant's record:
	// cipheron keeps no copy, and every call for the tenant carries it. Deleting it (and every older blob of the
	// same key) erases the tenant's keys.
	Blob []byte
	// KeyID is the tenant key's id: what its ciphertexts (KeyID) and its signatures (Signature.KeyID) name.
	KeyID []byte
	// SigningPublicKey is the key the tenant's signatures verify under (Verify).
	SigningPublicKey ed25519.PublicKey
	// Fingerprint is what WithTenantFingerprint pins. A rewrap keeps it.
	Fingerprint string
}

func tenantKey(k *client.TenantKey) TenantKey {
	return TenantKey{Blob: k.Blob, KeyID: k.KeyID, SigningPublicKey: k.SigningPublicKey, Fingerprint: k.Fingerprint}
}

// CreateTenantKey has cipheron make a new key for tenant (1 to 2048 bytes of printable ASCII, 0x21 to 0x7E) in
// the wrapped profile — the caller's entry needs the provision operation — and returns it, verified: signed by the
// profile's response key over this request and the key. Each call makes another key: store the one returned.
func (c *Client) CreateTenantKey(ctx context.Context, profile, tenant string) (TenantKey, error) {
	k, err := c.c.CreateTenantKey(ctx, profile, tenant)
	if err != nil {
		return TenantKey{}, mapErr(ctx, err)
	}
	return tenantKey(k), nil
}

// RewrapTenantKey has cipheron move tenant's key blob to the profile's current tenant-wrapping key and returns the
// new blob — the same tenant key inside (same key id, signing key, fingerprint and creation time; checked here) —
// to store in place of the old. The caller's entry needs the provision operation. It is optional: the old blob
// keeps opening while its wrapping version is listed.
func (c *Client) RewrapTenantKey(ctx context.Context, profile, tenant string, blob []byte) (TenantKey, error) {
	k, err := c.c.RewrapTenantKey(ctx, profile, tenant, blob)
	if err != nil {
		return TenantKey{}, mapErr(ctx, err)
	}
	return tenantKey(k), nil
}

// Tenant is a tenant of a perTenant profile, with its key blob in a wrapped profile. It is safe for concurrent use
// and costs nothing to make: make one per use.
type Tenant struct {
	t *client.Tenant
}

// Tenant is the handle of tenant in the perTenant profile: blob is the tenant's key blob in a WRAPPED profile, and
// must be nil in a DERIVED one. The checks run in this order, each before the operation is sent (the second
// needs the profile's keys, which the first call in a profile fetches):
//   - here, from the blob alone: a blob that is not a tenant key blob, names another profile or tenant than the
//     handle's, or is not the key pinned for the tenant (WithTenantFingerprint) fails every call with
//     ErrTenantKey — whatever the profile's tenancy, which is not known yet: another profile's blob given for a
//     derived profile's tenant is ErrTenantKey, not ErrTenancy;
//   - at the first call, against the profile's authenticated keys: a blob that passed the checks above, given for
//     a derived profile's tenant, is ErrTenancy (a derived profile never makes one: it is a blob from a wrapped
//     profile of the same name, re-created as derived, or of another deployment); no blob (nil) for a wrapped
//     profile's tenant is ErrTenantKey.
func (c *Client) Tenant(profile, tenant string, blob []byte) *Tenant {
	return &Tenant{t: c.c.Tenant(profile, tenant, blob)}
}

// Encrypt encrypts plaintext for the tenant and returns the ciphertext to store: under the tenant key (wrapped),
// or the tenant's derived key (derived). Only the same tenant's Decrypt reads it back.
func (t *Tenant) Encrypt(ctx context.Context, plaintext []byte, opts ...CallOption) ([]byte, error) {
	ct, err := t.t.Encrypt(ctx, plaintext, opts...)
	return ct, mapErr(ctx, err)
}

// Decrypt decrypts a ciphertext of the tenant. A ciphertext of another tenant key (wrapped) or another tenant
// (derived) is ErrInvalidInput; one whose key version cipheron no longer lists, ErrKeyVersionUnavailable.
func (t *Tenant) Decrypt(ctx context.Context, ciphertext []byte, opts ...CallOption) ([]byte, error) {
	pt, err := t.t.Decrypt(ctx, ciphertext, opts...)
	return pt, mapErr(ctx, err)
}

// ReEncrypt has cipheron decrypt a stored ciphertext of the tenant and encrypt the same plaintext again, without
// the plaintext leaving cipheron: derived, under the current master version (to must be nil); wrapped,
// under the tenant key blob to — the tenant's new key (CreateTenantKey), or the handle's own blob. The caller's
// entry needs the reencrypt operation. WithTargetAssociatedData must be WithAssociatedData's, as Client.ReEncrypt's.
func (t *Tenant) ReEncrypt(ctx context.Context, ciphertext, to []byte, opts ...CallOption) ([]byte, error) {
	ct, err := t.t.ReEncrypt(ctx, ciphertext, to, opts...)
	return ct, mapErr(ctx, err)
}

// Sign signs data for the tenant and returns the signature and its key id, verified here before it is returned:
// wrapped, by the tenant key (the key id is the blob's; the signature verifies under the blob's signing key);
// derived, by the profile's active signing key over a message bound to the profile and the tenant (VerifyTenant).
func (t *Tenant) Sign(ctx context.Context, data []byte) (Signature, error) {
	s, err := t.t.Sign(ctx, data)
	return s, mapErr(ctx, err)
}

// Verify reports whether signature is the tenant's over data under the key keyID names; the check itself is
// local. Derived: the profile signing key keyID names (the Client's cached list, fetched again — at most every few
// seconds — when it does not name it). Wrapped: the blob's signing key when keyID is the blob's — the key as the
// blob says, which WithTenantFingerprint authenticates.
//
// Derived, as Client.Verify, it has three answers: (true, nil); (false, nil) when keyID names a usable key of the
// profile this Client knows and the signature does not verify under it; and an error when the signature must not be
// accepted — ErrSigningKeyRevoked for a key the profile revoked and ErrBadResponse for one of an algorithm this
// library does not implement (whatever the bytes), ErrKeysStale when the key list was older than WithKeysMaxAge and could not be
// fetched again, ErrUnknownSigningKey for a key id it could not resolve now (try again in a few seconds).
//
// Wrapped, the handle has one key and nothing to learn (and cipheron publishes no revocation of a tenant key: an
// application retires one itself — CreateTenantKey, ReEncrypt, then it stops accepting the old key id): (false,
// nil) is a signature that does not verify under
// the blob's key, AND a key id that is not the blob's — which is not a verdict on the signature: one made by
// another key of the tenant (before or after the service rotated its key) verifies with that key's blob. Pick the
// blob by the signature's key id (ReadTenantKey(blob).KeyID) before calling Verify.
//
// Both: ErrTenantKey and ErrTenancy (the handle's refusals), ErrPinRequired and the other errors of fetching the
// profile's keys, ErrClosed, the context's error.
func (t *Tenant) Verify(ctx context.Context, data, signature, keyID []byte) (bool, error) {
	ok, err := t.t.Verify(ctx, data, signature, keyID)
	return ok, mapErr(ctx, err)
}

// Fingerprint is a wrapped tenant key's fingerprint as its blob says, computed here without cipheron. A derived
// profile's tenant has none (ErrTenancy).
func (t *Tenant) Fingerprint() (string, error) {
	fp, err := t.t.Fingerprint()
	return fp, mapErr(context.Background(), err)
}

// TenantKeyInfo is what a tenant key blob says about itself: its layout version, profile, tenant, key id, signing
// public key, fingerprint, wrapping master version, and creation time.
type TenantKeyInfo = client.TenantKeyInfo

// ReadTenantKey reads a tenant key blob's header without cipheron. IT IS NOT AUTHENTICATED: a blob's header can
// name any public key, and only cipheron proves it by opening the blob. Use it offline where the tenant's
// fingerprint is pinned — compare Fingerprint with the one CreateTenantKey answered — and then verify the tenant's
// signatures with Verify; or to read a blob's wrapping version and creation time.
func ReadTenantKey(blob []byte) (*TenantKeyInfo, error) {
	info, err := client.ReadTenantKey(blob)
	if err != nil {
		return nil, mapErr(context.Background(), err)
	}
	return info, nil
}

// TenantKeyEvidence is a tenant key blob copy as the erasure evidence record keeps it: its header's fields and the
// SHA-256 of the blob (client.TenantKeyEvidence). Read offline; the header is NOT authenticated.
type TenantKeyEvidence = client.TenantKeyEvidence

// ReadTenantKeyEvidence reads a tenant key blob's header as an erasure evidence entry, without cipheron
// (`cipheron client read-tenant-key` prints it as JSON). Compare its Fingerprint with the one kept from
// CreateTenantKey's answer: the header proves nothing by itself.
func ReadTenantKeyEvidence(blob []byte) (*TenantKeyEvidence, error) {
	e, err := client.ReadTenantKeyEvidence(blob)
	if err != nil {
		return nil, mapErr(context.Background(), err)
	}
	return e, nil
}
