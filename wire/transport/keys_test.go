package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
)

func lpJoin(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

func u32(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

func newSigningKey(t *testing.T, state SigningKeyState) (SigningKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKey{KeyID: SigningKeyID(pub), State: state, PublicKey: pub}, priv
}

func testIdentity(t *testing.T, tenancy Tenancy) (Identity, ed25519.PrivateKey) {
	t.Helper()
	hp, _ := NewOneTimeKey()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return Identity{Tenancy: tenancy, HPKE: hp.PublicKey().Bytes(), Response: pub}, priv
}

const testContext = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// testNonce is a PublicKeyRequest's request_nonce.
var testNonce = bytes.Repeat([]byte{0x5a}, NonceLen)

// TestSigningKeyID: the first 16 bytes of SHA-256(lp(label) lp(public key)), one per key.
func TestSigningKeyID(t *testing.T) {
	k, _ := newSigningKey(t, SigningKeyActive)
	sum := sha256.Sum256(lpJoin([]byte("cipheron/v1|signing-key-id"), k.PublicKey))
	if !bytes.Equal(SigningKeyID(k.PublicKey), sum[:16]) || len(k.KeyID) != SigningKeyIDLen {
		t.Fatal("SigningKeyID is not the specified derivation")
	}
	o, _ := newSigningKey(t, SigningKeyActive)
	if bytes.Equal(o.KeyID, k.KeyID) {
		t.Fatal("two keys share an id")
	}
}

// tx is a transcript a test builds from valid inputs: it fails loudly on the error.
func tx(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// keysTx is SigningKeysTranscript of a list a test made valid.
func keysTx(profile string, tenancy Tenancy, contextDigest string, nonce []byte, keys []SigningKey) []byte {
	return tx(SigningKeysTranscript(Release(), profile, tenancy, contextDigest, nonce, keys))
}

// TestSigningKeysTranscript: the specified layout (the transcript version 1 after the label), in canonical order
// whatever the order given, and different for any other version (or none), profile, tenancy, context digest, request
// nonce, key id, state (its NUMBER: a revoked key too), public key, or key added or removed.
func TestSigningKeysTranscript(t *testing.T) {
	a, _ := newSigningKey(t, SigningKeyActive)
	b, _ := newSigningKey(t, SigningKeyVerifyOnly)
	c, _ := newSigningKey(t, SigningKeyVerifyOnly)
	keys := []SigningKey{a, b, c}
	tr := keysTx("docs", TenancyShared, testContext, testNonce, keys)

	sorted := slices.Clone(keys)
	slices.SortFunc(sorted, func(x, y SigningKey) int { return bytes.Compare(x.KeyID, y.KeyID) })
	// layout is the specified layout of this list with the version field given (nil: no version field at all).
	layout := func(version []byte) []byte {
		head := [][]byte{[]byte("cipheron/v1|signed_keys")}
		if version != nil {
			head = append(head, version)
		}
		o := lpJoin(append(head, []byte("docs"), []byte("shared"), []byte(testContext), testNonce, u32(3))...)
		for _, k := range sorted {
			o = append(o, lpJoin(k.KeyID, u32(k.State.Code()), k.PublicKey)...)
		}
		return o
	}
	if !bytes.Equal(tr, layout(u32(1))) {
		t.Fatal("not the specified layout")
	}
	// Every order is one transcript, and the caller's slice is not reordered.
	for _, perm := range [][]SigningKey{{c, b, a}, {b, a, c}, {c, a, b}} {
		before := slices.Clone(perm)
		if !bytes.Equal(keysTx("docs", TenancyShared, testContext, testNonce, perm), tr) {
			t.Fatal("the order changed the transcript")
		}
		if !slices.EqualFunc(perm, before, func(x, y SigningKey) bool { return bytes.Equal(x.KeyID, y.KeyID) }) {
			t.Fatal("the caller's slice was reordered")
		}
	}
	flipped := func(f func(k *SigningKey)) []SigningKey {
		ks := []SigningKey{a, b, c}
		k := ks[1]
		k.KeyID, k.PublicKey = bytes.Clone(k.KeyID), bytes.Clone(k.PublicKey)
		f(&k)
		ks[1] = k
		return ks
	}
	kt := keysTx
	others := map[string][]byte{
		"profile":         kt("docs2", TenancyShared, testContext, testNonce, keys),
		"tenancy":         kt("docs", TenancyPerTenantDerived, testContext, testNonce, keys),
		"context digest":  kt("docs", TenancyShared, strings.Replace(testContext, "1", "2", 1), testNonce, keys),
		"key removed":     kt("docs", TenancyShared, testContext, testNonce, keys[:2]),
		"key added":       kt("docs", TenancyShared, testContext, testNonce, append(slices.Clone(keys), c)),
		"state":           kt("docs", TenancyShared, testContext, testNonce, flipped(func(k *SigningKey) { k.State = SigningKeyActive })),
		"revoked":         kt("docs", TenancyShared, testContext, testNonce, flipped(func(k *SigningKey) { k.State = SigningKeyRevoked })),
		"key id":          kt("docs", TenancyShared, testContext, testNonce, flipped(func(k *SigningKey) { k.KeyID[0] ^= 1 })),
		"public key":      kt("docs", TenancyShared, testContext, testNonce, flipped(func(k *SigningKey) { k.PublicKey[0] ^= 1 })),
		"no keys":         kt("docs", TenancyShared, testContext, testNonce, nil),
		"another nonce":   kt("docs", TenancyShared, testContext, bytes.Repeat([]byte{0x5b}, NonceLen), keys),
		"no nonce":        kt("docs", TenancyShared, testContext, nil, keys),
		"another version": layout(u32(2)),
		"version 0":       layout(u32(0)),
		"no version":      layout(nil),
	}
	for name, o := range others {
		if bytes.Equal(o, tr) {
			t.Errorf("%s: the same transcript", name)
		}
	}
	// A wrapped profile's empty list is the count 0.
	if !bytes.Equal(kt("tenants", TenancyPerTenantWrapped, testContext, testNonce, nil),
		lpJoin([]byte("cipheron/v1|signed_keys"), u32(1), []byte("tenants"), []byte("perTenantWrapped"), []byte(testContext),
			testNonce, u32(0))) {
		t.Fatal("an empty list is not the specified layout")
	}
	// Refused: a key whose state is not one of the three.
	for name, keys := range map[string][]SigningKey{
		"no state":             flipped(func(k *SigningKey) { k.State = "" }),
		"a state string":       flipped(func(k *SigningKey) { k.State = "legacy" }),
		"the digest's word":    flipped(func(k *SigningKey) { k.State = SigningKeyPublished }),
		"an unknown number's":  flipped(func(k *SigningKey) { k.State = SigningKeyStateOf(4) }),
		"UNSPECIFIED's (none)": flipped(func(k *SigningKey) { k.State = SigningKeyStateOf(0) }),
	} {
		if b, err := SigningKeysTranscript(Release(), "docs", TenancyShared, testContext, testNonce, keys); err == nil || b != nil {
			t.Errorf("%s: built", name)
		}
	}
}

// TestSigningKeyStates: the three states cipheron publishes and their wire numbers both ways, which of them a
// signature may verify under, and no state for any other number.
func TestSigningKeyStates(t *testing.T) {
	for _, c := range []struct {
		s             SigningKeyState
		code          uint32
		valid, usable bool
	}{
		{SigningKeyActive, 1, true, true},
		{SigningKeyVerifyOnly, 2, true, true},
		{SigningKeyRevoked, 3, true, false},
		{"", 0, false, false},
		{"unknown", 0, false, false},
		{"Active", 0, false, false},
		{"legacy", 0, false, false},
	} {
		if c.s.Code() != c.code || c.s.Valid() != c.valid || c.s.Usable() != c.usable {
			t.Errorf("%q: code %d valid %v usable %v", c.s, c.s.Code(), c.s.Valid(), c.s.Usable())
		}
		if c.valid && SigningKeyStateOf(c.code) != c.s {
			t.Errorf("SigningKeyStateOf(%d) is %q, not %q", c.code, SigningKeyStateOf(c.code), c.s)
		}
	}
	if SigningKeyActive != "active" || SigningKeyVerifyOnly != "verifyOnly" || SigningKeyRevoked != "revoked" {
		t.Fatal("the state strings are frozen: the keyset, the configuration and the context digest carry them")
	}
	// Any other number — UNSPECIFIED and every number past revoked — is no state: refused by every validation.
	for _, n := range []uint32{0, 4, 5, 99, 1 << 31, ^uint32(0)} {
		if s := SigningKeyStateOf(n); s != "" || s.Valid() {
			t.Errorf("%d: %q", n, s)
		}
	}
}

// otherAlgorithmKey is a signing key of an algorithm this package does not implement (5), under its own id
// (SigningKeyIDOf): the crypto-agility extension point a received list may hold.
func otherAlgorithmKey(t *testing.T, state SigningKeyState) SigningKey {
	t.Helper()
	pub := make([]byte, 40)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	return SigningKey{KeyID: SigningKeyIDOf(5, pub), State: state, PublicKey: pub, Algorithm: 5}
}

// TestValidateSigningKeys: the shapes a profile's list may have, per tenancy, and everything else refused — by the
// STRICT check (cipheron's, a keyset's) and by the RECEIVED one (a client's), which differ only in that a received
// list may hold a key of an algorithm this package does not implement. Both require one of the three states for
// every key and exactly one active key.
func TestValidateSigningKeys(t *testing.T) {
	shared, _ := testIdentity(t, TenancyShared)
	derived, _ := testIdentity(t, TenancyPerTenantDerived)
	wrapped, _ := testIdentity(t, TenancyPerTenantWrapped)
	a, _ := newSigningKey(t, SigningKeyActive)
	v, _ := newSigningKey(t, SigningKeyVerifyOnly)
	r, _ := newSigningKey(t, SigningKeyRevoked)
	mut := func(k SigningKey, f func(k *SigningKey)) SigningKey {
		k.KeyID, k.PublicKey = bytes.Clone(k.KeyID), bytes.Clone(k.PublicKey)
		f(&k)
		return k
	}

	type list struct {
		id   Identity
		keys []SigningKey
	}
	// Valid for both checks.
	for name, c := range map[string]list{
		"shared, one active":                {shared, []SigningKey{a}},
		"shared, active and verify-only":    {shared, []SigningKey{v, a}},
		"derived, one active":               {derived, []SigningKey{a}},
		"wrapped, none":                     {wrapped, nil},
		"shared, the most keys it may list": {shared, append([]SigningKey{a}, manyVerifyOnly(t, MaxSigningKeys-1)...)},
		"shared, a revoked key":             {shared, []SigningKey{r, v, a}},
		"derived, a revoked key":            {derived, []SigningKey{a, r}},
	} {
		if err := ValidateSigningKeys(c.id, c.keys); err != nil {
			t.Errorf("strict, %s: %v", name, err)
		}
		if err := ValidateReceivedSigningKeys(c.id, c.keys); err != nil {
			t.Errorf("received, %s: %v", name, err)
		}
	}
	// Valid for the received check only: a key of an algorithm this package does not implement (listed, unusable).
	for name, c := range map[string]list{
		"a verify-only key of another algorithm": {shared, []SigningKey{a, otherAlgorithmKey(t, SigningKeyVerifyOnly)}},
		"the active key of another algorithm":    {derived, []SigningKey{otherAlgorithmKey(t, SigningKeyActive), v}},
	} {
		if ValidateSigningKeys(c.id, c.keys) == nil {
			t.Errorf("strict, %s: validated", name)
		}
		if err := ValidateReceivedSigningKeys(c.id, c.keys); err != nil {
			t.Errorf("received, %s: %v", name, err)
		}
	}
	// Refused by both.
	a2, _ := newSigningKey(t, SigningKeyActive)
	for name, c := range map[string]list{
		"wrapped with a key":          {wrapped, []SigningKey{a}},
		"wrapped, a revoked key":      {wrapped, []SigningKey{r}},
		"shared, none":                {shared, nil},
		"derived, none":               {derived, nil},
		"no active":                   {shared, []SigningKey{v}},
		"the only active revoked":     {shared, []SigningKey{r}},
		"two active":                  {shared, []SigningKey{a, a2}},
		"two active and a revoked":    {shared, []SigningKey{a, a2, r}},
		"a key id not its key's":      {shared, []SigningKey{mut(a, func(k *SigningKey) { k.KeyID[0] ^= 1 })}},
		"a short key id":              {shared, []SigningKey{mut(a, func(k *SigningKey) { k.KeyID = k.KeyID[:15] })}},
		"a short public key":          {shared, []SigningKey{mut(a, func(k *SigningKey) { k.PublicKey = k.PublicKey[:31] })}},
		"a state string not known":    {shared, []SigningKey{a, mut(v, func(k *SigningKey) { k.State = "legacy" })}},
		"no state":                    {shared, []SigningKey{a, mut(v, func(k *SigningKey) { k.State = "" })}},
		"an unknown number's state":   {shared, []SigningKey{a, mut(v, func(k *SigningKey) { k.State = SigningKeyStateOf(4) })}},
		"the digest's published word": {shared, []SigningKey{a, mut(v, func(k *SigningKey) { k.State = SigningKeyPublished })}},
		"a key twice":                 {shared, []SigningKey{a, v, v}},
		"a revoked key twice":         {shared, []SigningKey{a, r, mut(r, func(k *SigningKey) { k.State = SigningKeyVerifyOnly })}},
		"too many keys":               {shared, append([]SigningKey{a}, manyVerifyOnly(t, MaxSigningKeys)...)},
	} {
		if ValidateSigningKeys(c.id, c.keys) == nil {
			t.Errorf("strict, %s: validated", name)
		}
		if ValidateReceivedSigningKeys(c.id, c.keys) == nil {
			t.Errorf("received, %s: validated", name)
		}
	}
}

func manyVerifyOnly(t *testing.T, n int) []SigningKey {
	t.Helper()
	ks := make([]SigningKey, n)
	for i := range ks {
		ks[i], _ = newSigningKey(t, SigningKeyVerifyOnly)
	}
	return ks
}

// TestProfileKeysVerify: an answer signed by the response key verifies; any change to the list, the context digest,
// the profile or the tenancy, an answer made for another request's nonce, or a signature by another key, is ErrAuth;
// a malformed answer — a list with a key in a state that is none of the three, a context digest that is not one, a
// response key of an algorithm this package does not implement — is refused before the signature is looked at. A
// list with a revoked key verifies.
func TestProfileKeysVerify(t *testing.T) {
	for _, tenancy := range []Tenancy{TenancyShared, TenancyPerTenantDerived, TenancyPerTenantWrapped} {
		id, resp := testIdentity(t, tenancy)
		var keys []SigningKey
		if tenancy.HasSigningKeys() {
			a, _ := newSigningKey(t, SigningKeyActive)
			v, _ := newSigningKey(t, SigningKeyVerifyOnly)
			keys = []SigningKey{v, a}
		}
		sign := func(profile string, d *ProfileKeys) {
			d.KeysSignature = ed25519.Sign(resp, keysTx(profile, d.Tenancy, d.ContextDigest, testNonce, d.SigningKeys))
		}
		good := ProfileKeys{Identity: id, SigningKeys: keys, ContextDigest: testContext}
		sign("docs", &good)
		if err := good.Verify(Release(), "docs", testNonce); err != nil {
			t.Fatalf("%s: %v", tenancy, err)
		}
		if act, ok := good.Active(); ok != tenancy.HasSigningKeys() || (ok && act.State != SigningKeyActive) {
			t.Fatalf("%s: Active %v %v", tenancy, act, ok)
		}
		for _, k := range keys {
			if got, ok := good.SigningKey(k.KeyID); !ok || !bytes.Equal(got.PublicKey, k.PublicKey) {
				t.Fatalf("%s: SigningKey(%x)", tenancy, k.KeyID)
			}
		}
		if _, ok := good.SigningKey(make([]byte, SigningKeyIDLen)); ok {
			t.Fatal("an unknown key id found")
		}
		if !errors.Is(good.Verify(Release(), "docs2", testNonce), ErrAuth) {
			t.Errorf("%s: verified for another profile", tenancy)
		}
		ctx := good
		ctx.ContextDigest = strings.Replace(testContext, "1", "2", 1)
		if !errors.Is(ctx.Verify(Release(), "docs", testNonce), ErrAuth) {
			t.Errorf("%s: another context digest verified", tenancy)
		}
		// An answer made for another request — a recorded one, replayed — does not verify for this one.
		if !errors.Is(good.Verify(Release(), "docs", bytes.Repeat([]byte{0x5b}, NonceLen)), ErrAuth) ||
			!errors.Is(good.Verify(Release(), "docs", nil), ErrAuth) {
			t.Errorf("%s: an answer verified for another request's nonce", tenancy)
		}
		// The transcript's version is bound: a signature over the same list under another version does not verify.
		otherVersion := good
		otherVersion.KeysSignature = ed25519.Sign(resp, signedKeysUnder(2, "docs", tenancy, testContext, testNonce, keys))
		if !errors.Is(otherVersion.Verify(Release(), "docs", testNonce), ErrAuth) {
			t.Errorf("%s: a list signed under transcript version 2 verified", tenancy)
		}
		_, other := testIdentity(t, tenancy)
		forged := good
		forged.KeysSignature = ed25519.Sign(other, keysTx("docs", tenancy, testContext, testNonce, keys))
		if !errors.Is(forged.Verify(Release(), "docs", testNonce), ErrAuth) {
			t.Errorf("%s: a list signed by another key verified", tenancy)
		}
		if tenancy.HasSigningKeys() {
			// The attacker's own key, appended (as verify-only) to a genuinely signed list.
			mine, _ := newSigningKey(t, SigningKeyVerifyOnly)
			added := good
			added.SigningKeys = append(slices.Clone(keys), mine)
			if !errors.Is(added.Verify(Release(), "docs", testNonce), ErrAuth) {
				t.Errorf("%s: a key added to the list verified", tenancy)
			}
			swapped := good
			swapped.SigningKeys = []SigningKey{keys[1], keys[0]}
			swapped.SigningKeys[0].State, swapped.SigningKeys[1].State = SigningKeyVerifyOnly, SigningKeyActive
			if !errors.Is(swapped.Verify(Release(), "docs", testNonce), ErrAuth) {
				t.Errorf("%s: another active key verified", tenancy)
			}
			// A revoked key, signed so, verifies; un-revoking it in flight does not.
			rk, _ := newSigningKey(t, SigningKeyRevoked)
			withRevoked := good
			withRevoked.SigningKeys = append(slices.Clone(keys), rk)
			sign("docs", &withRevoked)
			if err := withRevoked.Verify(Release(), "docs", testNonce); err != nil {
				t.Errorf("%s: a list with a revoked key: %v", tenancy, err)
			}
			unrevoked := withRevoked
			unrevoked.SigningKeys = slices.Clone(withRevoked.SigningKeys)
			unrevoked.SigningKeys[2].State = SigningKeyVerifyOnly
			if !errors.Is(unrevoked.Verify(Release(), "docs", testNonce), ErrAuth) {
				t.Errorf("%s: a revoked key un-revoked in flight verified", tenancy)
			}
			// A key in a state that is none of the three — as a client reads a number past revoked
			// (SigningKeyStateOf) — makes the answer malformed: refused, not verified, whatever the signature.
			unknown := withRevoked
			unknown.SigningKeys = slices.Clone(withRevoked.SigningKeys)
			unknown.SigningKeys[2].State = SigningKeyStateOf(4)
			if err := unknown.Verify(Release(), "docs", testNonce); err == nil || errors.Is(err, ErrAuth) {
				t.Errorf("%s: a key in an unknown state: %v", tenancy, err)
			}
		}
		for name, f := range map[string]func(d *ProfileKeys){
			"a malformed context digest":            func(d *ProfileKeys) { d.ContextDigest = "sha256:XY" },
			"a response key of another algorithm":   func(d *ProfileKeys) { d.ResponseAlgorithm = 5 },
			"an identity of another tenancy string": func(d *ProfileKeys) { d.Tenancy = "perTenantX" },
		} {
			bad := good
			f(&bad)
			if err := bad.Verify(Release(), "docs", testNonce); err == nil || errors.Is(err, ErrAuth) {
				t.Errorf("%s: %s: %v", tenancy, name, err)
			}
		}
	}
}

// signedKeysUnder is the signing-key transcript's layout with the version field v instead of TranscriptVersion.
func signedKeysUnder(v uint32, profile string, tenancy Tenancy, contextDigest string, nonce []byte, keys []SigningKey) []byte {
	sorted := slices.Clone(keys)
	SortSigningKeys(sorted)
	o := lpJoin([]byte("cipheron/v1|signed_keys"), u32(v), []byte(profile), []byte(tenancy), []byte(contextDigest), nonce,
		u32(uint32(len(sorted))))
	for _, k := range sorted {
		o = append(o, lpJoin(k.KeyID, u32(k.State.Code()), k.PublicKey)...)
	}
	return o
}

func kcv(b byte) []byte { return bytes.Repeat([]byte{b}, KeyCheckValueLen) }

// TestContextDigest: the specified layout; the same for any order
// of the versions and the signing keys; NOT changed by the master versions' states nor by which published signing
// key is active (an activation changes no pin: active and verifyOnly are written "published"); changed by every field
// it covers — a version's key check value, the keyset fingerprint, a signing key's id or its revocation; refusals.
// Nothing sits between the master versions and the keyset fingerprint, and the layout ends with the signing-key list.
func TestContextDigest(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	a, _ := newSigningKey(t, SigningKeyActive)
	v, _ := newSigningKey(t, SigningKeyVerifyOnly)
	base := KeyContext{
		Profile: "docs",
		Tenancy: TenancyPerTenantDerived,
		MasterVersions: []MasterVersionCheck{{ID: "v2", KCV: kcv(2)}, {ID: "legacy", KCV: kcv(0)},
			{ID: "v1", KCV: kcv(1)}},
		KeysetFingerprint: fp,
		SigningKeys:       []SigningKey{v, a},
	}
	d, err := ContextDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	sorted := []SigningKey{a, v}
	SortSigningKeys(sorted)
	want := lpJoin([]byte("cipheron/v1|context"), []byte("docs"), []byte("perTenantDerived"), u32(3),
		[]byte("legacy"), kcv(0), []byte("v1"), kcv(1), []byte("v2"), kcv(2),
		[]byte(fp), u32(2),
		sorted[0].KeyID, []byte(SigningKeyPublished), sorted[1].KeyID, []byte(SigningKeyPublished))
	sum := sha256.Sum256(want)
	if d != "sha256:"+hex.EncodeToString(sum[:]) || !ValidFingerprint(d) {
		t.Fatalf("not the specified layout: %s", d)
	}
	reordered := base
	reordered.MasterVersions = []MasterVersionCheck{base.MasterVersions[2], base.MasterVersions[0], base.MasterVersions[1]}
	reordered.SigningKeys = []SigningKey{a, v}
	if d2, _ := ContextDigest(reordered); d2 != d {
		t.Fatal("the order changed the digest")
	}
	if base.MasterVersions[0].ID != "v2" || !bytes.Equal(base.SigningKeys[0].KeyID, v.KeyID) {
		t.Fatal("the caller's slices were reordered")
	}
	change := func(f func(c *KeyContext)) KeyContext {
		c := base
		c.MasterVersions = slices.Clone(base.MasterVersions)
		c.SigningKeys = slices.Clone(base.SigningKeys)
		f(&c)
		return c
	}
	// A signing activation (another published key active) does not move it (D-Q).
	if d2, err := ContextDigest(change(func(c *KeyContext) {
		c.SigningKeys[0].State, c.SigningKeys[1].State = SigningKeyActive, SigningKeyVerifyOnly
	})); err != nil || d2 != d {
		t.Fatalf("another published key active moved the digest: %s, %s: %v", d2, d, err)
	}
	shared := func(c *KeyContext) { c.Tenancy = TenancyShared }
	sharedBase, _ := ContextDigest(change(shared))
	for name, c := range map[string]KeyContext{
		"profile":                change(func(c *KeyContext) { c.Profile = "docs2" }),
		"tenancy":                change(func(c *KeyContext) { c.Tenancy, c.SigningKeys = TenancyPerTenantWrapped, nil }),
		"a version's id":         change(func(c *KeyContext) { c.MasterVersions[2].ID = "v1b" }),
		"a version's key":        change(func(c *KeyContext) { c.MasterVersions[0].KCV = kcv(9) }),
		"a version removed":      change(func(c *KeyContext) { c.MasterVersions = c.MasterVersions[:2] }),
		"a version added":        change(func(c *KeyContext) { c.MasterVersions = append(c.MasterVersions, MasterVersionCheck{"v3", kcv(3)}) }),
		"keyset fingerprint":     change(func(c *KeyContext) { c.KeysetFingerprint = "sha256:" + strings.Repeat("ac", 32) }),
		"a signing key added":    change(func(c *KeyContext) { c.SigningKeys = append(c.SigningKeys, manyVerifyOnly(t, 1)...) }),
		"a signing key removed":  change(func(c *KeyContext) { c.SigningKeys = []SigningKey{a} }),
		"another signing key id": change(func(c *KeyContext) { c.SigningKeys[0].KeyID = bytes.Repeat([]byte{7}, SigningKeyIDLen) }),
		// A revocation changes the digest: a member whose keyset records it and one whose does not differ.
		"a signing key revoked": change(func(c *KeyContext) { c.SigningKeys[0].State = SigningKeyRevoked }),
		"a revoked key added": change(func(c *KeyContext) {
			r, _ := newSigningKey(t, SigningKeyRevoked)
			c.SigningKeys = append(c.SigningKeys, r)
		}),
	} {
		got, err := ContextDigest(c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == d {
			t.Errorf("%s: the same digest", name)
		}
	}
	// A shared one: another digest than the derived one.
	if sharedBase == "" || sharedBase == d {
		t.Errorf("a shared one: %s", sharedBase)
	}
	for name, c := range map[string]KeyContext{
		"no profile":               change(func(c *KeyContext) { c.Profile = "" }),
		"a profile with |":         change(func(c *KeyContext) { c.Profile = "do|cs" }),
		"a long profile":           change(func(c *KeyContext) { c.Profile = strings.Repeat("d", 64) }),
		"a bad tenancy":            change(func(c *KeyContext) { c.Tenancy = "perTenantX" }),
		"no version":               change(func(c *KeyContext) { c.MasterVersions = nil }),
		"a bad version id":         change(func(c *KeyContext) { c.MasterVersions[0].ID = "v|2" }),
		"a version twice":          change(func(c *KeyContext) { c.MasterVersions[1].ID = "v2" }),
		"a short check value":      change(func(c *KeyContext) { c.MasterVersions[1].KCV = kcv(1)[:15] }),
		"no check value":           change(func(c *KeyContext) { c.MasterVersions[1].KCV = nil }),
		"a bad fingerprint":        change(func(c *KeyContext) { c.KeysetFingerprint = "sha256:AB" }),
		"no signing key":           change(func(c *KeyContext) { c.SigningKeys = nil }),
		"no active signing key":    change(func(c *KeyContext) { c.SigningKeys = []SigningKey{v} }),
		"two active signing keys":  change(func(c *KeyContext) { c.SigningKeys[0].State = SigningKeyActive }),
		"a signing key twice":      change(func(c *KeyContext) { c.SigningKeys = []SigningKey{a, v, v} }),
		"a short signing key id":   change(func(c *KeyContext) { c.SigningKeys[0].KeyID = v.KeyID[:15] }),
		"a bad signing state":      change(func(c *KeyContext) { c.SigningKeys[0].State = "legacy" }),
		"an unknown signing state": change(func(c *KeyContext) { c.SigningKeys[0].State = SigningKeyStateOf(4) }),
		"the active one revoked":   change(func(c *KeyContext) { c.SigningKeys[1].State = SigningKeyRevoked }),
		"two active, one revoked": change(func(c *KeyContext) {
			c.SigningKeys[0].State = SigningKeyActive
			c.SigningKeys = append(c.SigningKeys, manyVerifyOnly(t, 1)...)
			c.SigningKeys[2].State = SigningKeyRevoked
		}),
		"signing keys, wrapped": change(func(c *KeyContext) { c.Tenancy = TenancyPerTenantWrapped }),
	} {
		if _, err := ContextDigest(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A shared profile: the minimal context.
	if _, err := ContextDigest(KeyContext{Profile: "credentials", Tenancy: TenancyShared,
		MasterVersions: []MasterVersionCheck{{"v1", kcv(0)}}, KeysetFingerprint: fp,
		SigningKeys: []SigningKey{a}}); err != nil {
		t.Fatal(err)
	}
	// A wrapped profile: no signing keys.
	if _, err := ContextDigest(KeyContext{Profile: "tenants", Tenancy: TenancyPerTenantWrapped,
		MasterVersions: []MasterVersionCheck{{"v1", kcv(1)}}, KeysetFingerprint: fp}); err != nil {
		t.Fatal(err)
	}
}

// digestState is the state string the specified layout writes for s: "published" for active and verifyOnly.
func digestState(s SigningKeyState) string {
	if s.Usable() {
		return SigningKeyPublished
	}
	return string(s)
}

// TestContextDigestRevokedKey: a revoked key is covered by its STRING "revoked" in the specified layout (not its wire
// number), next to exactly one active (written "published").
func TestContextDigestRevokedKey(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ef", 32)
	a, _ := newSigningKey(t, SigningKeyActive)
	r, _ := newSigningKey(t, SigningKeyRevoked)
	c := KeyContext{Profile: "ledger", Tenancy: TenancyShared, MasterVersions: []MasterVersionCheck{{"v1", kcv(1)}},
		KeysetFingerprint: fp, SigningKeys: []SigningKey{r, a}}
	d, err := ContextDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	sorted := []SigningKey{a, r}
	SortSigningKeys(sorted)
	want := lpJoin([]byte("cipheron/v1|context"), []byte("ledger"), []byte("shared"), u32(1), []byte("v1"), kcv(1),
		[]byte(fp), u32(2),
		sorted[0].KeyID, []byte(digestState(sorted[0].State)), sorted[1].KeyID, []byte(digestState(sorted[1].State)))
	sum := sha256.Sum256(want)
	if d != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("not the specified layout: %s", d)
	}
	if !slices.ContainsFunc(sorted, func(k SigningKey) bool { return k.State == "revoked" }) {
		t.Fatal("the revoked key's string")
	}
}

// TestContextDigestIgnoresMasterVersionStates: which listed version is active (or decryptOnly) does not change
// what can be read, so it is not an input at all — an activation, two-phase or by activateAt, keeps every pin.
// KeyContext carries the ids and check values only; the digest of a profile before and after an activation is one
// value.
func TestContextDigestIgnoresMasterVersionStates(t *testing.T) {
	fp := "sha256:" + strings.Repeat("cd", 32)
	before := KeyContext{Profile: "tenants", Tenancy: TenancyPerTenantWrapped,
		MasterVersions: []MasterVersionCheck{{"v1", kcv(1)}, {"v2", kcv(2)}}, KeysetFingerprint: fp}
	d1, err := ContextDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	// The same listed versions after v2 became active and v1 decryptOnly: the same input, the same digest.
	after := before
	after.MasterVersions = []MasterVersionCheck{{"v2", kcv(2)}, {"v1", kcv(1)}}
	if d2, _ := ContextDigest(after); d2 != d1 {
		t.Fatal("an activation (the same versions, other order) changed the digest")
	}
	// Adding or removing a version does change it.
	added := before
	added.MasterVersions = append(slices.Clone(before.MasterVersions), MasterVersionCheck{"v3", kcv(3)})
	removed := before
	removed.MasterVersions = before.MasterVersions[1:]
	for name, c := range map[string]KeyContext{"added": added, "removed": removed} {
		if d, _ := ContextDigest(c); d == d1 {
			t.Errorf("a version %s: the same digest", name)
		}
	}
}

// TestTenantSignedMessage: the specified layout; a signature for one (profile, tenant, data) verifies for no other —
// nor for the same bytes split differently between tenant and data — nor as a raw signature over the data.
func TestTenantSignedMessage(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := TenantSignedMessage("docs", "t_1", []byte("data"))
	if !bytes.Equal(msg, lpJoin([]byte("cipheron/v1|tenant-signature"), []byte("docs"), []byte("t_1"), []byte("data"))) {
		t.Fatal("not the specified layout")
	}
	sig := ed25519.Sign(priv, msg)
	if err := VerifyTenant(pub, "docs", "t_1", []byte("data"), sig); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"another tenant":  VerifyTenant(pub, "docs", "t_2", []byte("data"), sig),
		"another profile": VerifyTenant(pub, "docs2", "t_1", []byte("data"), sig),
		"other data":      VerifyTenant(pub, "docs", "t_1", []byte("datA"), sig),
		"split otherwise": VerifyTenant(pub, "docs", "t_1d", []byte("ata"), sig),
		"a short sig":     VerifyTenant(pub, "docs", "t_1", []byte("data"), sig[:63]),
		"another key":     VerifyTenant(pub[:31], "docs", "t_1", []byte("data"), sig),
	} {
		if !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ed25519.Verify(pub, []byte("data"), sig) {
		t.Fatal("a tenant-bound signature verified over the raw data")
	}
	// A raw signature over a message a caller chose to look like another tenant's is not that tenant's.
	forged := ed25519.Sign(priv, TenantSignedMessage("docs", "t_1", TenantSignedMessage("docs", "t_2", []byte("x"))))
	if VerifyTenant(pub, "docs", "t_2", []byte("x"), forged) == nil {
		t.Fatal("a nested message verified as another tenant's")
	}
}
