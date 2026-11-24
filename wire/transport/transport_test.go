package transport

import (
	"bytes"
	"errors"
	"testing"
)

func TestTheSuiteIsTheOneThePlanNames(t *testing.T) {
	if KEM().ID() != KEMID || KDF().ID() != KDFID || AEAD().ID() != AEADID {
		t.Fatalf("suite = %#x/%#x/%#x", KEM().ID(), KDF().ID(), AEAD().ID())
	}
	if KEMID != 0x0010 || KDFID != 0x0001 || AEADID != 0x0002 {
		t.Fatal("the suite identifiers are not DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM")
	}
}

// TestRoundTripBothDirections seals a request to a server key and a response to a client's one-time key.
func TestRoundTripBothDirections(t *testing.T) {
	server, _ := NewOneTimeKey()
	client, _ := NewOneTimeKey()

	info := RequestInfoTenant("credentials", OpEncrypt, "")
	enc, ct, err := Seal(server.PublicKey(), info, []byte("plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != EncLen {
		t.Fatalf("enc is %d bytes", len(enc))
	}
	pt, err := Open(server, info, enc, ct)
	if err != nil || string(pt) != "plaintext" {
		t.Fatalf("request: %q, %v", pt, err)
	}

	rinfo := ResponseInfo(Release(), "credentials", OpDecrypt)
	enc, ct, err = Seal(client.PublicKey(), rinfo, []byte("back"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err = Open(client, rinfo, enc, ct)
	if err != nil || string(pt) != "back" {
		t.Fatalf("response: %q, %v", pt, err)
	}
}

// TestTheInfoStringBindsEveryField: a payload sealed for one (profile, operation, direction) opens
// for no other.
func TestTheInfoStringBindsEveryField(t *testing.T) {
	server, _ := NewOneTimeKey()
	sealed := RequestInfoTenant("credentials", OpEncrypt, "")
	enc, ct, err := Seal(server.PublicKey(), sealed, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	others := map[string][]byte{
		"another operation (sign)": RequestInfoTenant("credentials", OpSign, ""),
		"another profile":          RequestInfoTenant("client-data", OpEncrypt, ""),
		"the response direction":   ResponseInfo(Release(), "credentials", OpEncrypt),
	}
	for name, info := range others {
		if _, err := Open(server, info, enc, ct); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: opened (%v)", name, err)
		}
	}
	// And the info strings themselves are pairwise distinct.
	all := [][]byte{sealed}
	for _, info := range others {
		all = append(all, info)
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if bytes.Equal(all[i], all[j]) {
				t.Fatalf("two contexts share the info string %q", all[i])
			}
		}
	}
}

func TestOpenRefusesWithoutNamingACause(t *testing.T) {
	server, _ := NewOneTimeKey()
	other, _ := NewOneTimeKey()
	info := RequestInfoTenant("d", OpSign, "")
	enc, ct, _ := Seal(server.PublicKey(), info, []byte("data"))

	modEnc := append([]byte(nil), enc...)
	modEnc[10] ^= 1
	modCT := append([]byte(nil), ct...)
	modCT[0] ^= 1
	cases := map[string]func() ([]byte, error){
		"the wrong key":       func() ([]byte, error) { return Open(other, info, enc, ct) },
		"a modified enc":      func() ([]byte, error) { return Open(server, info, modEnc, ct) },
		"a modified payload":  func() ([]byte, error) { return Open(server, info, enc, modCT) },
		"a short enc":         func() ([]byte, error) { return Open(server, info, enc[:64], ct) },
		"no key":              func() ([]byte, error) { return Open(nil, info, enc, ct) },
		"an empty ciphertext": func() ([]byte, error) { return Open(server, info, enc, nil) },
	}
	for name, f := range cases {
		if _, err := f(); err != ErrOpen { //nolint:errorlint // identity is the assertion: exactly ErrOpen, no cause named
			t.Errorf("%s: %v, want exactly ErrOpen", name, err)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	k, _ := NewOneTimeKey()
	b := k.PublicKey().Bytes()
	if len(b) != PublicKeyLen || b[0] != 0x04 {
		t.Fatalf("a P-256 public key serializes as an uncompressed point: %x", b)
	}
	if _, err := ParsePublicKey(b); err != nil {
		t.Fatal(err)
	}
	notOnCurve := append([]byte(nil), b...)
	notOnCurve[64] ^= 1
	for name, bad := range map[string][]byte{"empty": nil, "short": b[:33], "not on the curve": notOnCurve} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
