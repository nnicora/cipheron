package transport

// export_test.go — what this package's external tests (transport_test) need of its unexported declarations, compiled
// into its test binary only. Nothing here changes anything: a test builds its own catalog and policy from these
// (Release().With) and passes it to the readers and writers it calls.

import "github.com/nnicora/cipheron/wire/format"

// CiphertextSchemeForTest is a ciphertext scheme of format byte v for a test: the header of formats 4 and 5 (names a
// master version) or of formats 3 and 6 (names a tenant key), made with associated data or not, sealed by suite.
func CiphertextSchemeForTest(v byte, name string, names Names, aad bool, suite format.Suite, keyName string,
) format.Entry {
	var c ciphertextCodec = masterVersionHeader{aad: aad}
	if names == NamesTenantKey {
		c = tenantKeyIDHeader{aad: aad}
	}
	slot, _ := ciphertextSlot(names, aad)
	return ciphertexts.Scheme(uint32(v), name, c, format.SealedBy(suite, keyName), format.ForSlot(slot))
}

// CiphertextSlotForTest is the slot of a ciphertext whose header names names, made with associated data or not.
func CiphertextSlotForTest(names Names, aad bool) format.Slot {
	slot, _ := ciphertextSlot(names, aad)
	return slot
}

// CiphertextInfoForTest is the info the key of a ciphertext of format f is derived under, under p, before the salt:
// the codec's info with its suite's namespace.
func CiphertextInfoForTest(p *format.Policy, f byte, profile, tenant, versionID string) string {
	s, err := format.Read(p, ciphertexts, uint32(f))
	if err != nil {
		panic(err)
	}
	return s.Codec().info(s.Suite().Namespace(), profile, tenant, KeyID{MasterVersion: versionID}, nil)
}

// TenantBlobWrapInfoForTest is the info a blob's wrap key is derived under, under p, before the salt.
func TenantBlobWrapInfoForTest(p *format.Policy, profile, tenant, versionID string) string {
	s := format.Write(p, tenantKeys, 0)
	return s.Codec().info(s.Suite().Namespace(), &TenantKeyHeader{Profile: profile, Tenant: tenant,
		WrappingVersion: versionID}, nil)
}
