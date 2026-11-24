package transport

// transcripts.go — the transcript kind (catalog.go): every transcript cipheron and its clients sign or seal binds the
// transcript version at a fixed position, so that nothing signed or sealed under one version's layouts is ever taken
// for another's. A writer builds each with the version its policy writes; a verifier rebuilds it under each version
// its policy reads, the written one first (format.Each).

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"

	"github.com/nnicora/cipheron/wire/format"
)

// TranscriptVersion is the transcript version this release writes and reads, the transcript kind's one version. It
// is not negotiated and travels in no request or answer: a writer builds every transcript with the version its policy
// writes, and a verifier rebuilds it under each version its policy reads (the written one first). Each transcript
// binds it as a 4-byte field at a fixed position — right after the label in RequestTranscript, ResponseTranscript and
// SigningKeysTranscript, right after the context string in a request payload's HPKE info (RequestSealInfo) and in a
// Decrypt answer's (ResponseInfoTenant). A later layout of any of them is a later number, so no signature or seal of
// this one verifies or opens as that one's.
//
// Every versioned kind — these transcripts, the key statement (KeyStatementVersion), the tenant key blob
// (TenantKeyVersion), the segmented payload (SegmentedVersion) and cipheron's keyset file — takes 1 as its first
// released number, and a later layout of any of them takes a later number.
const TranscriptVersion uint32 = 1

// writtenTranscripts is the transcript scheme p writes.
func writtenTranscripts(p *format.Policy) *format.Scheme[transcriptCodec] {
	return format.Write(p, transcripts, 0)
}

// WrittenTranscriptVersion is the transcript version p writes: every transcript and seal info built under p binds it
// (a conformance vectors file is of it).
func WrittenTranscriptVersion(p *format.Policy) uint32 { return writtenTranscripts(p).Version() }

// EachRequestTranscript calls verifies with the request transcript (RequestTranscript) of the request under each
// transcript version p reads — the written one first — until it reports true; it reports whether one did. A verifier
// of RequestAuth.signature checks the signature in verifies.
func EachRequestTranscript(p *format.Policy, profile string, op Operation, timestampMS int64, nonce []byte,
	digest [sha256.Size]byte, verifies func(transcript []byte) bool,
) bool {
	for s := range format.Each(p, transcripts) {
		if verifies(s.Codec().request(s.Version(), profile, op, timestampMS, nonce, digest)) {
			return true
		}
	}
	return false
}

// VerifyResponseSignature checks a response_signature: pub's signature over the response transcript
// (ResponseTranscript) of the answer under any transcript version p reads. Any failure is ErrAuth.
func VerifyResponseSignature(p *format.Policy, pub ed25519.PublicKey, signature []byte, profile, contextDigest string,
	op Operation, requestNonce, requestSignature []byte, requestDigest, responseDigest [sha256.Size]byte,
) error {
	requester := Requester(requestSignature)
	for s := range format.Each(p, transcripts) {
		if verify(pub, s.Codec().response(s.Version(), profile, contextDigest, op, requestNonce, requester,
			requestDigest, responseDigest), signature) == nil {
			return nil
		}
	}
	return ErrAuth
}

// VerifyReceivedSigningKeys checks a keys_signature over keys as a PublicKey answer carries them: pub's signature over
// their signing-keys transcript (ReceivedSigningKeysTranscript) under any transcript version p reads. Any failure is
// ErrAuth.
func VerifyReceivedSigningKeys(p *format.Policy, pub ed25519.PublicKey, signature []byte, profile string,
	tenancy Tenancy, contextDigest string, nonce []byte, keys []ReceivedSigningKey,
) error {
	sorted := sortedReceived(keys)
	for s := range format.Each(p, transcripts) {
		if verify(pub, s.Codec().signingKeys(s.Version(), profile, tenancy, contextDigest, nonce, sorted),
			signature) == nil {
			return nil
		}
	}
	return ErrAuth
}

// OpenRequestPayload opens a request payload sealed to sk under its seal info (RequestSealInfo) of profile, op, tenant
// and requestKey, under any transcript version p reads. A payload that does not open is ErrOpen.
func OpenRequestPayload(p *format.Policy, sk hpke.PrivateKey, profile string, op Operation, tenant string,
	requestKey ed25519.PublicKey, enc, sealed []byte,
) ([]byte, error) {
	requester := RequesterKeyHash(requestKey)
	for s := range format.Each(p, transcripts) {
		if plaintext, err := Open(sk, s.Codec().requestSealInfo(s.Version(), profile, op, tenant, requester), enc,
			sealed); err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrOpen
}

// OpenResponsePayload opens a Decrypt answer's plaintext sealed to sk under its seal info (ResponseInfoTenant) of
// profile, op and tenant, under any transcript version p reads. A payload that does not open is ErrOpen.
func OpenResponsePayload(p *format.Policy, sk hpke.PrivateKey, profile string, op Operation, tenant string,
	enc, sealed []byte,
) ([]byte, error) {
	for s := range format.Each(p, transcripts) {
		if plaintext, err := Open(sk, s.Codec().responseSealInfo(s.Version(), profile, op, tenant), enc,
			sealed); err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrOpen
}
