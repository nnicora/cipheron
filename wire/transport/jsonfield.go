package transport

// jsonfield.go — field-level encryption of JSON documents (the client's EncryptJSONFields): which bytes a field's
// ciphertext is bound to, and how it is written into the document. cipheron sees ordinary ciphertexts with
// associated data; this file is the client's convention, published so that a reader in another language reads the
// same documents.
//
// A field is named by its JSON Pointer (RFC 6901) in the document. Its plaintext is the field's value as compact JSON
// (any JSON type), and its associated data is
//
//	lp("cipheron/v1|json-field") lp(record id) lp(JSON Pointer) lp(the caller's associated data)
//
// so a field's ciphertext decrypts only in the record it was made for (another record id) and at the place it was
// made for (another pointer): fields swapped within a record, or copied from another record, do not decrypt. The
// ciphertext replaces the value as a JSON string, JSONFieldPrefix followed by its standard base64.

import (
	"errors"

	"github.com/nnicora/cipheron/wire/format"
)

// JSONFieldPrefix opens an encrypted field's value: the marker of the version this release writes (catalog.go). It is
// a constant for the callers that test a value for it.
const JSONFieldPrefix = "cipheron:v1:"

// jsonFieldVersion is the JSON field encoding's version: the encrypted JSON field kind's one version, written and read.
const jsonFieldVersion uint32 = 1

// jsonFieldMarkerProbe bounds what of a value is looked at to find its scheme: no marker is longer
// (TestEveryJSONFieldMarkerFitsTheProbe), so a value is never copied whole to be told apart.
const jsonFieldMarkerProbe = 32

// jsonFieldScheme is the scheme p reads of v, by its prefix; ErrJSONField when v opens with none.
func jsonFieldScheme(p *format.Policy, v string) (*format.Scheme[jsonFieldCodec], error) {
	return format.Marked(p, jsonFields, []byte(v[:min(len(v), jsonFieldMarkerProbe)]))
}

// MaxJSONRecordIDLen bounds a record id (the row's primary key, a document id).
const MaxJSONRecordIDLen = 1024

// jsonFieldLabel opens a field's associated data.
var jsonFieldLabel = format.LabelJSONField.String()

// ErrJSONField is the refusal of a JSON field-encryption call's input: a document that is not one JSON value, a
// pointer that is not a JSON Pointer or names no value of the document, pointers that repeat or nest, a record id
// out of bounds — and, to decrypt, a value at an encrypted field's place that is not a string opening with
// JSONFieldPrefix and holding base64 (a field put back in clear is refused, never passed through).
var ErrJSONField = errors.New("cipheron: not a JSON document, field or encrypted field the call can use")

// JSONFieldAssociatedData is the associated data the field at pointer of record recordID is encrypted with.
func JSONFieldAssociatedData(recordID, pointer string, aad []byte) []byte {
	return transcript(nil).addString(jsonFieldLabel).addString(recordID).addString(pointer).add(aad)
}

// EncodeJSONField is an encrypted field's value: the prefix of the version p writes (JSONFieldPrefix) and the
// ciphertext's standard base64.
func EncodeJSONField(p *format.Policy, ciphertext []byte) string {
	w := format.Write(p, jsonFields, 0)
	return w.Marker() + w.Codec().encode(ciphertext)
}

// DecodeJSONField is the ciphertext of an encrypted field's value (EncodeJSONField) of a version p reads; ErrJSONField
// otherwise. The version is the one the value's prefix names, and the prefix must be exactly that version's
// ("cipheron:v01:" is not version 1's).
func DecodeJSONField(p *format.Policy, v string) ([]byte, error) {
	s, err := jsonFieldScheme(p, v)
	if err != nil {
		return nil, err
	}
	rest := v[len(s.Marker()):]
	if rest == "" {
		return nil, ErrJSONField
	}
	ct, ok := s.Codec().decode(rest)
	if !ok {
		return nil, ErrJSONField
	}
	return ct, nil
}

// IsJSONField reports whether v is an encrypted field's value of a version p reads: it opens with exactly that
// version's prefix (DecodeJSONField's parse), whatever follows it. Encrypting refuses such a value as encrypted
// already.
func IsJSONField(p *format.Policy, v string) bool {
	_, err := jsonFieldScheme(p, v)
	return err == nil
}
