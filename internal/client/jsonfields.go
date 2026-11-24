package client

// jsonfields.go — field-level encryption of a JSON document (transport/jsonfield.go): the fields a list of JSON
// Pointers names are encrypted (and decrypted) in one batch, each bound to its pointer and to the record's id.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nnicora/cipheron/wire/transport"
)

// MaxJSONFields bounds the pointers of one call.
const MaxJSONFields = 4096

// parsePointer splits a JSON Pointer (RFC 6901) into its reference tokens. The whole document ("") is refused: a
// document is encrypted with Encrypt.
func parsePointer(p string) ([]string, error) {
	if p == "" || p[0] != '/' {
		return nil, fmt.Errorf("%w: %q is not a JSON Pointer to a field (\"/a/b\", RFC 6901)", transport.ErrJSONField, p)
	}
	tokens := strings.Split(p[1:], "/")
	for i, t := range tokens {
		// ~1 is "/" and ~0 is "~", in that order; any other "~" is not a pointer.
		for j := 0; j < len(t); j++ {
			if t[j] == '~' && (j+1 == len(t) || (t[j+1] != '0' && t[j+1] != '1')) {
				return nil, fmt.Errorf("%w: %q: a \"~\" is written ~0, a \"/\" ~1", transport.ErrJSONField, p)
			}
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

// arrayIndex is a pointer token as an index of an array of n elements.
func arrayIndex(tok string, n int) (int, bool) {
	if tok == "" || (len(tok) > 1 && tok[0] == '0') {
		return 0, false
	}
	i, err := strconv.Atoi(tok)
	if err != nil || i < 0 || i >= n {
		return 0, false
	}
	return i, true
}

// locate finds the value tokens name in doc, and a function that replaces it.
func locate(doc any, tokens []string) (any, func(any), bool) {
	cur := doc
	for k, tok := range tokens {
		last := k == len(tokens)-1
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[tok]
			if !ok {
				return nil, nil, false
			}
			if last {
				return next, func(x any) { v[tok] = x }, true
			}
			cur = next
		case []any:
			i, ok := arrayIndex(tok, len(v))
			if !ok {
				return nil, nil, false
			}
			if last {
				return v[i], func(x any) { v[i] = x }, true
			}
			cur = v[i]
		default:
			return nil, nil, false
		}
	}
	return nil, nil, false
}

// decodeJSON decodes one JSON value, numbers kept as written (json.Number), nothing after it.
func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

// encodeJSON is v as compact JSON, without HTML escaping.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// checkPointers parses pointers: at least one, at most MaxJSONFields, none twice, none inside another (a field and
// a field within it cannot both be encrypted).
func checkPointers(pointers []string) ([][]string, error) {
	if len(pointers) == 0 || len(pointers) > MaxJSONFields {
		return nil, fmt.Errorf("%w: 1 to %d field pointers, not %d", transport.ErrJSONField, MaxJSONFields, len(pointers))
	}
	out := make([][]string, len(pointers))
	for i, p := range pointers {
		t, err := parsePointer(p)
		if err != nil {
			return nil, err
		}
		out[i] = t
	}
	for i := range out {
		for j := range out {
			if i != j && len(out[i]) <= len(out[j]) && slices.Equal(out[i], out[j][:len(out[i])]) {
				return nil, fmt.Errorf("%w: %q and %q: a field is named twice, or inside another", transport.ErrJSONField,
					pointers[i], pointers[j])
			}
		}
	}
	return out, nil
}

// fieldAssociatedData is the associated data of the field at pointer of record recordID, with the caller's aad
// (transport.JSONFieldAssociatedData); ErrJSONField when it is over transport.MaxAssociatedDataLen. which names it in
// the refusal ("" for the field's own, "target " for a re-encryption's new one).
func fieldAssociatedData(recordID, pointer string, aad []byte, which string) ([]byte, error) {
	ad := transport.JSONFieldAssociatedData(recordID, pointer, aad)
	if len(ad) > transport.MaxAssociatedDataLen {
		return nil, fmt.Errorf("%w: %q: the field's %sassociated data — the record id, the pointer and the caller's "+
			"associated data, with %d bytes of framing (transport.JSONFieldAssociatedData) — is %d bytes; at most %d",
			transport.ErrJSONField, pointer, which, len(ad)-len(recordID)-len(pointer)-len(aad), len(ad),
			transport.MaxAssociatedDataLen)
	}
	return ad, nil
}

// fieldOp is what jsonFields does with each field.
type fieldOp int

const (
	fieldEncrypt   fieldOp = iota // the value, as compact JSON, through EncryptBatch
	fieldDecrypt                  // the encrypted field, through DecryptBatch
	fieldReEncrypt                // the encrypted field, through ReEncryptBatch: a new ciphertext, never a plaintext
)

// jsonFields encrypts, decrypts or re-encrypts the fields pointers name in doc, through call in batches, each with
// the associated data that binds it to its pointer and to recordID (and co's associated data; a re-encryption's new
// ciphertext with co's target associated data).
func (c *Client) jsonFields(ctx context.Context, doc []byte, recordID string, pointers []string, co callOptions,
	op fieldOp, call batchFunc) ([]byte, error) {
	if recordID == "" || len(recordID) > transport.MaxJSONRecordIDLen || !utf8.ValidString(recordID) {
		return nil, fmt.Errorf("%w: a record id is 1 to %d bytes of UTF-8", transport.ErrJSONField, transport.MaxJSONRecordIDLen)
	}
	paths, err := checkPointers(pointers)
	if err != nil {
		return nil, err
	}
	root, err := decodeJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: the document: %v", transport.ErrJSONField, err) //nolint:errorlint // the cause is named, not wrapped: the error is ErrJSONField's, not the JSON decoder's
	}
	items := make([]BatchItem, len(paths))
	sets := make([]func(any), len(paths))
	for i, tokens := range paths {
		v, set, ok := locate(root, tokens)
		if !ok {
			return nil, fmt.Errorf("%w: %q names no value of the document", transport.ErrJSONField, pointers[i])
		}
		aad, err := fieldAssociatedData(recordID, pointers[i], co.aad, "")
		if err != nil {
			return nil, err
		}
		var toAAD []byte
		if op == fieldReEncrypt {
			if toAAD, err = fieldAssociatedData(recordID, pointers[i], co.toAAD, "target "); err != nil {
				return nil, err
			}
		}
		var data []byte
		if op == fieldEncrypt {
			if s, isString := v.(string); isString && transport.IsJSONField(transport.Release(), s) {
				return nil, fmt.Errorf("%w: %q is encrypted already", transport.ErrJSONField, pointers[i])
			}
			if data, err = encodeJSON(v); err != nil {
				return nil, fmt.Errorf("%w: %q: %v", transport.ErrJSONField, pointers[i], err) //nolint:errorlint // the cause is named, not wrapped: the error is ErrJSONField's, not the JSON encoder's
			}
		} else {
			s, isString := v.(string)
			if !isString {
				return nil, fmt.Errorf("%w: %q is not an encrypted field", transport.ErrJSONField, pointers[i])
			}
			if data, err = transport.DecodeJSONField(transport.Release(), s); err != nil {
				return nil, fmt.Errorf("%q: %w", pointers[i], err)
			}
		}
		items[i] = BatchItem{Data: data, AssociatedData: aad, ToAssociatedData: toAAD}
		sets[i] = set
	}
	out, err := c.inBatches(ctx, items, op == fieldEncrypt, call)
	var f *segmentError
	if errors.As(err, &f) {
		return nil, fmt.Errorf("cipheron: field %q: %w", pointers[f.index], f.err)
	}
	if err != nil {
		return nil, err
	}
	for i, v := range out {
		if op != fieldDecrypt { // a ciphertext: the field's new value
			sets[i](transport.EncodeJSONField(transport.Release(), v))
			continue
		}
		x, err := decodeJSON(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %q decrypted to something that is not one JSON value", transport.ErrJSONField, pointers[i])
		}
		sets[i](x)
	}
	return encodeJSON(root)
}

// EncryptJSONFields encrypts the fields of doc (one JSON value) that pointers name — JSON Pointers (RFC 6901), such
// as "/card/number" or "/contacts/0/email" — in the shared profile, in batches (EncryptBatch), and returns the document
// with each such field's value replaced by a string: transport.JSONFieldPrefix and the ciphertext's base64. The
// plaintext of a field is its value as compact JSON, whatever its type, so DecryptJSONFields gives it back as it was.
//
// Each field is bound, by its associated data, to its pointer and to recordID — the record's identity, as the
// application knows it (a primary key, a document id; 1 to transport.MaxJSONRecordIDLen bytes): a field's ciphertext
// does not decrypt at another place of the document, nor in another record. WithAssociatedData adds the caller's own.
// Every pointer must name a value of the document; none may repeat or lie inside another; nothing else of the
// document is changed (it is written again compact, object keys in sorted order, numbers as they were written).
func (c *Client) EncryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.jsonFields(ctx, doc, recordID, pointers, co, fieldEncrypt, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.EncryptBatch(ctx, profile, items)
	})
}

// DecryptJSONFields decrypts the fields pointers name in doc (EncryptJSONFields' output), with the record id and the
// associated data they were made with, and returns the document with their values as they were. A field at one of
// pointers that is not an encrypted field — put back in clear, say — is refused (transport.ErrJSONField), never
// passed through; a field moved from another place or another record fails to decrypt. Nothing is returned unless
// every field decrypted.
func (c *Client) DecryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.jsonFields(ctx, doc, recordID, pointers, co, fieldDecrypt, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.DecryptBatch(ctx, profile, items)
	})
}

// EncryptJSONFields is Client.EncryptJSONFields for the tenant.
func (t *Tenant) EncryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.jsonFields(ctx, doc, recordID, pointers, co, fieldEncrypt, t.EncryptBatch)
}

// DecryptJSONFields is Client.DecryptJSONFields for the tenant.
func (t *Tenant) DecryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	co, err := callOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.jsonFields(ctx, doc, recordID, pointers, co, fieldDecrypt, t.DecryptBatch)
}

// ReEncryptJSONFields has cipheron re-encrypt the encrypted fields pointers name in doc (EncryptJSONFields' output)
// under the shared profile's current keys, in batches (ReEncryptBatch), and returns the document with each such field's
// value replaced by its new ciphertext — the plaintexts never leave cipheron, so the caller's entry needs the reencrypt
// operation only, and nothing returned or kept here is a plaintext. It is what a migration sweep needs before a master
// key version is retired: a field's header names its key without cipheron (package cipheron's
// JSONFieldKeyID), and only the fields still under an old one need moving.
//
// Each field is decrypted with the associated data it was made with — its pointer, recordID and WithAssociatedData's —
// and its new ciphertext is bound to the same: the same pointer and record, and WithTargetAssociatedData, which must
// be WithAssociatedData's (as ReEncrypt: reencryptOpts; anything else is refused before anything is sent) — a
// re-encryption keeps the binding. The pointers and the document are checked as DecryptJSONFields checks them: a
// field put back in clear is refused (transport.ErrJSONField), and a field moved from another place or another record
// fails to decrypt. Nothing is returned unless every field was re-encrypted.
func (c *Client) ReEncryptJSONFields(ctx context.Context, profile string, doc []byte, recordID string, pointers []string,
	opts ...CallOption) ([]byte, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	return c.jsonFields(ctx, doc, recordID, pointers, co, fieldReEncrypt, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return c.ReEncryptBatch(ctx, profile, items)
	})
}

// ReEncryptJSONFields is Client.ReEncryptJSONFields for the tenant: in a wrapped profile every field moves to the tenant
// key blob to (as Tenant.ReEncrypt: the tenant's new key, or the handle's own blob); in a derived one to is nil.
func (t *Tenant) ReEncryptJSONFields(ctx context.Context, doc []byte, recordID string, pointers []string, to []byte,
	opts ...CallOption) ([]byte, error) {
	co, err := reencryptOpts(opts)
	if err != nil {
		return nil, err
	}
	return t.c.jsonFields(ctx, doc, recordID, pointers, co, fieldReEncrypt, func(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
		return t.ReEncryptBatch(ctx, items, to)
	})
}
