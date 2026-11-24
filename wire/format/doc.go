// Package format is cipheron's one framework for everything it and its client library write that a later release may
// write differently: the stored layouts an application keeps (a ciphertext, a tenant key blob, a segmented object),
// the transcripts and seal infos it signs and seals under, the key statement and its exported document, an encrypted
// JSON field's value, and cipheron's keyset file.
//
// THE MODEL. A Kind is one kind of versioned item, declared once by the package that owns its bytes; a reader
// dispatches on it (by the item's marker or version field, or, for an item that carries no version, by rebuilding it
// under each version read). A Scheme is one version of a Kind: its number, its name, its codec (what reads and writes
// its bytes) and, for a sealed kind, its Suite (the cryptography its items are sealed under, owning one label
// namespace). A Catalog is a program's schemes, declared as data and validated once (NewCatalog). A Policy is what a
// release reads and writes of every kind of its Catalog: per kind, the scheme written for each slot and the schemes
// read. Every reader and writer takes a Policy.
//
// WHAT IT TAKES FROM GOOGLE TINK. Tink's keyset (one primary key, several enabled keys) is the Policy (one scheme
// written per slot, several read); Tink's rotation discipline is Check (a version joins the read set before any slot
// writes it, a slot switches only to a version the previous release read, a version leaves the read set only after the
// previous release no longer wrote it); Tink's output prefix is a Stored or Prefixed scheme's marker, which here is
// inside the AEAD's additional data, so a changed marker is a refusal and never another algorithm; Tink's primitive
// interfaces are Suite and ItemKey; Tink's configuration objects, passed in instead of a global registry, are the
// Catalog and Policy values every reader and writer takes.
//
// WHAT IT DOES NOT TAKE. No global registry: nothing is registered at run time, no package-level state changes after
// initialisation, and a test builds its own Catalog and Policy values (Policy.With) and runs in parallel with every
// other. No key material in the framework: a scheme names a layout, the item's header names its key. No algorithm
// chosen by configuration: another algorithm is another scheme with its own marker and its own namespace. No trial
// decryption of a stored item: its marker names its scheme.
//
// THE FRAME. A Stored scheme's item is marker || fields || salt, then (a sealed kind) nonce || ciphertext || tag. The
// framework writes and checks the marker, the salt (its suite's SaltLen) and the sealed tail (its suite's Overhead,
// and the Layout's Plaintext); a codec writes and parses its fields only (AppendHeader, ParseHeader), so no codec can
// disagree with its suite.
//
// THE LABELS. Every label cipheron and its clients derive a key under, sign, hash or seal under is built in labels.go,
// from typed fields: the purpose table (Fixed, Scoped and the shape builders). It is the only place a namespace is
// spelled (make check-label-namespace), and every shape is injective across shapes (labels_test.go).
package format
