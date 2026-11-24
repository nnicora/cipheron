// Package spec is cipheron's protocol contract as data: what every implementation — this Go SDK, the server, a
// client in any other language — is held to. The files are the source of truth; this package only embeds them so Go
// code (the conformance kit, the server's tests) reads them by import rather than by a path into another tree.
//
//	api.md, compatibility.md   the wire API and the format versions each kind reads
//	vectors/                   the conformance vectors (cipheron-conformance-v1.json) and their JSON Schema
//	frozen/                    the frozen set: what cipheron writes for fixed inputs (manifest.json and its keysets),
//	                           the vectors are derived from it and every release reads it
//
// An implementation in another language reads the same files from this directory of the repository.
package spec

import "embed"

// Vectors are the conformance vectors and their schema: vectors/cipheron-conformance-v1.json,
// vectors/vectors.schema.json.
//
//go:embed vectors/cipheron-conformance-v1.json vectors/vectors.schema.json
var Vectors embed.FS

// Frozen is the frozen set: frozen/manifest.json and the keysets it names.
//
//go:embed frozen
var Frozen embed.FS

// Docs are the protocol documents: api.md and compatibility.md.
//
//go:embed api.md compatibility.md
var Docs embed.FS
