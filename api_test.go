package cipheron

// api_test.go — what an application can see of cipheron. The application packages are exactly package cipheron,
// cipherontest and conformance; the client engine is internal/client, which Go refuses to import from another module,
// and the protocol's machinery is wire/* and peercred, which the server and other implementations import and
// applications do not. This test holds two rules:
//
//   - THE SURFACE IS A REVIEWED FILE: every exported declaration of the public packages, without comments or bodies,
//     is testdata/api.txt. A change to what applications can see is a diff of that file, rewritten only on purpose
//     (go test . -run TestThePublicAPI -update-api).
//   - NO INTERNAL TYPE WITHOUT A PUBLIC NAME: an exported signature, field or type of the public packages may name
//     an internal/*, wire/* or peercred type only when package cipheron re-exports it by an alias (type X = transport.X), so an
//     application can always name what it is handed.

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var updateAPI = flag.Bool("update-api", false, "rewrite testdata/api.txt from the public packages")

// publicPackages are the packages an application may import, by directory from this one, and import path.
var publicPackages = []struct{ dir, path string }{
	{".", "github.com/nnicora/cipheron"},
	{"cipherontest", "github.com/nnicora/cipheron/cipherontest"},
	{"conformance", "github.com/nnicora/cipheron/conformance"},
}

// modulePath is this module's import path. The packages the public API is built from — internal/* (the client
// engine and the private utilities), wire/* (the protocol) and peercred — are followed when a public declaration
// names one of their types, so a change there that reaches the public surface shows in testdata/api.txt.
const modulePath = "github.com/nnicora/cipheron"

// followedDirs are those packages' directories, from this one.
var followedDirs = []string{"internal/*", "wire/*", "peercred"}

// followed reports whether import path p is one of the packages followedDirs names.
func followed(p string) bool {
	rel, ok := strings.CutPrefix(p, modulePath+"/")
	if !ok {
		return false
	}
	for _, g := range followedDirs {
		if m, _ := filepath.Match(g, rel); m {
			return true
		}
	}
	return false
}

// parsePublic is a public package's non-test files and its go/doc view (exported declarations only).
func parsePublic(t *testing.T, dir, path string) (*token.FileSet, []*ast.File, *doc.Package) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	p, err := doc.NewFromFiles(fset, files, path)
	if err != nil {
		t.Fatal(err)
	}
	return fset, files, p
}

// render is one declaration as source, without its comments or a function's body.
func render(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()
	var b bytes.Buffer
	if err := (&printer.Config{Mode: printer.TabIndent | printer.UseSpaces, Tabwidth: 8}).Fprint(&b, fset, node); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// stripDoc removes the comments a declaration carries, so the surface is the declarations alone.
func stripDoc(n ast.Node) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.GenDecl:
			x.Doc = nil
		case *ast.FuncDecl:
			x.Doc, x.Body = nil, nil
		case *ast.Field:
			x.Doc, x.Comment = nil, nil
		case *ast.ValueSpec:
			x.Doc, x.Comment = nil, nil
		case *ast.TypeSpec:
			x.Doc, x.Comment = nil, nil
		}
		return true
	})
}

// surface is the public packages' exported declarations, package by package, in go/doc's order.
func surface(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	for _, pp := range publicPackages {
		fset, _, p := parsePublic(t, pp.dir, pp.path)
		fmt.Fprintf(&out, "package %s // %s\n\n", p.Name, pp.path)
		var decls []ast.Node
		for _, v := range p.Consts {
			decls = append(decls, v.Decl)
		}
		for _, v := range p.Vars {
			decls = append(decls, v.Decl)
		}
		for _, f := range p.Funcs {
			decls = append(decls, f.Decl)
		}
		for _, ty := range p.Types {
			decls = append(decls, ty.Decl)
			for _, v := range ty.Consts {
				decls = append(decls, v.Decl)
			}
			for _, v := range ty.Vars {
				decls = append(decls, v.Decl)
			}
			for _, f := range ty.Funcs {
				decls = append(decls, f.Decl)
			}
			for _, f := range ty.Methods {
				decls = append(decls, f.Decl)
			}
		}
		for _, d := range decls {
			stripDoc(d)
			out.WriteString(render(t, fset, d))
			out.WriteString("\n")
		}
		out.WriteString("\n")
	}
	return out.String()
}

func TestThePublicAPI(t *testing.T) {
	got := surface(t)
	const file = "testdata/api.txt"
	if *updateAPI {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (write it with -update-api)", err)
	}
	if string(want) != got {
		t.Fatalf("the public API is not %s: review the change, then rewrite it with "+
			"go test . -run TestThePublicAPI -update-api", file)
	}
}

// internalImports is a file's imports of internal packages: the name it refers to each by, and its path.
func internalImports(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !followed(p) {
			continue
		}
		name := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		m[name] = p
	}
	return m
}

// aliases are the internal types package cipheron re-exports by an alias: "path.Name".
func aliases(t *testing.T) map[string]bool {
	t.Helper()
	_, files, _ := parsePublic(t, ".", publicPackages[0].path)
	out := map[string]bool{}
	for _, f := range files {
		imps := internalImports(f)
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.TYPE {
				continue
			}
			for _, s := range g.Specs {
				ts, ok := s.(*ast.TypeSpec)
				if !ok || !ts.Assign.IsValid() || !ts.Name.IsExported() {
					continue
				}
				if sel, ok := ts.Type.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && imps[x.Name] != "" {
						out[imps[x.Name]+"."+sel.Sel.Name] = true
					}
				}
			}
		}
	}
	return out
}

// internalTypes are the exported type names of every internal package the public packages import: "path.Name".
// Parsed, not type-checked: what a value expression converts to or builds a literal of is a type of these.
func internalTypes(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	seen := map[string]bool{}
	for _, pp := range publicPackages {
		_, files, _ := parsePublic(t, pp.dir, pp.path)
		for _, f := range files {
			for _, path := range internalImports(f) {
				if seen[path] {
					continue
				}
				seen[path] = true
				dir := strings.TrimPrefix(path, modulePath+"/")
				names, err := filepath.Glob(filepath.Join(dir, "*.go"))
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range names {
					if strings.HasSuffix(n, "_test.go") {
						continue
					}
					af, err := parser.ParseFile(token.NewFileSet(), n, nil, 0)
					if err != nil {
						t.Fatal(err)
					}
					for _, d := range af.Decls {
						if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.TYPE {
							for _, sp := range g.Specs {
								if ts, ok := sp.(*ast.TypeSpec); ok && ts.Name.IsExported() {
									out[path+"."+ts.Name.Name] = true
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// leaks are the internal types an exported declaration of the public packages names with no public alias: in a
// function's or method's signature, an exported type's definition or exported fields, a variable's or constant's
// written type, and — a value of an internal type — a conversion to or a literal of one in its value. A value returned
// by a call is not seen (that needs type-checking).
func leaks(t *testing.T) []string {
	t.Helper()
	ok := aliases(t)
	types := internalTypes(t)
	var out []string
	for _, pp := range publicPackages {
		fset, files, _ := parsePublic(t, pp.dir, pp.path)
		for _, f := range files {
			imps := internalImports(f)
			if len(imps) == 0 {
				continue
			}
			check := func(what string, n ast.Node) {
				if n == nil {
					return
				}
				ast.Inspect(n, func(x ast.Node) bool {
					sel, isSel := x.(*ast.SelectorExpr)
					if !isSel {
						return true
					}
					id, isID := sel.X.(*ast.Ident)
					if !isID || imps[id.Name] == "" || !sel.Sel.IsExported() {
						return true
					}
					if key := imps[id.Name] + "." + sel.Sel.Name; !ok[key] {
						out = append(out, fmt.Sprintf("%s: %s names %s", fset.Position(sel.Pos()), what, key))
					}
					return true
				})
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if !d.Name.IsExported() || d.Recv != nil && !exportedRecv(d.Recv) {
						continue
					}
					check(pp.dir+"."+d.Name.Name, d.Type)
				case *ast.GenDecl:
					for _, s := range d.Specs {
						switch s := s.(type) {
						case *ast.TypeSpec:
							if s.Name.IsExported() && !s.Assign.IsValid() {
								check(pp.dir+"."+s.Name.Name, exportedPart(s.Type))
							}
						case *ast.ValueSpec:
							if len(s.Names) > 0 && s.Names[0].IsExported() {
								what := pp.dir + "." + s.Names[0].Name
								check(what, s.Type)
								for _, v := range s.Values {
									valueTypes(v, imps, types, ok, func(key string, pos token.Pos) {
										out = append(out, fmt.Sprintf("%s: %s is a value of %s", fset.Position(pos), what, key))
									})
								}
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// valueTypes reports, in a value expression, each conversion to or composite literal of an internal type (types)
// with no public alias (ok): the value is then of that type.
func valueTypes(v ast.Expr, imps map[string]string, types, ok map[string]bool, report func(string, token.Pos)) {
	typeOf := func(e ast.Expr) (string, token.Pos, bool) {
		sel, isSel := e.(*ast.SelectorExpr)
		if !isSel {
			return "", 0, false
		}
		id, isID := sel.X.(*ast.Ident)
		if !isID || imps[id.Name] == "" {
			return "", 0, false
		}
		key := imps[id.Name] + "." + sel.Sel.Name
		return key, sel.Pos(), types[key] && !ok[key]
	}
	switch e := v.(type) {
	case *ast.CallExpr: // a conversion: T(x)
		if key, pos, bad := typeOf(e.Fun); bad {
			report(key, pos)
		}
	case *ast.CompositeLit:
		if key, pos, bad := typeOf(e.Type); bad {
			report(key, pos)
		}
	case *ast.UnaryExpr: // &T{...}
		valueTypes(e.X, imps, types, ok, report)
	case *ast.ParenExpr:
		valueTypes(e.X, imps, types, ok, report)
	}
}

// exportedRecv reports whether a method's receiver is an exported type.
func exportedRecv(fl *ast.FieldList) bool {
	if len(fl.List) == 0 {
		return false
	}
	t := fl.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.IsExported()
}

// exportedPart is a type's exported part: a struct's exported fields (and embedded types), any other type whole.
func exportedPart(e ast.Expr) ast.Expr {
	st, ok := e.(*ast.StructType)
	if !ok {
		return e
	}
	kept := &ast.FieldList{}
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			kept.List = append(kept.List, f)
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				kept.List = append(kept.List, f)
				break
			}
		}
	}
	return &ast.StructType{Fields: kept}
}

func TestNoInternalTypeWithoutAPublicName(t *testing.T) {
	if l := leaks(t); len(l) > 0 {
		t.Fatalf("an exported declaration of a public package names an internal type package cipheron does not re-export "+
			"by an alias (type X = pkg.X):\n%s", strings.Join(l, "\n"))
	}
}

// internalTypeDecls are the type declarations and methods of the internal packages: per "path.Name", its spec (for
// embedded fields) and its exported methods (receiver T or *T), each with the file's internal imports.
type internalDecl struct {
	spec    *ast.TypeSpec
	methods []*ast.FuncDecl
	imps    map[string]string
	pkg     string
}

func internalDecls(t *testing.T) map[string]*internalDecl {
	t.Helper()
	out := map[string]*internalDecl{}
	var dirs []string
	for _, g := range followedDirs {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, m...)
	}
	for _, dir := range dirs {
		path := modulePath + "/" + filepath.ToSlash(dir)
		names, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, n := range names {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), n, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			imps := internalImports(f)
			get := func(name string) *internalDecl {
				k := path + "." + name
				if out[k] == nil {
					out[k] = &internalDecl{pkg: path}
				}
				return out[k]
			}
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.GenDecl:
					for _, s := range d.Specs {
						if ts, ok := s.(*ast.TypeSpec); ok {
							e := get(ts.Name.Name)
							e.spec, e.imps = ts, imps
						}
					}
				case *ast.FuncDecl:
					if d.Recv == nil || !d.Name.IsExported() || len(d.Recv.List) == 0 {
						continue
					}
					rt := d.Recv.List[0].Type
					if s, ok := rt.(*ast.StarExpr); ok {
						rt = s.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						e := get(id.Name)
						e.methods = append(e.methods, d)
						if e.imps == nil {
							e.imps = imps
						}
						// a method's file may import other packages than the type's file: keep both
						for k, v := range imps {
							e.imps[k] = v
						}
					}
				}
			}
		}
	}
	return out
}

// methodLeaks are the exported methods an application reaches through a public alias of an internal type — the
// type's own and those promoted from its embedded fields — whose signatures name an internal type with no public
// alias.
func methodLeaks(t *testing.T) []string {
	t.Helper()
	ok := aliases(t)
	decls := internalDecls(t)
	var out []string
	seen := map[string]bool{}
	var walk func(key, via string)
	walk = func(key, via string) {
		if seen[key+via] {
			return
		}
		seen[key+via] = true
		d := decls[key]
		if d == nil {
			return
		}
		local := func(e ast.Expr) string { // the "path.Name" an expression names, in d's package or an imported one
			switch e := e.(type) {
			case *ast.Ident:
				return d.pkg + "." + e.Name
			case *ast.SelectorExpr:
				if id, isID := e.X.(*ast.Ident); isID && d.imps[id.Name] != "" {
					return d.imps[id.Name] + "." + e.Sel.Name
				}
			case *ast.StarExpr:
				if id, isID := e.X.(*ast.Ident); isID {
					return d.pkg + "." + id.Name
				}
			}
			return ""
		}
		for _, m := range d.methods {
			ast.Inspect(m.Type, func(x ast.Node) bool {
				var named string
				switch x := x.(type) {
				case *ast.SelectorExpr:
					named = local(x)
				case *ast.Ident:
					if x.IsExported() && decls[d.pkg+"."+x.Name] != nil && decls[d.pkg+"."+x.Name].spec != nil {
						named = d.pkg + "." + x.Name
					}
				}
				if named != "" && decls[named] != nil && decls[named].spec != nil && !ok[named] {
					out = append(out, fmt.Sprintf("%s.%s (via %s) names %s", via, m.Name.Name, key, named))
				}
				return true
			})
		}
		if st, isStruct := d.spec.Type.(*ast.StructType); isStruct {
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 { // embedded: its methods are promoted
					if k := local(f.Type); k != "" {
						walk(k, via)
					}
				}
			}
		}
	}
	for key := range ok {
		walk(key, key[strings.LastIndex(key, "/")+1:])
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func TestNoInternalTypeThroughAnAliasMethod(t *testing.T) {
	if l := methodLeaks(t); len(l) > 0 {
		t.Fatalf("a method an application reaches through a public alias names an internal type with no public "+
			"alias:\n%s", strings.Join(l, "\n"))
	}
}
