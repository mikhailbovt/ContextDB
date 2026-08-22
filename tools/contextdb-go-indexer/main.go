// contextdb-go-indexer emits deterministic go/ast + go/types evidence for the
// external ContextDB coding-domain pack. It has no dependency on ContextDB's
// universal core or durable logical formats.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const schemaVersion = 1

type sourceRange struct {
	StartLine   uint32 `json:"start_line"`
	StartColumn uint32 `json:"start_column"`
	EndLine     uint32 `json:"end_line"`
	EndColumn   uint32 `json:"end_column"`
}

type sourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type indexSymbol struct {
	Key                 string      `json:"key"`
	QualifiedName       string      `json:"qualified_name"`
	DisplayName         string      `json:"display_name"`
	Kind                string      `json:"kind"`
	File                string      `json:"file"`
	Range               sourceRange `json:"range"`
	Signature           string      `json:"signature"`
	SemanticFingerprint string      `json:"semantic_fingerprint"`
}

type indexRelation struct {
	Source string       `json:"source"`
	Target string       `json:"target"`
	Kind   string       `json:"kind"`
	Range  *sourceRange `json:"range,omitempty"`
}

type compilerIndex struct {
	SchemaVersion uint16          `json:"schema_version"`
	Module        string          `json:"module"`
	Package       string          `json:"package"`
	Files         []sourceFile    `json:"files"`
	Symbols       []indexSymbol   `json:"symbols"`
	Relations     []indexRelation `json:"relations"`
}

type parsedFile struct {
	path    string
	content []byte
	file    *ast.File
}

func main() {
	directory := flag.String("dir", ".", "package directory to index")
	module := flag.String("module", "", "Go module path")
	packagePath := flag.String("package", "", "fully-qualified Go package path")
	flag.Parse()
	if *module == "" || *packagePath == "" {
		fatal(errors.New("--module and --package are required"))
	}
	index, err := indexDirectory(*directory, *module, *packagePath)
	if err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(index); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "contextdb-go-indexer: %v\n", err)
	os.Exit(1)
}

func indexDirectory(directory, module, packagePath string) (compilerIndex, error) {
	if strings.TrimSpace(module) == "" || strings.TrimSpace(packagePath) == "" {
		return compilerIndex{}, errors.New("module and package path must be non-empty")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return compilerIndex{}, err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return compilerIndex{}, errors.New("package contains no Go source")
	}

	fileSet := token.NewFileSet()
	parsed := make([]parsedFile, 0, len(names))
	astFiles := make([]*ast.File, 0, len(names))
	packageName := ""
	for _, name := range names {
		fullPath := filepath.Join(directory, name)
		content, readErr := os.ReadFile(fullPath)
		if readErr != nil {
			return compilerIndex{}, readErr
		}
		file, parseErr := parser.ParseFile(fileSet, name, content, parser.ParseComments|parser.SkipObjectResolution)
		if parseErr != nil {
			return compilerIndex{}, parseErr
		}
		if packageName == "" {
			packageName = file.Name.Name
		} else if packageName != file.Name.Name {
			return compilerIndex{}, fmt.Errorf("mixed package names %q and %q", packageName, file.Name.Name)
		}
		parsed = append(parsed, parsedFile{path: filepath.ToSlash(name), content: content, file: file})
		astFiles = append(astFiles, file)
	}

	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	config := &types.Config{Importer: importer.Default()}
	typedPackage, err := config.Check(packagePath, fileSet, astFiles, info)
	if err != nil {
		return compilerIndex{}, fmt.Errorf("go/types rejected package: %w", err)
	}
	_ = typedPackage

	result := compilerIndex{
		SchemaVersion: schemaVersion,
		Module:        module,
		Package:       packagePath,
		Files:         make([]sourceFile, 0, len(parsed)),
		Symbols:       make([]indexSymbol, 0),
		Relations:     make([]indexRelation, 0),
	}
	for _, file := range parsed {
		result.Files = append(result.Files, sourceFile{Path: file.path, Content: string(file.content)})
	}

	objectKeys := make(map[types.Object]string)
	functionKeys := make(map[*ast.FuncDecl]string)
	for _, file := range parsed {
		for _, declaration := range file.file.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				object := info.Defs[value.Name]
				if object == nil {
					return compilerIndex{}, fmt.Errorf("go/types omitted function %s", value.Name.Name)
				}
				key := objectKey(packagePath, object, receiverName(value))
				objectKeys[object] = key
				functionKeys[value] = key
				kind := "function"
				if strings.HasPrefix(value.Name.Name, "Test") && strings.HasSuffix(file.path, "_test.go") {
					kind = "test"
				}
				result.Symbols = append(result.Symbols, makeSymbol(fileSet, file, value, object, key, kind))
			case *ast.GenDecl:
				for _, specification := range value.Specs {
					switch spec := specification.(type) {
					case *ast.TypeSpec:
						object := info.Defs[spec.Name]
						if object == nil {
							continue
						}
						key := objectKey(packagePath, object, "")
						objectKeys[object] = key
						kind := "type"
						if _, ok := spec.Type.(*ast.InterfaceType); ok {
							kind = "interface"
						}
						result.Symbols = append(result.Symbols, makeSymbol(fileSet, file, spec, object, key, kind))
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							object := info.Defs[name]
							if object == nil {
								continue
							}
							key := objectKey(packagePath, object, "")
							objectKeys[object] = key
							result.Symbols = append(result.Symbols, makeSymbol(fileSet, file, spec, object, key, "value"))
						}
					}
				}
			}
		}
	}

	relationSet := make(map[string]struct{})
	for _, file := range parsed {
		for _, declaration := range file.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			sourceKey := functionKeys[function]
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				object := calledObject(call.Fun, info)
				targetKey, local := objectKeys[object]
				if !local || targetKey == sourceKey {
					return true
				}
				kind := "calls"
				relationSource, relationTarget := sourceKey, targetKey
				if strings.Contains(sourceKey, ".Test") {
					kind = "tested_by"
					relationSource, relationTarget = targetKey, sourceKey
				}
				key := relationSource + "\x00" + relationTarget + "\x00" + kind
				if _, exists := relationSet[key]; exists {
					return true
				}
				relationSet[key] = struct{}{}
				callRange := nodeRange(fileSet, call)
				result.Relations = append(result.Relations, indexRelation{
					Source: relationSource,
					Target: relationTarget,
					Kind:   kind,
					Range:  &callRange,
				})
				return true
			})
		}
	}

	sort.Slice(result.Symbols, func(i, j int) bool { return result.Symbols[i].Key < result.Symbols[j].Key })
	sort.Slice(result.Relations, func(i, j int) bool {
		left, right := result.Relations[i], result.Relations[j]
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		return left.Kind < right.Kind
	})
	return result, nil
}

func makeSymbol(fileSet *token.FileSet, file parsedFile, node ast.Node, object types.Object, key, kind string) indexSymbol {
	qualifiedName := object.Pkg().Path() + "." + object.Name()
	if function, ok := node.(*ast.FuncDecl); ok {
		if receiver := receiverName(function); receiver != "" {
			qualifiedName = object.Pkg().Path() + ".(" + receiver + ")." + object.Name()
		}
	}
	return indexSymbol{
		Key:                 key,
		QualifiedName:       qualifiedName,
		DisplayName:         object.Name(),
		Kind:                kind,
		File:                file.path,
		Range:               nodeRange(fileSet, node),
		Signature:           types.TypeString(object.Type(), qualifier),
		SemanticFingerprint: semanticFingerprint(fileSet, file, node, object),
	}
}

func qualifier(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

func objectKey(packagePath string, object types.Object, receiver string) string {
	if receiver == "" {
		return packagePath + "." + object.Name()
	}
	return packagePath + ".(" + receiver + ")." + object.Name()
}

func receiverName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	expression := function.Recv.List[0].Type
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = pointer.X
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return ""
}

func calledObject(expression ast.Expr, info *types.Info) types.Object {
	switch value := expression.(type) {
	case *ast.Ident:
		return info.Uses[value]
	case *ast.SelectorExpr:
		if selection := info.Selections[value]; selection != nil {
			return selection.Obj()
		}
		return info.Uses[value.Sel]
	default:
		return nil
	}
}

func nodeRange(fileSet *token.FileSet, node ast.Node) sourceRange {
	start := fileSet.PositionFor(node.Pos(), false)
	end := fileSet.PositionFor(node.End(), false)
	return sourceRange{
		StartLine:   uint32(start.Line),
		StartColumn: uint32(max(start.Column-1, 0)),
		EndLine:     uint32(end.Line),
		EndColumn:   uint32(max(end.Column-1, 0)),
	}
}

func semanticFingerprint(fileSet *token.FileSet, file parsedFile, node ast.Node, object types.Object) string {
	start := fileSet.PositionFor(node.Pos(), false).Offset
	end := fileSet.PositionFor(node.End(), false).Offset
	if start < 0 || end < start || end > len(file.content) {
		return strings.Repeat("0", 64)
	}
	source := string(file.content[start:end])
	source = strings.Replace(source, object.Name(), "<symbol>", 1)
	normalized := strings.Join(strings.Fields(source), " ")
	signature := types.TypeString(object.Type(), qualifier)
	signature = strings.Replace(signature, object.Name(), "<symbol>", 1)
	digest := sha256.Sum256([]byte(signature + "\x00" + normalized))
	return hex.EncodeToString(digest[:])
}
