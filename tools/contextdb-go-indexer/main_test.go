package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIndexDirectoryIsDeterministicAndCompilerResolved(t *testing.T) {
	directory := t.TempDir()
	writeFixture(t, directory, "password.go", `package auth

func DerivePassword(value string) string { return value + "-hash" }
func Login(value string) string { return DerivePassword(value) }
`)
	writeFixture(t, directory, "password_test.go", `package auth

import "testing"

func TestDerivePassword(t *testing.T) {
	if DerivePassword("x") == "" { t.Fatal("empty") }
}
`)
	first, err := indexDirectory(directory, "example.dev/rift", "example.dev/rift/internal/auth")
	if err != nil {
		t.Fatalf("index first: %v", err)
	}
	second, err := indexDirectory(directory, "example.dev/rift", "example.dev/rift/internal/auth")
	if err != nil {
		t.Fatalf("index second: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("compiler index changed without input changes")
	}
	if len(first.Symbols) != 3 {
		t.Fatalf("got %d symbols, want 3", len(first.Symbols))
	}
	if len(first.Relations) != 2 {
		t.Fatalf("got %d relations, want call and test", len(first.Relations))
	}
	foundTestRelation := false
	for _, relation := range first.Relations {
		foundTestRelation = foundTestRelation || relation.Kind == "tested_by"
	}
	if !foundTestRelation {
		t.Fatalf("got relations %#v, want tested_by", first.Relations)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTrip compilerIndex
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(first, roundTrip) {
		t.Fatal("JSON round trip changed compiler evidence")
	}
}

func TestIndexDirectoryRejectsTypeErrors(t *testing.T) {
	directory := t.TempDir()
	writeFixture(t, directory, "bad.go", "package bad\nfunc Broken() { missing() }\n")
	if _, err := indexDirectory(directory, "example.dev/bad", "example.dev/bad"); err == nil {
		t.Fatal("type-invalid source must fail closed")
	}
}

func writeFixture(t *testing.T, directory, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
