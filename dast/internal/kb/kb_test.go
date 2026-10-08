package kb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultHasVectors(t *testing.T) {
	k, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Vectors) == 0 {
		t.Fatal("embedded knowledge base is empty")
	}
	for _, v := range k.Vectors {
		if v.ID == "" || v.Class == "" {
			t.Errorf("vector with empty id/class: %+v", v)
		}
		if v.Source == "" {
			t.Errorf("vector %s missing provenance Source", v.ID)
		}
	}
}

func TestClassesDistinct(t *testing.T) {
	k, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	classes := k.Classes()
	if len(classes) == 0 {
		t.Fatal("no classes found")
	}
	seen := map[string]bool{}
	for _, c := range classes {
		if seen[c] {
			t.Errorf("duplicate class %q", c)
		}
		seen[c] = true
	}
}

func TestFilter(t *testing.T) {
	k, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	classes := k.Classes()
	if len(classes) == 0 {
		t.Skip("no classes to filter")
	}
	target := classes[0]
	out := k.Filter([]string{target})
	if len(out.Vectors) == 0 {
		t.Fatalf("filter on %q yielded nothing", target)
	}
	for _, v := range out.Vectors {
		if v.Class != target {
			t.Errorf("filter leaked class %q (wanted %q)", v.Class, target)
		}
	}
	// Empty filter returns everything.
	if all := k.Filter(nil); len(all.Vectors) != len(k.Vectors) {
		t.Errorf("nil filter changed vector count: %d vs %d", len(all.Vectors), len(k.Vectors))
	}
	// Unknown class matches nothing.
	if none := k.Filter([]string{"does-not-exist"}); len(none.Vectors) != 0 {
		t.Errorf("unknown-class filter returned %d vectors", len(none.Vectors))
	}
}

func TestLoadDirMerges(t *testing.T) {
	dir := t.TempDir()
	custom := `vectors:
  - id: custom-test
    class: custom
    title: Custom vector
    severity: low
    applies_to:
      locations: [query]
    payloads:
      - value: "x"
        technique: reflection
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	k, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	before := len(k.Vectors)
	if err := k.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	if len(k.Vectors) != before+1 {
		t.Fatalf("expected %d vectors after merge, got %d", before+1, len(k.Vectors))
	}
	var found *Vector
	for _, v := range k.Vectors {
		if v.ID == "custom-test" {
			found = v
		}
	}
	if found == nil {
		t.Fatal("custom vector not merged")
	}
	if found.Source == "" {
		t.Error("merged vector missing Source provenance")
	}
}
