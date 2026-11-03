// Original finite research probes for the separately acquired pinned source.
// This file is copied into common/db only in a newly owned qualification view.
package db

import (
	"errors"
	"reflect"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

type research18cRow struct{ key, value string }

func research18cRows(t *testing.T, view DB, prefix string, expected []research18cRow) {
	t.Helper()
	iterator := view.NewIterator([]byte(prefix))
	defer iterator.Release()
	var actual []research18cRow
	for iterator.Next() {
		actual = append(actual, research18cRow{string(iterator.Key()), string(iterator.Value())})
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected selected rows: got %v, want %v", actual, expected)
	}
}

func research18cValue(t *testing.T, view DB, key, expected string) {
	t.Helper()
	value, err := view.Get([]byte(key))
	if err != nil || string(value) != expected {
		t.Fatalf("unexpected selected lookup for %q: value=%q error=%v", key, value, err)
	}
	present, err := view.Has([]byte(key))
	if err != nil || !present {
		t.Fatalf("live lookup was not present: %q error=%v", key, err)
	}
}

func research18cMissing(t *testing.T, view DB, key string) {
	t.Helper()
	if value, err := view.Get([]byte(key)); err != leveldb.ErrNotFound {
		t.Fatalf("missing lookup did not retain ErrNotFound: value=%q error=%v", value, err)
	}
	if present, err := view.Has([]byte(key)); err != nil || present {
		t.Fatalf("deleted lookup remained present: %q error=%v", key, err)
	}
}

func research18cPut(t *testing.T, view DB, key, value string) {
	t.Helper()
	if err := view.Put([]byte(key), []byte(value)); err != nil {
		t.Fatal(err)
	}
}

func research18cDelete(t *testing.T, view DB, key string) {
	t.Helper()
	if err := view.Delete([]byte(key)); err != nil {
		t.Fatal(err)
	}
}

func TestPTLCResearchStorageComposition(t *testing.T) {
	t.Run("snapshot_delete_mask", func(t *testing.T) {
		base := NewMemDB()
		for _, row := range []research18cRow{{"p/a", "A"}, {"p/b", "B"}, {"p/c", "C"}} {
			research18cPut(t, base, row.key, row.value)
		}
		child := base.Snapshot()
		research18cDelete(t, child, "p/b")
		research18cRows(t, child, "p/", []research18cRow{{"p/a", "A"}, {"p/c", "C"}})
		research18cMissing(t, child, "p/b")
		research18cValue(t, base, "p/b", "B")
	})
	t.Run("nested_snapshots", func(t *testing.T) {
		base := NewMemDB()
		research18cPut(t, base, "p/a", "base")
		deleted := base.Snapshot()
		research18cDelete(t, deleted, "p/a")
		restored := deleted.Snapshot()
		research18cPut(t, restored, "p/a", "restored")
		deletedAgain := restored.Snapshot()
		research18cDelete(t, deletedAgain, "p/a")
		research18cRows(t, deleted, "p/", nil)
		research18cRows(t, restored, "p/", []research18cRow{{"p/a", "restored"}})
		research18cRows(t, deletedAgain, "p/", nil)
		research18cMissing(t, deleted, "p/a")
		research18cMissing(t, deletedAgain, "p/a")
		research18cValue(t, restored, "p/a", "restored")
		research18cValue(t, base, "p/a", "base")
	})
	t.Run("live_empty_value", func(t *testing.T) {
		base := NewMemDB()
		research18cPut(t, base, "p/a", "old")
		research18cPut(t, base, "p/b", "deleted")
		child := base.Snapshot()
		research18cPut(t, child, "p/a", "")
		research18cDelete(t, child, "p/b")
		research18cRows(t, child, "p/", []research18cRow{{"p/a", ""}})
		research18cValue(t, child, "p/a", "")
		research18cMissing(t, child, "p/b")
		research18cValue(t, base, "p/a", "old")
	})
	t.Run("subset_complete_prefix", func(t *testing.T) {
		base := NewMemDB()
		for _, row := range []research18cRow{{"p/a", "A"}, {"p/b", "B"}, {"p0/a", "adjacent"}, {"q/a", "foreign"}} {
			research18cPut(t, base, row.key, row.value)
		}
		child := base.Snapshot()
		subset := child.Subset([]byte("p/"))
		research18cDelete(t, subset, "b")
		research18cRows(t, child, "p/", []research18cRow{{"p/a", "A"}})
		research18cRows(t, subset, "", []research18cRow{{"a", "A"}})
		research18cMissing(t, subset, "b")
		research18cValue(t, child, "p0/a", "adjacent")
		research18cValue(t, child, "q/a", "foreign")
		research18cValue(t, base, "p/b", "B")
	})
	t.Run("snapshot_reverse_errors", func(t *testing.T) {
		base := NewMemDB()
		research18cPut(t, base, "p/a", "A")
		view := base.Snapshot()
		for _, method := range []string{"Prev", "Last"} {
			iterator := view.NewIterator([]byte("p/"))
			var moved bool
			if method == "Prev" {
				moved = iterator.Prev()
			} else {
				moved = iterator.Last()
			}
			err := iterator.Error()
			iterator.Release()
			if moved || err == nil {
				t.Fatalf("merged %s lost its unsupported-operation error: moved=%v error=%v", method, moved, err)
			}
		}
	})
	t.Run("leveldb_pop_reopen", func(t *testing.T) {
		directory := t.TempDir()
		var current Manager
		t.Cleanup(func() {
			if current != nil {
				if err := current.Stop(); err != nil {
					t.Error(err)
				}
			}
		})
		open := func() {
			var err error
			current, err = NewLevelDBManager(directory)
			if err != nil {
				t.Fatal(err)
			}
		}
		open()
		// keyedTransaction is part of this exact pinned upstream test package.
		for _, row := range []research18cRow{{"p/a", "A"}, {"p/b", "B"}, {"q/a", "foreign"}} {
			if err := current.Add(keyedTransaction(current.Frontier(), row.key, row.value)); err != nil {
				t.Fatal(err)
			}
		}
		identifier := GetFrontierIdentifier(current.Frontier())
		if err := current.Add(keyedTransaction(current.Frontier(), "p/c", "later")); err != nil {
			t.Fatal(err)
		}
		historical := current.Get(identifier)
		expected := []research18cRow{{"p/a", "A"}, {"p/b", "B"}}
		research18cRows(t, historical, "p/", expected)
		research18cMissing(t, historical, "p/c")
		if err := current.Pop(); err != nil {
			t.Fatal(err)
		}
		research18cRows(t, current.Frontier(), "p/", expected)
		research18cMissing(t, current.Frontier(), "p/c")
		err := current.Stop()
		current = nil
		if err != nil {
			t.Fatal(err)
		}
		open()
		research18cRows(t, current.Frontier(), "p/", expected)
		research18cMissing(t, current.Frontier(), "p/c")
		research18cValue(t, current.Frontier(), "q/a", "foreign")
	})
}

// Only iterator forwarding is fault-injected. This is not physical IO evidence.
type research18cFaultIterator struct {
	fault    error
	steps    int
	releases int
}

func (i *research18cFaultIterator) Next() bool { i.steps++; return i.steps == 1 }
func (i *research18cFaultIterator) Prev() bool { i.steps++; return i.steps == 1 }
func (i *research18cFaultIterator) Last() bool { return true }
func (i *research18cFaultIterator) Key() []byte { return []byte("p/deleted") }
func (i *research18cFaultIterator) Value() []byte { return nil }
func (i *research18cFaultIterator) Error() error {
	if i.steps > 1 { return i.fault }
	return nil
}
func (i *research18cFaultIterator) Release() { i.releases++ }

func TestPTLCResearchIteratorErrorForwarding(t *testing.T) {
	for _, name := range []string{"Next", "Prev", "Last"} {
		t.Run(name, func(t *testing.T) {
			fault := errors.New("synthetic selected iterator failure")
			raw := &research18cFaultIterator{fault: fault}
			iterator := newEnableDeleteIterator(raw)
			var moved bool
			switch name {
			case "Next": moved = iterator.Next()
			case "Prev": moved = iterator.Prev()
			case "Last": moved = iterator.Last()
			}
			if moved || !errors.Is(iterator.Error(), fault) || raw.steps != 2 {
				t.Fatalf("selected %s did not preserve its failure after a tombstone", name)
			}
			iterator.Release()
			if raw.releases != 1 { t.Fatal("iterator release was not forwarded exactly once") }
		})
	}
}
