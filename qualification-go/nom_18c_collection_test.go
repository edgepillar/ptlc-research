// Original post-wrapper collection boundary probes for the pinned source.
// The scripted iterator is not a physical storage or networking implementation.
package definition

import (
	"bytes"
	"errors"
	"math/big"
	"sort"
	"testing"

	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

type research18cCollectionRow struct{ key, value []byte }
type research18cCollectionIterator struct {
	rows []research18cCollectionRow
	position int
	fault error
	releases int
}
func (i *research18cCollectionIterator) Next() bool { i.position++; return i.position < len(i.rows) }
func (i *research18cCollectionIterator) Prev() bool { panic("reverse operation outside selected collection scope") }
func (i *research18cCollectionIterator) Last() bool { panic("reverse operation outside selected collection scope") }
func (i *research18cCollectionIterator) Key() []byte { return i.rows[i.position].key }
func (i *research18cCollectionIterator) Value() []byte { return i.rows[i.position].value }
func (i *research18cCollectionIterator) Error() error { return i.fault }
func (i *research18cCollectionIterator) Release() { i.releases++ }

type research18cCollectionDB struct {
	db.DB
	prefix []byte
	rows []research18cCollectionRow
	fault error
	latest *research18cCollectionIterator
}
func (d *research18cCollectionDB) NewIterator(prefix []byte) db.StorageIterator {
	if !bytes.Equal(prefix, d.prefix) { panic("unexpected selected collection prefix") }
	d.latest = &research18cCollectionIterator{rows: d.rows, position: -1, fault: d.fault}
	return d.latest
}

func research18cCollection(t *testing.T, project, valid bool, fault error) (*research18cCollectionDB, types.Address) {
	t.Helper()
	var rows []research18cCollectionRow
	var owner types.Address
	for n := byte(1); n <= 3; n++ {
		address := make([]byte, 20)
		address[len(address)-1] = n
		selected, err := types.BytesToAddress(address)
		if err != nil { t.Fatal(err) }
		var key, data []byte
		if project {
			item := &Project{Id: types.NewHash([]byte{n}), Owner: selected,
				Name: "synthetic selected project", ZnnFundsNeeded: big.NewInt(10), QsrFundsNeeded: big.NewInt(20)}
			key, data = item.Key(), item.Data()
		} else {
			item := &SentinelInfo{SentinelInfoKey: SentinelInfoKey{Owner: selected}, ZnnAmount: big.NewInt(10), QsrAmount: big.NewInt(20)}
			key, data = item.Key(), item.Data()
		}
		if n != 2 || !valid {
			data = nil
			if n == 3 { data = []byte{} }
		} else { owner = selected }
		rows = append(rows, research18cCollectionRow{key, data})
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].key, rows[j].key) < 0 })
	return &research18cCollectionDB{DB: db.NewMemDB(), prefix: rows[0].key[:1], rows: rows, fault: fault}, owner
}

func research18cReleased(t *testing.T, context *research18cCollectionDB) {
	t.Helper()
	if context.latest == nil || context.latest.releases != 1 { t.Fatal("selected collection did not release its iterator exactly once") }
}

func TestPTLCResearchCollectionEmptyRows(t *testing.T) {
	t.Run("sentinel_get_all", func(t *testing.T) {
		context, owner := research18cCollection(t, false, true, nil)
		values := GetAllSentinelInfo(context)
		if len(values) != 1 || values[0].Owner != owner { t.Fatal("empty sentinel values were not skipped separately from the live row") }
		research18cReleased(t, context)
	})
	t.Run("sentinel_iterate", func(t *testing.T) {
		context, owner := research18cCollection(t, false, true, nil)
		calls := 0
		err := IterateSentinelEntries(context, func(value *SentinelInfo) error {
			calls++
			if value.Owner != owner { t.Fatal("unexpected selected sentinel") }
			return nil
		})
		if err != nil || calls != 1 { t.Fatalf("unexpected selected callback result: calls=%d error=%v", calls, err) }
		research18cReleased(t, context)
	})
	t.Run("project_get_list", func(t *testing.T) {
		context, owner := research18cCollection(t, true, true, nil)
		values, err := GetProjectList(context)
		if err != nil || len(values) != 1 || values[0].Owner != owner { t.Fatal("empty project values were not skipped separately from the live row") }
		research18cReleased(t, context)
	})
	t.Run("sentinel_callback_refusal", func(t *testing.T) {
		context, _ := research18cCollection(t, false, true, nil)
		fault := errors.New("synthetic selected callback refusal")
		calls := 0
		err := IterateSentinelEntries(context, func(*SentinelInfo) error { calls++; return fault })
		if !errors.Is(err, fault) || calls != 1 { t.Fatal("callback refusal was converted into collection success") }
		research18cReleased(t, context)
	})
}

func TestPTLCResearchCollectionIteratorErrors(t *testing.T) {
	for _, name := range []string{"sentinel_get_all", "sentinel_iterate", "project_get_list"} {
		t.Run(name, func(t *testing.T) {
			fault := errors.New("synthetic selected collection iterator failure")
			context, _ := research18cCollection(t, name == "project_get_list", false, fault)
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				switch name {
				case "sentinel_get_all": GetAllSentinelInfo(context)
				case "sentinel_iterate":
					_ = IterateSentinelEntries(context, func(*SentinelInfo) error { t.Fatal("an empty row reached the callback"); return nil })
				case "project_get_list": _, _ = GetProjectList(context)
				}
			}()
			actual, ok := recovered.(error)
			if !ok || !errors.Is(actual, fault) { t.Fatalf("iterator failure did not retain its existing panic boundary: %v", recovered) }
			research18cReleased(t, context)
		})
	}
}
