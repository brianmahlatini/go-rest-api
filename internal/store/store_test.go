package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestKeysetPaginationIsStableUnderTies(t *testing.T) {
	m := NewMemory()
	same := time.Unix(1_900_000_000, 0)
	for i := range 25 {
		m.CreateTask(Task{ID: fmt.Sprintf("tsk_%02d", i), OwnerID: "u1", CreatedAt: same.Add(time.Duration(i%5) * time.Second), Status: "todo"})
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		items, next, err := m.ListTasks(TaskFilter{OwnerID: "u1"}, cursor, 7)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if seen[it.ID] {
				t.Fatalf("%s returned twice", it.ID)
			}
			seen[it.ID] = true
		}
		pages++
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 25 || pages != 4 {
		t.Fatalf("saw %d items in %d pages", len(seen), pages)
	}
	if _, _, err := m.ListTasks(TaskFilter{}, "!!", 5); !errors.Is(err, ErrBadCursor) {
		t.Fatalf("got %v", err)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	m := NewMemory()
	m.CreateTask(Task{ID: "t1", OwnerID: "u1", Title: "a", Version: 1})
	cur, _ := m.GetTask("t1")
	cur.Title = "b"
	updated, err := m.UpdateTask(cur, 1)
	if err != nil || updated.Version != 2 {
		t.Fatalf("%v %+v", err, updated)
	}
	cur.Title = "lost update"
	if _, err := m.UpdateTask(cur, 1); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale write accepted: %v", err)
	}
	if err := m.DeleteTask("t1", 1); !errors.Is(err, ErrVersionMismatch) {
		t.Fatal("stale delete accepted")
	}
}

func TestEmailUniquenessIsCaseInsensitive(t *testing.T) {
	m := NewMemory()
	m.CreateUser(User{ID: "u1", Email: "Demo@Example.com"})
	if err := m.CreateUser(User{ID: "u2", Email: "demo@example.com"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
}
