// Package store defines the persistence contract and an in-memory
// implementation. Handlers depend only on the Store interface, so a Postgres
// implementation can be dropped in without touching HTTP code.
package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrConflict        = errors.New("already exists")
	ErrVersionMismatch = errors.New("version mismatch")
	ErrBadCursor       = errors.New("invalid cursor")
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	PasswordHash string    `json:"-"`
	FailedLogins int       `json:"-"`
	LockedUntil  time.Time `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Task struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Priority    string    `json:"priority"`
	DueDate     string    `json:"due_date,omitempty"` // YYYY-MM-DD
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TaskFilter struct {
	OwnerID string // empty = all owners (admin)
	Status  string
}

type Store interface {
	CreateUser(User) error
	UserByEmail(email string) (User, error)
	UserByID(id string) (User, error)
	UpdateUser(User) error
	ListUsers(cursor string, limit int) ([]User, string, error)

	CreateTask(Task) error
	GetTask(id string) (Task, error)
	// UpdateTask stores t only if the current version equals expected, and
	// increments the version. This is optimistic concurrency control.
	UpdateTask(t Task, expected int64) (Task, error)
	DeleteTask(id string, expected int64) error
	ListTasks(f TaskFilter, cursor string, limit int) ([]Task, string, error)
}

// Cursors are opaque to clients: base64("<unixnano>|<id>"). Keyset (not
// offset) pagination stays stable while rows are inserted or deleted.
func encodeCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.UnixNano(), 10) + "|" + id))
}

func decodeCursor(c string) (int64, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, "", ErrBadCursor
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	n, err := strconv.ParseInt(ts, 10, 64)
	if !ok || err != nil || id == "" {
		return 0, "", ErrBadCursor
	}
	return n, id, nil
}

// newestFirst orders by (created_at DESC, id DESC): a total order, so ties on
// timestamp never cause skipped or repeated rows across pages.
func newestFirst(at, bt time.Time, aid, bid string) int {
	if c := bt.Compare(at); c != 0 {
		return c
	}
	return strings.Compare(bid, aid)
}

func page[T any](items []T, key func(T) (time.Time, string), cursor string, limit int) ([]T, string, error) {
	start := 0
	if cursor != "" {
		ts, id, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", err
		}
		ct := time.Unix(0, ts)
		start = len(items)
		for i, it := range items {
			t, iid := key(it)
			if newestFirst(ct, t, id, iid) < 0 { // strictly after the cursor
				start = i
				break
			}
		}
	}
	end := min(start+limit, len(items))
	out := items[start:end]
	next := ""
	if end < len(items) && len(out) > 0 {
		t, id := key(out[len(out)-1])
		next = encodeCursor(t, id)
	}
	return slices.Clone(out), next, nil
}

type Memory struct {
	mu      sync.RWMutex
	users   map[string]User
	byEmail map[string]string
	tasks   map[string]Task
}

func NewMemory() *Memory {
	return &Memory{users: map[string]User{}, byEmail: map[string]string{}, tasks: map[string]Task{}}
}

func (m *Memory) CreateUser(u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	email := strings.ToLower(u.Email)
	if _, ok := m.byEmail[email]; ok {
		return fmt.Errorf("user %s: %w", email, ErrConflict)
	}
	m.users[u.ID] = u
	m.byEmail[email] = u.ID
	return nil
}

func (m *Memory) UserByEmail(email string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byEmail[strings.ToLower(email)]
	if !ok {
		return User{}, ErrNotFound
	}
	return m.users[id], nil
}

func (m *Memory) UserByID(id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) UpdateUser(u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.ID]; !ok {
		return ErrNotFound
	}
	m.users[u.ID] = u
	return nil
}

func (m *Memory) ListUsers(cursor string, limit int) ([]User, string, error) {
	m.mu.RLock()
	all := make([]User, 0, len(m.users))
	for _, u := range m.users {
		all = append(all, u)
	}
	m.mu.RUnlock()
	slices.SortFunc(all, func(a, b User) int { return newestFirst(a.CreatedAt, b.CreatedAt, a.ID, b.ID) })
	return page(all, func(u User) (time.Time, string) { return u.CreatedAt, u.ID }, cursor, limit)
}

func (m *Memory) CreateTask(t Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tasks[t.ID]; ok {
		return ErrConflict
	}
	m.tasks[t.ID] = t
	return nil
}

func (m *Memory) GetTask(id string) (Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	return t, nil
}

func (m *Memory) UpdateTask(t Task, expected int64) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.tasks[t.ID]
	if !ok {
		return Task{}, ErrNotFound
	}
	if cur.Version != expected {
		return Task{}, ErrVersionMismatch
	}
	t.Version = cur.Version + 1
	t.OwnerID, t.CreatedAt = cur.OwnerID, cur.CreatedAt // immutable fields
	m.tasks[t.ID] = t
	return t, nil
}

func (m *Memory) DeleteTask(id string, expected int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.tasks[id]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != expected {
		return ErrVersionMismatch
	}
	delete(m.tasks, id)
	return nil
}

func (m *Memory) ListTasks(f TaskFilter, cursor string, limit int) ([]Task, string, error) {
	m.mu.RLock()
	var all []Task
	for _, t := range m.tasks {
		if (f.OwnerID == "" || t.OwnerID == f.OwnerID) && (f.Status == "" || t.Status == f.Status) {
			all = append(all, t)
		}
	}
	m.mu.RUnlock()
	slices.SortFunc(all, func(a, b Task) int { return newestFirst(a.CreatedAt, b.CreatedAt, a.ID, b.ID) })
	return page(all, func(t Task) (time.Time, string) { return t.CreatedAt, t.ID }, cursor, limit)
}
