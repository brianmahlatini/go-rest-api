// Package api is a framework-free REST API for tasks, built on net/http
// routing patterns (Go 1.22+). It is designed as the backend for React and
// Angular single-page apps: CORS allowlist, exposed ETag header, JSON errors.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/brianmahlatini/go-rest-api/internal/auth"
	"github.com/brianmahlatini/go-rest-api/internal/store"
)

const (
	RoleMember = "member"
	RoleAdmin  = "admin"

	maxFailedLogins = 5
	lockoutDuration = 15 * time.Minute
)

var (
	statuses   = []string{"todo", "in_progress", "done"}
	priorities = []string{"low", "medium", "high"}
)

type Server struct {
	Store          store.Store
	Hasher         auth.Hasher
	Tokens         auth.Tokens
	AllowedOrigins []string // exact origins, e.g. http://localhost:5173
	Log            *slog.Logger
	Now            func() time.Time

	dummyOnce sync.Once
	dummyHash string
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/auth/register", s.register)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.Handle("GET /v1/me", s.authn(http.HandlerFunc(s.me)))
	mux.Handle("GET /v1/tasks", s.authn(http.HandlerFunc(s.listTasks)))
	mux.Handle("POST /v1/tasks", s.authn(http.HandlerFunc(s.createTask)))
	mux.Handle("GET /v1/tasks/{id}", s.authn(http.HandlerFunc(s.getTask)))
	mux.Handle("PATCH /v1/tasks/{id}", s.authn(http.HandlerFunc(s.patchTask)))
	mux.Handle("DELETE /v1/tasks/{id}", s.authn(http.HandlerFunc(s.deleteTask)))
	mux.Handle("GET /v1/admin/users", s.authn(s.requireRole(RoleAdmin, http.HandlerFunc(s.listUsers))))
	return s.recoverer(s.logRequests(s.securityHeaders(s.cors(mux))))
}

// ---------- responses ----------

type apiError struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Field  string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, code int, detail, field string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(apiError{Status: code, Title: http.StatusText(code), Detail: detail, Field: field})
}

type validationError struct{ field, msg string }

func (e validationError) Error() string { return e.field + ": " + e.msg }

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve validationError
	switch {
	case errors.As(err, &ve):
		problem(w, http.StatusUnprocessableEntity, ve.msg, ve.field)
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "resource not found", "")
	case errors.Is(err, store.ErrConflict):
		problem(w, http.StatusConflict, "resource already exists", "")
	case errors.Is(err, store.ErrVersionMismatch):
		problem(w, http.StatusPreconditionFailed, "resource was modified by someone else; refetch and retry", "")
	case errors.Is(err, store.ErrBadCursor):
		problem(w, http.StatusBadRequest, "invalid cursor", "cursor")
	default:
		s.Log.ErrorContext(r.Context(), "internal error", "err", err, "request_id", requestID(r.Context()))
		problem(w, http.StatusInternalServerError, "internal error", "")
	}
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") && !strings.HasPrefix(ct, "application/merge-patch+json") {
		return errors.New("content-type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("body must be a single JSON object")
	}
	return nil
}

func newID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b[:])
}

// ---------- auth ----------

type principal struct{ ID, Role string }

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyRequestID
)

func who(ctx context.Context) principal { p, _ := ctx.Value(keyPrincipal).(principal); return p }
func requestID(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

func (s *Server) authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer`)
			problem(w, http.StatusUnauthorized, "bearer token required", "")
			return
		}
		c, err := s.Tokens.Parse(tok)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			problem(w, http.StatusUnauthorized, "invalid or expired token", "")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyPrincipal, principal{ID: c.Subject, Role: c.Role})))
	})
}

func (s *Server) requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if who(r.Context()).Role != role {
			problem(w, http.StatusForbidden, "insufficient role", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validPassword(p string) error {
	if n := utf8.RuneCountInString(p); n < 12 || n > 128 {
		return validationError{"password", "must be 12-128 characters"}
	}
	return nil
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Name, Password string }
	if err := decode(w, r, &in); err != nil {
		problem(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	addr, err := mail.ParseAddress(in.Email)
	if err != nil || addr.Address != in.Email || len(in.Email) > 254 {
		s.fail(w, r, validationError{"email", "must be a valid email address"})
		return
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(in.Name)); n < 1 || n > 100 {
		s.fail(w, r, validationError{"name", "must be 1-100 characters"})
		return
	}
	if err := validPassword(in.Password); err != nil {
		s.fail(w, r, err)
		return
	}
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u := store.User{ID: newID("usr_"), Email: strings.ToLower(in.Email), Name: strings.TrimSpace(in.Name), Role: RoleMember, PasswordHash: hash, CreatedAt: s.now()}
	if err := s.Store.CreateUser(u); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// login returns the same error for unknown email and wrong password, and does
// equivalent hashing work in both cases, so accounts cannot be enumerated by
// message or timing. Repeated failures lock the account temporarily.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if err := decode(w, r, &in); err != nil {
		problem(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	denied := func() { problem(w, http.StatusUnauthorized, "invalid email or password", "") }
	u, err := s.Store.UserByEmail(in.Email)
	if err != nil {
		s.dummyOnce.Do(func() { s.dummyHash, _ = s.Hasher.Hash("dummy-password-for-timing") })
		_, _, _ = s.Hasher.Verify(s.dummyHash, in.Password)
		denied()
		return
	}
	now := s.now()
	if now.Before(u.LockedUntil) {
		w.Header().Set("Retry-After", strconv.Itoa(int(u.LockedUntil.Sub(now).Seconds())+1))
		problem(w, http.StatusTooManyRequests, "too many failed attempts; try again later", "")
		return
	}
	ok, rehash, err := s.Hasher.Verify(u.PasswordHash, in.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		u.FailedLogins++
		if u.FailedLogins >= maxFailedLogins {
			u.FailedLogins, u.LockedUntil = 0, now.Add(lockoutDuration)
			s.Log.Warn("account locked", "user_id", u.ID)
		}
		_ = s.Store.UpdateUser(u)
		denied()
		return
	}
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	if rehash { // transparently upgrade old hashes on successful login
		if h, err := s.Hasher.Hash(in.Password); err == nil {
			u.PasswordHash = h
		}
	}
	_ = s.Store.UpdateUser(u)
	tok, exp, err := s.Tokens.Issue(u.ID, u.Role)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_at": exp.UTC()})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.UserByID(who(r.Context()).ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, next, err := s.Store.ListUsers(r.URL.Query().Get("cursor"), limit(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": users, "next_cursor": next})
}

// ---------- tasks ----------

func limit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n < 1 || n > 100 {
		return 20
	}
	return n
}

func etag(t store.Task) string { return `"` + strconv.FormatInt(t.Version, 10) + `"` }

// ifMatch requires a strong ETag precondition: without it, two browser tabs
// editing the same task silently overwrite each other (lost update).
func ifMatch(w http.ResponseWriter, r *http.Request) (int64, bool) {
	h := r.Header.Get("If-Match")
	if h == "" {
		problem(w, http.StatusPreconditionRequired, "If-Match header with the task's ETag is required", "")
		return 0, false
	}
	v, err := strconv.ParseInt(strings.Trim(h, `"`), 10, 64)
	if err != nil {
		problem(w, http.StatusPreconditionFailed, "malformed If-Match", "")
		return 0, false
	}
	return v, true
}

func validateTask(t store.Task) error {
	switch {
	case utf8.RuneCountInString(strings.TrimSpace(t.Title)) < 1 || utf8.RuneCountInString(t.Title) > 200:
		return validationError{"title", "must be 1-200 characters"}
	case utf8.RuneCountInString(t.Description) > 5000:
		return validationError{"description", "must be at most 5000 characters"}
	case !slices.Contains(statuses, t.Status):
		return validationError{"status", "must be one of " + strings.Join(statuses, ", ")}
	case !slices.Contains(priorities, t.Priority):
		return validationError{"priority", "must be one of " + strings.Join(priorities, ", ")}
	}
	if t.DueDate != "" {
		if _, err := time.Parse(time.DateOnly, t.DueDate); err != nil {
			return validationError{"due_date", "must be YYYY-MM-DD"}
		}
	}
	return nil
}

// loadOwned returns 404 (not 403) for tasks the caller may not see, so task
// IDs cannot be probed for existence.
func (s *Server) loadOwned(r *http.Request) (store.Task, error) {
	t, err := s.Store.GetTask(r.PathValue("id"))
	if err != nil {
		return store.Task{}, err
	}
	p := who(r.Context())
	if t.OwnerID != p.ID && p.Role != RoleAdmin {
		return store.Task{}, store.ErrNotFound
	}
	return t, nil
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Priority    string `json:"priority"`
		DueDate     string `json:"due_date"`
	}
	if err := decode(w, r, &in); err != nil {
		problem(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	now := s.now()
	t := store.Task{
		ID: newID("tsk_"), OwnerID: who(r.Context()).ID, Title: strings.TrimSpace(in.Title), Description: in.Description,
		Status: cmp(in.Status, "todo"), Priority: cmp(in.Priority, "medium"), DueDate: in.DueDate,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := validateTask(t); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.CreateTask(t); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tasks/"+t.ID)
	w.Header().Set("ETag", etag(t))
	writeJSON(w, http.StatusCreated, t)
}

func cmp(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	t, err := s.loadOwned(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(t))
	if r.Header.Get("If-None-Match") == etag(t) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// patchTask applies JSON Merge Patch (RFC 7396) semantics to the mutable
// fields: absent = unchanged, null = cleared (where clearing is meaningful).
func (s *Server) patchTask(w http.ResponseWriter, r *http.Request) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var in struct {
		Title       *string         `json:"title"`
		Description json.RawMessage `json:"description"`
		Status      *string         `json:"status"`
		Priority    *string         `json:"priority"`
		DueDate     json.RawMessage `json:"due_date"`
	}
	if err := decode(w, r, &in); err != nil {
		problem(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	t, err := s.loadOwned(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Title != nil {
		t.Title = strings.TrimSpace(*in.Title)
	}
	if in.Status != nil {
		t.Status = *in.Status
	}
	if in.Priority != nil {
		t.Priority = *in.Priority
	}
	for field, raw := range map[string]json.RawMessage{"description": in.Description, "due_date": in.DueDate} {
		if raw == nil {
			continue
		}
		var v *string
		if err := json.Unmarshal(raw, &v); err != nil {
			s.fail(w, r, validationError{field, "must be a string or null"})
			return
		}
		val := ""
		if v != nil {
			val = *v
		}
		if field == "description" {
			t.Description = val
		} else {
			t.DueDate = val
		}
	}
	if err := validateTask(t); err != nil {
		s.fail(w, r, err)
		return
	}
	t.UpdatedAt = s.now()
	updated, err := s.Store.UpdateTask(t, expected)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(updated))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteTask(w http.ResponseWriter, r *http.Request) {
	expected, ok := ifMatch(w, r)
	if !ok {
		return
	}
	t, err := s.loadOwned(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteTask(t.ID, expected); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := who(r.Context())
	f := store.TaskFilter{OwnerID: p.ID, Status: q.Get("status")}
	if f.Status != "" && !slices.Contains(statuses, f.Status) {
		s.fail(w, r, validationError{"status", "unknown status filter"})
		return
	}
	if q.Get("scope") == "all" {
		if p.Role != RoleAdmin {
			problem(w, http.StatusForbidden, "scope=all requires admin", "")
			return
		}
		f.OwnerID = ""
	}
	tasks, next, err := s.Store.ListTasks(f, q.Get("cursor"), limit(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if tasks == nil {
		tasks = []store.Task{} // SPAs expect [], not null
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": tasks, "next_cursor": next})
}

// ---------- middleware ----------

// cors implements an exact-match origin allowlist. Wildcards are never
// combined with credentials, and Vary: Origin keeps caches correct.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(s.AllowedOrigins, origin) {
			h := w.Header()
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Expose-Headers", "ETag, Location, Retry-After, X-Request-Id")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, If-None-Match")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newID("")[:16]
		}
		w.Header().Set("X-Request-Id", id)
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), keyRequestID, id)))
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", id)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic", "value", fmt.Sprint(v), "path", r.URL.Path)
				problem(w, http.StatusInternalServerError, "internal error", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
