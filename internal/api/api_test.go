package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brianmahlatini/go-rest-api/internal/auth"
	"github.com/brianmahlatini/go-rest-api/internal/store"
)

type env struct {
	t   *testing.T
	ts  *httptest.Server
	st  *store.Memory
	now time.Time
}

func setup(t *testing.T) *env {
	e := &env{t: t, st: store.NewMemory(), now: time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return e.now }
	s := &Server{
		Store: e.st, Hasher: auth.Hasher{Iterations: 1_000}, Now: clock,
		Tokens:         auth.Tokens{Secret: []byte(strings.Repeat("s", 32)), TTL: 15 * time.Minute, Now: clock},
		AllowedOrigins: []string{"http://localhost:5173", "http://localhost:4200"},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	e.ts = httptest.NewServer(s.Routes())
	t.Cleanup(e.ts.Close)
	return e
}

func (e *env) do(method, path, token, body string, hdr ...string) (*http.Response, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

func (e *env) user(email string, admin bool) string {
	e.t.Helper()
	resp, m := e.do("POST", "/v1/auth/register", "", `{"email":"`+email+`","name":"Demo User","password":"a-long-demo-password"}`)
	if resp.StatusCode != 201 {
		e.t.Fatalf("register %d %v", resp.StatusCode, m)
	}
	if admin {
		u, _ := e.st.UserByEmail(email)
		u.Role = RoleAdmin
		e.st.UpdateUser(u)
	}
	resp, m = e.do("POST", "/v1/auth/login", "", `{"email":"`+email+`","password":"a-long-demo-password"}`)
	if resp.StatusCode != 200 {
		e.t.Fatalf("login %d %v", resp.StatusCode, m)
	}
	return m["access_token"].(string)
}

func TestTaskLifecycleWithOptimisticConcurrency(t *testing.T) {
	e := setup(t)
	tok := e.user("alice@example.com", false)

	resp, task := e.do("POST", "/v1/tasks", tok, `{"title":"Ship v1","priority":"high","due_date":"2026-07-01"}`)
	if resp.StatusCode != 201 || resp.Header.Get("ETag") != `"1"` || task["status"] != "todo" {
		t.Fatalf("create %d %v", resp.StatusCode, task)
	}
	id := task["id"].(string)

	if resp, _ := e.do("PATCH", "/v1/tasks/"+id, tok, `{"status":"done"}`); resp.StatusCode != 428 {
		t.Fatalf("PATCH without If-Match must be 428, got %d", resp.StatusCode)
	}
	resp, upd := e.do("PATCH", "/v1/tasks/"+id, tok, `{"status":"in_progress","due_date":null}`, "If-Match", `"1"`)
	if resp.StatusCode != 200 || upd["status"] != "in_progress" || upd["due_date"] != nil || resp.Header.Get("ETag") != `"2"` {
		t.Fatalf("patch %d %v", resp.StatusCode, upd)
	}
	// A second tab still holding version 1 must not overwrite the change.
	if resp, _ := e.do("PATCH", "/v1/tasks/"+id, tok, `{"title":"stale"}`, "If-Match", `"1"`); resp.StatusCode != 412 {
		t.Fatalf("lost update not prevented: %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/v1/tasks/"+id, tok, "", "If-None-Match", `"2"`); resp.StatusCode != 304 {
		t.Fatalf("conditional GET: %d", resp.StatusCode)
	}
	if resp, _ := e.do("DELETE", "/v1/tasks/"+id, tok, "", "If-Match", `"2"`); resp.StatusCode != 204 {
		t.Fatalf("delete %d", resp.StatusCode)
	}
}

func TestOwnershipAndRBAC(t *testing.T) {
	e := setup(t)
	alice := e.user("alice@example.com", false)
	bob := e.user("bob@example.com", false)
	admin := e.user("admin@example.com", true)
	_, task := e.do("POST", "/v1/tasks", alice, `{"title":"private"}`)
	id := task["id"].(string)

	if resp, _ := e.do("GET", "/v1/tasks/"+id, bob, ""); resp.StatusCode != 404 {
		t.Fatalf("other user's task must be 404 (not 403), got %d", resp.StatusCode)
	}
	if resp, _ := e.do("PATCH", "/v1/tasks/"+id, bob, `{"title":"pwned"}`, "If-Match", `"1"`); resp.StatusCode != 404 {
		t.Fatalf("cross-user patch: %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/v1/tasks/"+id, admin, ""); resp.StatusCode != 200 {
		t.Fatal("admin should read any task")
	}
	if resp, _ := e.do("GET", "/v1/admin/users", bob, ""); resp.StatusCode != 403 {
		t.Fatal("member reached admin endpoint")
	}
	if resp, _ := e.do("GET", "/v1/tasks?scope=all", bob, ""); resp.StatusCode != 403 {
		t.Fatal("member used scope=all")
	}
	if _, m := e.do("GET", "/v1/admin/users", admin, ""); len(m["data"].([]any)) != 3 {
		t.Fatalf("admin users: %v", m)
	}
	if _, m := e.do("GET", "/v1/tasks", bob, ""); len(m["data"].([]any)) != 0 {
		t.Fatal("bob sees alice's tasks")
	}
}

func TestPaginationAndFilters(t *testing.T) {
	e := setup(t)
	tok := e.user("p@example.com", false)
	for i := range 7 {
		st := "todo"
		if i%2 == 0 {
			st = "done"
		}
		e.do("POST", "/v1/tasks", tok, `{"title":"t","status":"`+st+`"}`)
		e.now = e.now.Add(time.Second)
	}
	_, p1 := e.do("GET", "/v1/tasks?limit=3", tok, "")
	cur := p1["next_cursor"].(string)
	_, p2 := e.do("GET", "/v1/tasks?limit=3&cursor="+cur, tok, "")
	_, p3 := e.do("GET", "/v1/tasks?limit=3&cursor="+p2["next_cursor"].(string), tok, "")
	if len(p1["data"].([]any))+len(p2["data"].([]any))+len(p3["data"].([]any)) != 7 || p3["next_cursor"] != "" {
		t.Fatalf("pagination broken: %v", p3)
	}
	if _, m := e.do("GET", "/v1/tasks?status=done", tok, ""); len(m["data"].([]any)) != 4 {
		t.Fatalf("filter: %v", m)
	}
	if resp, _ := e.do("GET", "/v1/tasks?status=bogus", tok, ""); resp.StatusCode != 422 {
		t.Fatal("bad filter accepted")
	}
}

func TestAuthHardening(t *testing.T) {
	e := setup(t)
	e.user("lock@example.com", false)
	cases := map[string]int{
		`{"email":"nobody@example.com","password":"a-long-demo-password"}`: 401,
		`{"email":"lock@example.com","password":"wrong-password-123"}`:     401,
	}
	for body, want := range cases {
		resp, m := e.do("POST", "/v1/auth/login", "", body)
		if resp.StatusCode != want || m["detail"] != "invalid email or password" {
			t.Fatalf("%s: %d %v (messages must not reveal which part was wrong)", body, resp.StatusCode, m)
		}
	}
	for range 4 {
		e.do("POST", "/v1/auth/login", "", `{"email":"lock@example.com","password":"wrong-password-123"}`)
	}
	resp, _ := e.do("POST", "/v1/auth/login", "", `{"email":"lock@example.com","password":"a-long-demo-password"}`)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("expected lockout after 5 failures, got %d", resp.StatusCode)
	}
	e.now = e.now.Add(16 * time.Minute)
	if resp, _ := e.do("POST", "/v1/auth/login", "", `{"email":"lock@example.com","password":"a-long-demo-password"}`); resp.StatusCode != 200 {
		t.Fatalf("lockout should expire, got %d", resp.StatusCode)
	}
	for body, want := range map[string]int{
		`{"email":"not-an-email","name":"x","password":"a-long-demo-password"}`:                 422,
		`{"email":"short@example.com","name":"x","password":"short"}`:                           422,
		`{"email":"lock@example.com","name":"x","password":"a-long-demo-password"}`:             409,
		`{"email":"x@example.com","name":"x","password":"a-long-demo-password","role":"admin"}`: 400,
	} {
		if resp, m := e.do("POST", "/v1/auth/register", "", body); resp.StatusCode != want {
			t.Errorf("%s: got %d want %d %v", body, resp.StatusCode, want, m)
		}
	}
	if resp, _ := e.do("GET", "/v1/me", "garbage.token.here", ""); resp.StatusCode != 401 {
		t.Fatal("bad token accepted")
	}
}

func TestValidationAndCORS(t *testing.T) {
	e := setup(t)
	tok := e.user("v@example.com", false)
	for body, field := range map[string]string{
		`{"title":""}`:                        "title",
		`{"title":"x","status":"archived"}`:   "status",
		`{"title":"x","due_date":"01/07/26"}`: "due_date",
	} {
		if resp, m := e.do("POST", "/v1/tasks", tok, body); resp.StatusCode != 422 || m["field"] != field {
			t.Errorf("%s: %d %v", body, resp.StatusCode, m)
		}
	}
	resp, _ := e.do("OPTIONS", "/v1/tasks", "", "", "Origin", "http://localhost:4200", "Access-Control-Request-Method", "PATCH")
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "http://localhost:4200" ||
		!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "If-Match") {
		t.Fatalf("preflight for Angular dev origin failed: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = e.do("GET", "/v1/me", tok, "", "Origin", "http://localhost:5173")
	if !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "ETag") {
		t.Fatal("SPA cannot read ETag without Access-Control-Expose-Headers")
	}
	resp, _ = e.do("GET", "/v1/me", tok, "", "Origin", "https://evil.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unlisted origin allowed")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}
