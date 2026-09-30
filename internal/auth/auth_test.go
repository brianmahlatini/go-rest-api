package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	h := Hasher{Iterations: 1_000}
	enc, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := h.Verify(enc, "correct horse battery staple"); !ok || rehash {
		t.Fatal("valid password rejected")
	}
	if ok, _, _ := h.Verify(enc, "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	other, _ := h.Hash("correct horse battery staple")
	if other == enc {
		t.Fatal("salts must differ per hash")
	}
	if _, rehash, _ := (Hasher{Iterations: 2_000}).Verify(enc, "correct horse battery staple"); !rehash {
		t.Fatal("weaker hash should be flagged for rehash")
	}
	if _, _, err := h.Verify("md5$abc", "x"); err != ErrBadHash {
		t.Fatalf("got %v", err)
	}
}

func TestTokens(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	tk := Tokens{Secret: []byte(strings.Repeat("k", 32)), TTL: 15 * time.Minute, Now: func() time.Time { return now }}
	tok, _, err := tk.Issue("usr_1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := tk.Parse(tok)
	if err != nil || c.Subject != "usr_1" || c.Role != "admin" {
		t.Fatalf("%v %+v", err, c)
	}
	parts := strings.Split(tok, ".")
	forged := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."
	other := Tokens{Secret: []byte(strings.Repeat("x", 32)), TTL: time.Minute, Now: tk.Now}
	wrongKey, _, _ := other.Issue("usr_1", "admin")
	for name, bad := range map[string]string{"alg none": forged, "wrong key": wrongKey, "garbage": "a.b.c", "truncated": parts[0] + "." + parts[1]} {
		if _, err := tk.Parse(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	now = now.Add(16 * time.Minute)
	if _, err := tk.Parse(tok); err == nil {
		t.Fatal("expired token accepted")
	}
}
