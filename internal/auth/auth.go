// Package auth provides password hashing (PBKDF2-SHA256) and HS256 access
// tokens using only the standard library.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrBadHash      = errors.New("unrecognised password hash")
)

// DefaultIterations follows the OWASP 2023+ guidance for PBKDF2-HMAC-SHA256.
const DefaultIterations = 600_000

type Hasher struct{ Iterations int }

// Hash returns "pbkdf2-sha256$<iter>$<salt>$<key>". The iteration count is
// stored per hash so it can be raised later without invalidating users.
func (h Hasher) Hash(password string) (string, error) {
	iter := h.Iterations
	if iter <= 0 {
		iter = DefaultIterations
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// Verify reports whether password matches, and whether the hash should be
// upgraded because it uses fewer iterations than currently configured.
func (h Hasher) Verify(encoded, password string) (ok, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false, false, ErrBadHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, false, ErrBadHash
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false, false, ErrBadHash
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, false, err
	}
	target := h.Iterations
	if target <= 0 {
		target = DefaultIterations
	}
	return subtle.ConstantTimeCompare(got, want) == 1, iter < target, nil
}

type Claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type Tokens struct {
	Secret []byte
	TTL    time.Duration
	Now    func() time.Time
}

var b64 = base64.RawURLEncoding

const header = `{"alg":"HS256","typ":"JWT"}`

func (t Tokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t Tokens) sign(unsigned string) []byte {
	m := hmac.New(sha256.New, t.Secret)
	m.Write([]byte(unsigned))
	return m.Sum(nil)
}

func (t Tokens) Issue(sub, role string) (string, time.Time, error) {
	if len(t.Secret) < 32 {
		return "", time.Time{}, errors.New("token secret must be at least 32 bytes")
	}
	now := t.now()
	exp := now.Add(t.TTL)
	p, err := json.Marshal(Claims{Subject: sub, Role: role, IssuedAt: now.Unix(), ExpiresAt: exp.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	u := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(p)
	return u + "." + b64.EncodeToString(t.sign(u)), exp, nil
}

// Parse verifies the token. The header must be exactly the one this service
// issues, which pins the algorithm and rules out alg=none/key confusion.
func (t Tokens) Parse(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 4096 {
		return Claims{}, ErrInvalidToken
	}
	if h, err := b64.DecodeString(parts[0]); err != nil || string(h) != header {
		return Claims{}, ErrInvalidToken
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, t.sign(parts[0]+"."+parts[1])) {
		return Claims{}, ErrInvalidToken
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil || c.Subject == "" {
		return Claims{}, ErrInvalidToken
	}
	if !t.now().Before(time.Unix(c.ExpiresAt, 0)) {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}
