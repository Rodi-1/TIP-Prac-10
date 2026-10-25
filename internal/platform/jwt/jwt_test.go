package jwt

import (
	lib "github.com/golang-jwt/jwt/v5"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRotationRefreshAndValidation(t *testing.T) {
	dir := t.TempDir()
	if e := GenerateKeys(dir); e != nil {
		t.Fatal(e)
	}
	a, e := NewManager(dir, "key1", 15*time.Minute, 7*24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewManager(dir, "key2", 15*time.Minute, 7*24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	first, e := a.NewPair(2, "user@example.com", "user")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Parse(first.Access); e != nil {
		t.Fatalf("old key validation: %v", e)
	}
	second, e := b.NewPair(2, "user@example.com", "user")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Parse(second.Access); e != nil {
		t.Fatal(e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := b.Rotate(second.Refresh); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("refresh replay allowed")
	}
	if _, e = b.Rotate(first.Access); e == nil {
		t.Fatal("access accepted as refresh")
	}
	for _, c := range []lib.MapClaims{{"iss": "pz10-auth", "aud": "pz10-clients", "exp": time.Now().Add(-time.Hour).Unix()}, {"iss": "wrong", "aud": "pz10-clients", "exp": time.Now().Add(time.Hour).Unix()}, {"iss": "pz10-auth", "aud": "wrong", "exp": time.Now().Add(time.Hour).Unix()}, {"iss": "pz10-auth", "aud": "pz10-clients"}} {
		tok := lib.NewWithClaims(lib.SigningMethodRS256, c)
		tok.Header["kid"] = "key1"
		raw, e := tok.SignedString(a.keys["key1"])
		if e != nil {
			t.Fatal(e)
		}
		if _, e = b.Parse(raw); e == nil {
			t.Fatal("invalid claims accepted")
		}
	}
	tok := lib.NewWithClaims(lib.SigningMethodHS256, lib.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = "key1"
	raw, _ := tok.SignedString([]byte("test"))
	if _, e = b.Parse(raw); e == nil {
		t.Fatal("wrong algorithm accepted")
	}
}
