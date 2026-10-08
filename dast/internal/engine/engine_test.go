package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestForgeJWTNone(t *testing.T) {
	// header.payload.signature — payload is {"sub":"1"} base64url.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	token := "aaa." + payload + ".sig"

	forged := forgeJWTNone("Bearer " + token)
	if !strings.HasPrefix(forged, "Bearer ") {
		t.Fatalf("lost the Bearer prefix: %q", forged)
	}
	parts := strings.Split(strings.TrimPrefix(forged, "Bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("forged token has %d parts, want 3: %q", len(parts), forged)
	}
	if parts[2] != "" {
		t.Errorf("signature should be empty, got %q", parts[2])
	}
	if parts[1] != payload {
		t.Errorf("payload altered: got %q want %q", parts[1], payload)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header not base64url: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("header not JSON: %v", err)
	}
	if hdr["alg"] != "none" {
		t.Errorf("alg = %v, want none", hdr["alg"])
	}
}

func TestForgeJWTNoneBareToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1"}`))
	token := "aaa." + payload + ".sig"
	forged := forgeJWTNone(token)
	if strings.Contains(forged, "Bearer") {
		t.Errorf("should not add a prefix to a bare token: %q", forged)
	}
	if !strings.HasSuffix(forged, ".") {
		t.Errorf("forged bare token should end with empty signature: %q", forged)
	}
}

func TestForgeJWTNonePassThrough(t *testing.T) {
	for _, in := range []string{"not-a-jwt", "Bearer abc", "", "a.b"} {
		if got := forgeJWTNone(in); got != in {
			t.Errorf("forgeJWTNone(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestLimiterDisabledDoesNotBlock(t *testing.T) {
	l := newLimiter(0)
	defer l.close()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			l.wait(context.Background())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disabled limiter blocked")
	}
}

func TestLimiterThrottles(t *testing.T) {
	l := newLimiter(50) // ~20ms between tokens
	defer l.close()
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		l.wait(ctx)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("3 tokens at 50/s returned in %s, expected throttling", elapsed)
	}
}

func TestLimiterRespectsContextCancel(t *testing.T) {
	l := newLimiter(1) // 1/s — slow
	defer l.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		l.wait(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wait did not return on cancelled context")
	}
}
