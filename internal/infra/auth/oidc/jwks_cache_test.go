package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSCache_KidMissRefreshes(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := "https://jwks.test/keys"
	jwks1 := buildJWKS(t, &privKey.PublicKey, "kid-1")
	jwks2 := buildJWKS(t, &privKey.PublicKey, "kid-2")
	var calls int32
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != jwksURL {
				return jsonResponse(http.StatusNotFound, `{}`), nil
			}
			call := atomic.AddInt32(&calls, 1)
			if call == 1 {
				return jsonResponse(http.StatusOK, jwks1), nil
			}
			return jsonResponse(http.StatusOK, jwks2), nil
		}),
	}
	cache := newJWKSCache(jwksURL, client)

	if _, err := cache.getKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("get kid-1: %v", err)
	}
	if _, err := cache.getKey(context.Background(), "kid-2"); err != nil {
		t.Fatalf("get kid-2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("expected refresh on kid miss, got %d fetches", got)
	}
}

func TestJWKSCache_StaleKeysUsedUntilMaxStale(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := "https://jwks.test/keys"
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("fetch failed")
		}),
	}
	cache := newJWKSCache(jwksURL, client)
	now := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	cache.keys = map[string]*rsa.PublicKey{
		"kid-1": &privKey.PublicKey,
	}
	cache.expiresAt = now.Add(-time.Minute)
	cache.staleUntil = now.Add(10 * time.Minute)

	if _, err := cache.getKey(context.Background(), "kid-1"); err != nil {
		t.Fatalf("expected stale key to be used: %v", err)
	}

	now = now.Add(20 * time.Minute)
	if _, err := cache.getKey(context.Background(), "kid-1"); err == nil {
		t.Fatal("expected error after max stale window")
	}
}

func TestJWKSCache_RefreshSingleflight(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksURL := "https://jwks.test/keys"
	jwks := buildJWKS(t, &privKey.PublicKey, "kid-1")
	var calls int32
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			return jsonResponse(http.StatusOK, jwks), nil
		}),
	}
	cache := newJWKSCache(jwksURL, client)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.getKey(ctx, "kid-1"); err != nil {
				t.Errorf("get key: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected single fetch, got %d", got)
	}
}
