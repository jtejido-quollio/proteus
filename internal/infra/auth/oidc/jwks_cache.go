package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	defaultJWKSCacheTTL      = 5 * time.Minute
	defaultJWKSMaxStale      = 15 * time.Minute
	defaultJWKSFetchTimeout  = 5 * time.Second
	defaultJWKSRetryAttempts = 3
	defaultJWKSRetryBase     = 200 * time.Millisecond
	defaultJWKSRetryMax      = 2 * time.Second
)

type keyState int

const (
	keyMissing keyState = iota
	keyFresh
	keyStale
)

type jwksCache struct {
	url          string
	httpClient   *http.Client
	ttl          time.Duration
	maxStale     time.Duration
	fetchTimeout time.Duration
	retryBase    time.Duration
	retryMax     time.Duration
	now          func() time.Time

	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	expiresAt  time.Time
	staleUntil time.Time

	refreshMu sync.Mutex
	refreshCh chan struct{}
	lastErr   error
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func newJWKSCache(url string, httpClient *http.Client) *jwksCache {
	return &jwksCache{
		url:          url,
		httpClient:   httpClient,
		ttl:          defaultJWKSCacheTTL,
		maxStale:     defaultJWKSMaxStale,
		fetchTimeout: defaultJWKSFetchTimeout,
		retryBase:    defaultJWKSRetryBase,
		retryMax:     defaultJWKSRetryMax,
		now:          time.Now,
		keys:         map[string]*rsa.PublicKey{},
	}
}

func (c *jwksCache) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("kid is required")
	}
	now := c.now()
	if key, state := c.lookup(kid, now); state == keyFresh {
		return key, nil
	} else if state == keyStale {
		c.refreshAsync()
		return key, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if key, _ := c.lookup(kid, c.now()); key != nil {
		return key, nil
	}
	return nil, errors.New("jwks key not found")
}

func (c *jwksCache) lookup(kid string, now time.Time) (*rsa.PublicKey, keyState) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, keyMissing
	}
	if now.Before(c.expiresAt) {
		return key, keyFresh
	}
	if !c.staleUntil.IsZero() && now.Before(c.staleUntil) {
		return key, keyStale
	}
	return nil, keyMissing
}

func (c *jwksCache) refreshAsync() {
	ctx, cancel := context.WithTimeout(context.Background(), c.fetchTimeout)
	go func() {
		_ = c.refresh(ctx)
		cancel()
	}()
}

func (c *jwksCache) refresh(ctx context.Context) error {
	ch, leader := c.beginRefresh()
	if !leader {
		return c.waitRefresh(ctx, ch)
	}

	err := c.doRefresh(ctx)
	c.finishRefresh(err, ch)
	return err
}

func (c *jwksCache) beginRefresh() (chan struct{}, bool) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if c.refreshCh != nil {
		return c.refreshCh, false
	}
	ch := make(chan struct{})
	c.refreshCh = ch
	return ch, true
}

func (c *jwksCache) waitRefresh(ctx context.Context, ch chan struct{}) error {
	select {
	case <-ch:
		c.refreshMu.Lock()
		defer c.refreshMu.Unlock()
		return c.lastErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *jwksCache) finishRefresh(err error, ch chan struct{}) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.lastErr = err
	close(ch)
	c.refreshCh = nil
}

func (c *jwksCache) doRefresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	keys, err := c.fetchWithRetry(ctx)
	if err != nil {
		return err
	}
	now := c.now()
	c.mu.Lock()
	c.keys = keys
	c.expiresAt = now.Add(c.ttl)
	c.staleUntil = c.expiresAt.Add(c.maxStale)
	c.mu.Unlock()
	return nil
}

func (c *jwksCache) fetchWithRetry(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	delay := c.retryBase
	var lastErr error
	for attempt := 0; attempt < defaultJWKSRetryAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, delay); err != nil {
				return nil, err
			}
			delay *= 2
			if delay > c.retryMax {
				delay = c.retryMax
			}
		}
		keys, err := c.fetchOnce(ctx)
		if err == nil {
			return keys, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (c *jwksCache) fetchOnce(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("jwks fetch failed")
	}
	var payload jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, key := range payload.Keys {
		if key.Kty != "RSA" || key.Kid == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(key)
		if err != nil {
			continue
		}
		keys[key.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable keys")
	}
	return keys, nil
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func jwkToRSAPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	if key.N == "" || key.E == "" {
		return nil, errors.New("missing rsa params")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()
	if e <= 0 || e > int64(^uint32(0)) {
		return nil, errors.New("invalid rsa exponent")
	}
	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}
