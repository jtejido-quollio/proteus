package vaultclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	addr       string
	token      string
	httpClient *http.Client
}

func New(addr, token string) *Client {
	return &Client{
		addr:       strings.TrimRight(addr, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) ReadKV(ctx context.Context, path string, out any) error {
	if c == nil {
		return errors.New("vault client is nil")
	}
	if c.addr == "" || c.token == "" {
		return errors.New("vault addr or token missing")
	}
	if path == "" {
		return errors.New("vault path is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/"+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault read failed: status %d", resp.StatusCode)
	}

	var envelope struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	if len(envelope.Data.Data) == 0 {
		return errors.New("vault response missing data")
	}
	return json.Unmarshal(envelope.Data.Data, out)
}

func (c *Client) WriteKV(ctx context.Context, path string, payload any) error {
	if c == nil {
		return errors.New("vault client is nil")
	}
	if c.addr == "" || c.token == "" {
		return errors.New("vault addr or token missing")
	}
	if path == "" {
		return errors.New("vault path is required")
	}
	body, err := json.Marshal(map[string]any{"data": payload})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.addr+"/v1/"+strings.TrimLeft(path, "/"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("vault write failed: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) DeleteKV(ctx context.Context, path string) error {
	if c == nil {
		return errors.New("vault client is nil")
	}
	if c.addr == "" || c.token == "" {
		return errors.New("vault addr or token missing")
	}
	if path == "" {
		return errors.New("vault path is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.addr+"/v1/"+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault delete failed: status %d", resp.StatusCode)
	}
	return nil
}
