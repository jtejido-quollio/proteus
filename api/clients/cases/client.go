package cases

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Principal struct {
	Subject  string
	TenantID string
	Scopes   []string
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Principal  Principal
}

type EmitEventInput struct {
	TenantID  string
	CaseID    string
	EventType string
	RequestID string
	Payload   map[string]any
}

type Option func(*Client)

func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.HTTPClient = client
	}
}

func WithPrincipal(principal Principal) Option {
	return func(c *Client) {
		c.Principal = principal
	}
}

func NewClient(baseURL string, opts ...Option) *Client {
	client := &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (c *Client) EmitEvent(ctx context.Context, input EmitEventInput) error {
	if c == nil {
		return fmt.Errorf("cases client is nil")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("case service base URL is required")
	}
	if input.CaseID == "" || input.EventType == "" {
		return fmt.Errorf("case_id and event_type are required")
	}
	path := fmt.Sprintf("/v1/cases/%s/events", url.PathEscape(input.CaseID))
	endpoint := c.BaseURL + path

	payload := map[string]any{
		"event_type": input.EventType,
		"payload":    input.Payload,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input.RequestID != "" {
		req.Header.Set("X-Request-ID", input.RequestID)
	}

	principal := c.Principal
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(principal.TenantID)
	}
	if principal.Subject != "" {
		req.Header.Set("X-Principal-Subject", principal.Subject)
	}
	if tenantID != "" {
		req.Header.Set("X-Principal-Tenant", tenantID)
	}
	if len(principal.Scopes) > 0 {
		req.Header.Set("X-Principal-Scopes", strings.Join(principal.Scopes, ","))
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emit event: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("emit event failed: status %d body %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}
