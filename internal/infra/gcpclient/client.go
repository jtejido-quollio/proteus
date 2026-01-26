package gcpclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proteus/internal/config"
)

type Client struct {
	endpoint   string
	projectID  string
	token      string
	httpClient *http.Client
}

func New(endpoint, projectID, token string) *Client {
	return &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		projectID:  projectID,
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func NewFromConfig(cfg config.Config) (*Client, error) {
	projectID := cfg.GCPProjectID
	token := cfg.GCPAccessToken
	if projectID == "" || token == "" {
		return nil, errors.New("GCP_PROJECT_ID and GCP_ACCESS_TOKEN are required")
	}
	endpoint := cfg.GCPSecretManagerEndpoint
	if endpoint == "" {
		endpoint = "https://secretmanager.googleapis.com"
	}
	return New(endpoint, projectID, token), nil
}

func (c *Client) AccessSecret(ctx context.Context, secretID string) ([]byte, error) {
	if secretID == "" {
		return nil, errors.New("secret id is required")
	}
	path := fmt.Sprintf("/v1/projects/%s/secrets/%s/versions/latest:access", c.projectID, secretID)
	body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.Payload.Data == "" {
		return nil, errors.New("secret payload missing")
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Payload.Data)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Client) AddSecretVersion(ctx context.Context, secretID string, payload []byte) error {
	if secretID == "" {
		return errors.New("secret id is required")
	}
	path := fmt.Sprintf("/v1/projects/%s/secrets/%s:addVersion", c.projectID, secretID)
	reqBody := map[string]any{
		"payload": map[string]string{
			"data": base64.StdEncoding.EncodeToString(payload),
		},
	}
	_, err := c.do(ctx, http.MethodPost, path, reqBody)
	return err
}

func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	if secretID == "" {
		return errors.New("secret id is required")
	}
	path := fmt.Sprintf("/v1/projects/%s/secrets/%s", c.projectID, secretID)
	_, err := c.do(ctx, http.MethodDelete, path, nil)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	if c == nil {
		return nil, errors.New("gcp client is nil")
	}
	if c.endpoint == "" || c.projectID == "" || c.token == "" {
		return nil, errors.New("gcp client missing configuration")
	}
	var body []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = encoded
	}
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp secret manager failed: status %d", resp.StatusCode)
	}
	return respBody, nil
}
