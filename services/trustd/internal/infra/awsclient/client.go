package awsclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"proteus/internal/config"
)

const (
	awsServiceSecretsManager = "secretsmanager"
	awsTargetPrefix          = "secretsmanager."
)

type Client struct {
	endpoint     string
	region       string
	accessKey    string
	secretKey    string
	sessionToken string
	httpClient   *http.Client
	clock        func() time.Time
}

func New(endpoint, region, accessKey, secretKey, sessionToken string) *Client {
	return &Client{
		endpoint:     strings.TrimRight(endpoint, "/"),
		region:       region,
		accessKey:    accessKey,
		secretKey:    secretKey,
		sessionToken: sessionToken,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		clock:        time.Now,
	}
}

func NewFromConfig(cfg config.Config) (*Client, error) {
	region := cfg.AWSRegion
	accessKey := cfg.AWSAccessKeyID
	secretKey := cfg.AWSSecretAccessKey
	if region == "" || accessKey == "" || secretKey == "" {
		return nil, errors.New("AWS_REGION, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY are required")
	}
	endpoint := cfg.AWSSecretsManagerEndpoint
	if endpoint == "" {
		endpoint = "https://secretsmanager." + region + ".amazonaws.com"
	}
	return New(endpoint, region, accessKey, secretKey, cfg.AWSSessionToken), nil
}

func (c *Client) WithClock(clock func() time.Time) *Client {
	if c == nil {
		return nil
	}
	c.clock = clock
	return c
}

func (c *Client) GetSecret(ctx context.Context, secretID string) ([]byte, error) {
	if secretID == "" {
		return nil, errors.New("secret id is required")
	}
	body, err := c.do(ctx, "GetSecretValue", map[string]string{"SecretId": secretID})
	if err != nil {
		return nil, err
	}
	var resp struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.SecretString == "" {
		return nil, errors.New("secret string missing")
	}
	return []byte(resp.SecretString), nil
}

func (c *Client) CreateSecret(ctx context.Context, secretID string, secretString []byte) error {
	if secretID == "" {
		return errors.New("secret id is required")
	}
	_, err := c.do(ctx, "CreateSecret", map[string]any{
		"Name":         secretID,
		"SecretString": string(secretString),
	})
	return err
}

func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	if secretID == "" {
		return errors.New("secret id is required")
	}
	_, err := c.do(ctx, "DeleteSecret", map[string]any{
		"SecretId":                   secretID,
		"ForceDeleteWithoutRecovery": true,
	})
	return err
}

func (c *Client) do(ctx context.Context, target string, payload any) ([]byte, error) {
	if c == nil {
		return nil, errors.New("aws client is nil")
	}
	if c.endpoint == "" || c.region == "" || c.accessKey == "" || c.secretKey == "" {
		return nil, errors.New("aws client missing configuration")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", awsTargetPrefix+target)

	if c.clock == nil {
		c.clock = time.Now
	}
	now := c.clock().UTC()
	amzDate := now.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	if c.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.sessionToken)
	}

	if err := signRequest(req, body, c.region, c.accessKey, c.secretKey, c.sessionToken); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("aws secrets manager failed: status %d", resp.StatusCode)
	}
	return respBody, nil
}

func signRequest(req *http.Request, payload []byte, region, accessKey, secretKey, sessionToken string) error {
	parsed, err := url.Parse(req.URL.String())
	if err != nil {
		return err
	}
	host := parsed.Host
	if host == "" {
		return errors.New("aws host missing")
	}
	req.Header.Set("Host", host)

	amzDate := req.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return errors.New("X-Amz-Date is required")
	}
	date := amzDate[:8]
	service := awsServiceSecretsManager

	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req.Header)
	payloadHash := sha256Hex(payload)
	canonicalRequest := strings.Join([]string{
		req.Method,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, date, region, service)
	signature := hmacHex(signingKey, []byte(stringToSign))
	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey,
		scope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", auth)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	return nil
}

func buildCanonicalHeaders(headers http.Header) (string, string) {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		values := headers.Values(key)
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		canonical.WriteString(key)
		canonical.WriteString(":")
		canonical.WriteString(strings.Join(values, ","))
		canonical.WriteString("\n")
	}
	return canonical.String(), strings.Join(keys, ";")
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacHex(key, data []byte) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
