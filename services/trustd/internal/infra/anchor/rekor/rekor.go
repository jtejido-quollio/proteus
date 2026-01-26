package rekor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"proteus/internal/domain"
	"proteus/internal/infra/anchor"
)

type Signer interface {
	Sign(ctx context.Context, payload []byte) (sig []byte, pubKey []byte, err error)
}

type Client struct {
	baseURL  string
	bundleID string
	signer   Signer
	httpDo   func(*http.Request) (*http.Response, error)
}

const maxProviderReceiptBytes = 256 * 1024

func NewClient(baseURL, bundleID string, signer Signer, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("rekor base url is required")
	}
	if signer == nil {
		return nil, errors.New("rekor signer is required")
	}
	if bundleID == "" {
		bundleID = "rekor"
	}
	doer := http.DefaultClient.Do
	if httpClient != nil {
		doer = httpClient.Do
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		bundleID: bundleID,
		signer:   signer,
		httpDo:   doer,
	}, nil
}

func (c *Client) ProviderName() string {
	return "rekor"
}

func (c *Client) BundleID() string {
	return c.bundleID
}

func (c *Client) Anchor(ctx context.Context, payload anchor.Payload) domain.AnchorReceipt {
	if c == nil {
		return failedReceipt("rekor", "unknown", domain.AnchorErrorBadConfig, "", nil)
	}
	receipt, err := c.anchorWithPayload(ctx, payload)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, domain.AnchorErrorBadConfig, "", nil)
	}
	return receipt
}

func (c *Client) anchorWithPayload(ctx context.Context, payload anchor.Payload) (domain.AnchorReceipt, error) {
	signature, pubKey, err := c.signer.Sign(ctx, payload.CanonicalJSON)
	if err != nil {
		return domain.AnchorReceipt{}, err
	}

	entry := hashedRekord{
		APIVersion: "0.0.1",
		Kind:       "hashedrekord",
		Spec: hashedRekordSpec{
			Data: hashedRekordData{
				Hash: hashedRekordHash{
					Algorithm: "sha256",
					Value:     payload.HashHex,
				},
			},
			Signature: hashedRekordSignature{
				Content: base64.StdEncoding.EncodeToString(signature),
				PublicKey: hashedRekordPublicKey{
					Content: base64.StdEncoding.EncodeToString(pubKey),
				},
			},
		},
	}

	postBody, err := json.Marshal(entry)
	if err != nil {
		return domain.AnchorReceipt{}, err
	}

	postURL := c.baseURL + "/api/v1/log/entries"
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(postBody))
	if err != nil {
		return domain.AnchorReceipt{}, err
	}
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := c.httpDo(postReq)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, errorToCode(ctx, err), "", nil), nil
	}
	defer postResp.Body.Close()
	postRespBody, err := io.ReadAll(postResp.Body)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, errorToCode(ctx, err), "", nil), nil
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return failedReceipt(c.ProviderName(), c.bundleID, statusToErrorCode(postResp.StatusCode), "", postRespBody), nil
	}
	uuid := firstMapKey(postRespBody)
	if uuid == "" {
		return failedReceipt(c.ProviderName(), c.bundleID, domain.AnchorErrorProviderError, "", postRespBody), nil
	}

	getURL := c.baseURL + "/api/v1/log/entries/" + uuid
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, errorToCode(ctx, err), uuid, postRespBody), nil
	}
	getResp, err := c.httpDo(getReq)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, errorToCode(ctx, err), uuid, postRespBody), nil
	}
	defer getResp.Body.Close()
	getRespBody, err := io.ReadAll(getResp.Body)
	if err != nil {
		return failedReceipt(c.ProviderName(), c.bundleID, errorToCode(ctx, err), uuid, postRespBody), nil
	}
	if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
		return failedReceipt(c.ProviderName(), c.bundleID, statusToErrorCode(getResp.StatusCode), uuid, getRespBody), nil
	}
	logIndex, integratedTime := parseEntryMeta(getRespBody)
	receiptJSON, truncated, size := truncateReceiptJSON(getRespBody)
	receiptHash := sha256Hex(getRespBody)

	return domain.AnchorReceipt{
		Provider:                 c.ProviderName(),
		BundleID:                 c.bundleID,
		Status:                   domain.AnchorStatusAnchored,
		PayloadHash:              payload.HashHex,
		EntryUUID:                uuid,
		LogIndex:                 logIndex,
		IntegratedTime:           integratedTime,
		EntryURL:                 getURL,
		ProviderReceiptJSON:      json.RawMessage(receiptJSON),
		ProviderReceiptTruncated: truncated,
		ProviderReceiptSizeBytes: size,
		ProviderReceiptSHA256:    receiptHash,
	}, nil
}

func failedReceipt(provider, bundleID, code, uuid string, body []byte) domain.AnchorReceipt {
	receiptJSON, truncated, size := truncateReceiptJSON(body)
	receipt := domain.AnchorReceipt{
		Provider:                 provider,
		BundleID:                 bundleID,
		Status:                   domain.AnchorStatusFailed,
		ErrorCode:                code,
		EntryUUID:                uuid,
		ProviderReceiptTruncated: truncated,
		ProviderReceiptSizeBytes: size,
		ProviderReceiptSHA256:    sha256Hex(body),
	}
	if len(receiptJSON) > 0 {
		receipt.ProviderReceiptJSON = json.RawMessage(receiptJSON)
	}
	return receipt
}

func statusToErrorCode(code int) string {
	if code == http.StatusTooManyRequests {
		return domain.AnchorErrorRateLimit
	}
	if code >= 500 {
		return domain.AnchorErrorProvider5xx
	}
	return domain.AnchorErrorProviderError
}

func errorToCode(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return domain.AnchorErrorTimeout
	}
	return domain.AnchorErrorNetwork
}

func firstMapKey(payload []byte) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return ""
	}
	for key := range raw {
		return key
	}
	return ""
}

func parseEntryMeta(payload []byte) (int64, int64) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return 0, 0
	}
	for _, value := range raw {
		var entry rekorEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			continue
		}
		return entry.LogIndex, entry.IntegratedTime
	}
	return 0, 0
}

func truncateReceiptJSON(payload []byte) ([]byte, bool, int) {
	size := len(payload)
	if size == 0 {
		return nil, false, 0
	}
	if size <= maxProviderReceiptBytes {
		return payload, false, size
	}
	prefix := payload[:maxProviderReceiptBytes]
	truncated := map[string]any{
		"truncated":     true,
		"prefix_base64": base64.StdEncoding.EncodeToString(prefix),
	}
	encoded, err := json.Marshal(truncated)
	if err != nil {
		return nil, true, size
	}
	return encoded, true, size
}

func sha256Hex(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

type hashedRekord struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Spec       hashedRekordSpec `json:"spec"`
}

type hashedRekordSpec struct {
	Data      hashedRekordData      `json:"data"`
	Signature hashedRekordSignature `json:"signature"`
}

type hashedRekordData struct {
	Hash hashedRekordHash `json:"hash"`
}

type hashedRekordHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type hashedRekordSignature struct {
	Content   string                `json:"content"`
	PublicKey hashedRekordPublicKey `json:"publicKey"`
}

type hashedRekordPublicKey struct {
	Content string `json:"content"`
}

type rekorEntry struct {
	LogIndex       int64 `json:"logIndex"`
	IntegratedTime int64 `json:"integratedTime"`
}
