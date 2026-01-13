package replay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func ComputeReplayInputsDigestJSON(bundleJSON []byte) (string, error) {
	bundle, err := decodeBundleJSON(bundleJSON)
	if err != nil {
		return "", err
	}
	return ComputeReplayInputsDigest(bundle)
}

func ComputeReplayInputsDigestFromPayload(payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return ComputeReplayInputsDigestJSON(data)
}

func decodeBundleJSON(input []byte) (ReplayBundle, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var bundle ReplayBundle
	if err := dec.Decode(&bundle); err != nil {
		return ReplayBundle{}, fmt.Errorf("invalid replay bundle json: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return ReplayBundle{}, err
	}
	return bundle, nil
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid replay bundle json: %w", err)
	}
	return errors.New("invalid replay bundle json: trailing data")
}
