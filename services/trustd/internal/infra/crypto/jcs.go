package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

func CanonicalizeJSON(input []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := writeCanonical(buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func CanonicalizeAny(v any) ([]byte, error) {
	switch value := v.(type) {
	case nil, bool, string, json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, map[string]any, []any:
		buf := &bytes.Buffer{}
		if err := writeCanonical(buf, value); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case json.RawMessage:
		return CanonicalizeJSON([]byte(value))
	case []byte:
		return CanonicalizeJSON(value)
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return CanonicalizeJSON(b)
	}
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return errors.New("invalid JSON: trailing data")
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, v)
	case json.Number:
		num, err := canonicalizeNumberString(v.String())
		if err != nil {
			return err
		}
		buf.WriteString(num)
	case float64:
		num, err := canonicalizeFloat(v)
		if err != nil {
			return err
		}
		buf.WriteString(num)
	case float32:
		num, err := canonicalizeFloat(float64(v))
		if err != nil {
			return err
		}
		buf.WriteString(num)
	case int:
		return writeCanonical(buf, float64(v))
	case int8:
		return writeCanonical(buf, float64(v))
	case int16:
		return writeCanonical(buf, float64(v))
	case int32:
		return writeCanonical(buf, float64(v))
	case int64:
		return writeCanonical(buf, float64(v))
	case uint:
		return writeCanonical(buf, float64(v))
	case uint8:
		return writeCanonical(buf, float64(v))
	case uint16:
		return writeCanonical(buf, float64(v))
	case uint32:
		return writeCanonical(buf, float64(v))
	case uint64:
		return writeCanonical(buf, float64(v))
	case map[string]any:
		return writeObject(buf, v)
	case []any:
		return writeArray(buf, v)
	default:
		return fmt.Errorf("unsupported JSON type %T", value)
	}
	return nil
}

func writeObject(buf *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, k)
		buf.WriteByte(':')
		if err := writeCanonical(buf, obj[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeArray(buf *bytes.Buffer, arr []any) error {
	buf.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, item); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexLower[r>>4])
				buf.WriteByte(hexLower[r&0x0f])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

var hexLower = []byte("0123456789abcdef")

func canonicalizeNumberString(number string) (string, error) {
	f, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return "", fmt.Errorf("invalid JSON number: %w", err)
	}
	return canonicalizeFloat(f)
}

func canonicalizeFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("invalid JSON number")
	}
	if f == 0 {
		return "0", nil
	}

	sign := ""
	if f < 0 {
		sign = "-"
		f = math.Abs(f)
	}

	mantissa, exp, err := splitScientific(f)
	if err != nil {
		return "", err
	}

	digits := strings.ReplaceAll(mantissa, ".", "")

	if exp <= -7 || exp >= 21 {
		if len(digits) == 1 {
			return sign + digits + "e" + strconv.Itoa(exp), nil
		}
		return sign + digits[:1] + "." + digits[1:] + "e" + strconv.Itoa(exp), nil
	}

	point := exp + 1
	if point >= len(digits) {
		return sign + digits + strings.Repeat("0", point-len(digits)), nil
	}
	if point <= 0 {
		return sign + "0." + strings.Repeat("0", -point) + digits, nil
	}
	return sign + digits[:point] + "." + digits[point:], nil
}

func splitScientific(f float64) (string, int, error) {
	s := strconv.FormatFloat(f, 'e', -1, 64)
	parts := strings.SplitN(s, "e", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid float format: %q", s)
	}
	exp, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid float exponent: %w", err)
	}
	return parts[0], exp, nil
}
