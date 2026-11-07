package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const MaxJSONSize = 4 << 20
const maxJSONDepth = 64

// DecodeJSON rejects ambiguous JSON, unknown fields, excessive nesting and trailing data.
func DecodeJSON(r io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxJSONSize+1))
	if err != nil {
		return err
	}
	if len(data) > MaxJSONSize {
		return fmt.Errorf("JSON exceeds %d bytes", MaxJSONSize)
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(scanner, 0); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := scanner.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid JSON: trailing data")
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

func scanJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("maximum nesting depth exceeded")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			for _, r := range name {
				if r > 127 {
					return fmt.Errorf("non-ASCII object key %q", name)
				}
			}
			// encoding/json matches struct fields case-insensitively.
			folded := strings.ToLower(name)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate object key %q", name)
			}
			seen[folded] = struct{}{}
			if err := scanJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("unterminated object")
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("unterminated array")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	return nil
}
