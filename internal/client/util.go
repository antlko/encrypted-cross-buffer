package client

import (
	"encoding/base64"
	"encoding/json"
	"io"
)

func base64Std(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, 4<<20)).Decode(v)
}

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
