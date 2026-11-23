package main

import "testing"

func TestNormaliseRelayRefusesPlainHTTP(t *testing.T) {
	for _, u := range []string{"http://relay.example.com", "http://10.0.0.5:8080", "http://[2001:db8::1]"} {
		if _, err := normaliseRelay(u, false); err == nil {
			t.Errorf("%s accepted without --insecure", u)
		}
		if _, err := normaliseRelay(u, true); err != nil {
			t.Errorf("%s with --insecure: %v", u, err)
		}
	}
	for _, u := range []string{"https://relay.example.com/", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:9", "http://127.9.9.9"} {
		if _, err := normaliseRelay(u, false); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	if got, _ := normaliseRelay("https://a.example/", false); got != "https://a.example" {
		t.Errorf("trailing slash kept: %q", got)
	}
}
