package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runDoctor(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("ECB_CONFIG_DIR", t.TempDir())
	t.Setenv("ECB_KEYSTORE", "file")
	t.Setenv("ECB_RELAY", "")
	var o, e bytes.Buffer
	code := realMain(append([]string{"doctor"}, args...), &o, &e)
	return code, o.String(), e.String()
}

func TestDoctorClosedPortText(t *testing.T) {
	code, o, _ := runDoctor(t, "--relay", "http://127.0.0.1:1")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, o)
	}
	for _, want := range []string{"[WARN] 1. url", "[FAIL] 3. tcp", "what to do:", "FAIL at step \"tcp\""} {
		if !strings.Contains(o, want) {
			t.Errorf("output missing %q:\n%s", want, o)
		}
	}
}

func TestDoctorJSON(t *testing.T) {
	code, o, _ := runDoctor(t, "--json", "--relay", "http://127.0.0.1:1")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var m struct {
		Verdict    string `json:"verdict"`
		FailedStep string `json:"failed_step"`
		Steps      []struct{ ID, Status string }
	}
	if err := json.Unmarshal([]byte(o), &m); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, o)
	}
	if m.Verdict != "FAIL" || m.FailedStep != "tcp" || len(m.Steps) < 5 {
		t.Fatalf("%+v", m)
	}
}

func TestDoctorNoRelayAndHelp(t *testing.T) {
	if code, _, e := runDoctor(t); code != 1 || !strings.Contains(e, "connectivity check failed") {
		t.Fatalf("exit %d: %s", code, e)
	}
	code, _, e := runDoctor(t, "--help")
	if code != 0 || !strings.Contains(e, "-duration") || !strings.Contains(e, "-json") {
		t.Fatalf("help exit %d: %s", code, e)
	}
	if code, _, _ := runDoctor(t, "--bogus"); code != 2 {
		t.Fatalf("bad flag exit %d", code)
	}
}
