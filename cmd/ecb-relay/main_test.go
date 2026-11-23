package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(status)
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())

	if err := healthcheck("0.0.0.0:" + port); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(":" + port); err == nil {
		t.Fatal("expected error on 503")
	}
	if err := healthcheck("nonsense"); err == nil {
		t.Fatal("expected error on bad addr")
	}
}
