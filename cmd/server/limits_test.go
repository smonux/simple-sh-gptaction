package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestOverloadIsRejectedAndSlotReleased(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h := limitRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-release; w.WriteHeader(204) }), 1)
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)) }()
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("overload returned %d", w.Code)
	}
	close(release)
	<-done
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 204 {
		t.Fatal("request slot was not released")
	}
}
