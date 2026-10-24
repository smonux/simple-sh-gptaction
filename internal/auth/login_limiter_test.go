package auth

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginLimiterConcurrentBudgetAndRecovery(t *testing.T) {
	var limiter loginLimiter
	now := time.Unix(1700000000, 0)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.retryAfter(now) == 0 {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != loginAttemptLimit {
		t.Fatalf("allowed %d attempts", allowed.Load())
	}
	if limiter.retryAfter(now.Add(loginAttemptWindow)) != 0 {
		t.Fatal("budget did not recover")
	}
}

func TestLoginHandlerReturns429(t *testing.T) {
	a, _ := localOAuth(t)
	values := authorizeValues()
	w := httptest.NewRecorder()
	a.oauth.HandleAuthorize(w, httptest.NewRequest("GET", testResource+"/oauth/authorize?"+values.Encode(), nil))
	cookie := w.Result().Cookies()[0]
	values.Set("csrf_token", cookie.Value)
	values.Set("username", "owner")
	values.Set("password", "wrong-password")
	for i := 0; i <= loginAttemptLimit; i++ {
		r := httptest.NewRequest("POST", testResource+"/oauth/authorize", strings.NewReader(url.Values(values).Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		a.oauth.HandleAuthorize(w, r)
		if i == loginAttemptLimit {
			if w.Code != 429 || w.Header().Get("Retry-After") == "" {
				t.Fatalf("expected 429: %d", w.Code)
			}
		} else {
			if w.Code != 200 {
				t.Fatalf("unexpected status: %d", w.Code)
			}
			cookie = w.Result().Cookies()[0]
			values.Set("csrf_token", cookie.Value)
		}
	}
}
