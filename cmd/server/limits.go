package main

import "net/http"

// Reject overload instead of queuing arbitrarily many handlers or shell calls.
func limitRequests(next http.Handler, maximum int) http.Handler {
	active := make(chan struct{}, maximum)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "server busy; try again later", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}
