package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fastClient() *Client {
	c := New(5*time.Second, "test")
	c.BaseBackof = time.Millisecond
	return c
}

func TestRetriesServerErrors(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	var out struct{ OK bool }
	if _, err := fastClient().GetJSON(context.Background(), srv.URL, nil, nil, &out); err != nil || !out.OK {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if n.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", n.Load())
	}
}

func TestRateLimitedLongWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, _, err := fastClient().Do(context.Background(), Request{URL: srv.URL})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, _, err := fastClient().Do(context.Background(), Request{URL: srv.URL})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 || n.Load() != 1 {
		t.Fatalf("err=%v attempts=%d", err, n.Load())
	}
}
