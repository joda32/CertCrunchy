// Package httpx is the shared HTTP client for API sources: TLS verification
// on, retries with backoff for transient failures, Retry-After handling and an
// optional per-source rate limiter.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// ErrRateLimited is returned when a source keeps answering 429 or announces a
// wait longer than we are willing to sleep.
var ErrRateLimited = errors.New("rate limited")

// StatusError is a non-2xx response that was not retried away.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	b := strings.TrimSpace(e.Body)
	if len(b) > 200 {
		b = b[:200] + "…"
	}
	if b == "" {
		return fmt.Sprintf("HTTP %d", e.Code)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Code, b)
}

type Client struct {
	HTTP       *http.Client
	UserAgent  string
	Retries    int           // extra attempts after the first
	MaxWait    time.Duration // longest Retry-After we will honour
	BaseBackof time.Duration
}

func New(timeout time.Duration, version string) *Client {
	return &Client{
		HTTP:       &http.Client{Timeout: timeout},
		UserAgent:  "certcrunchy/" + version + " (+https://github.com/joda32/CertCrunchy)",
		Retries:    2,
		MaxWait:    30 * time.Second,
		BaseBackof: 1500 * time.Millisecond,
	}
}

// Request describes one call. Limiter may be nil.
type Request struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
	Limiter *rate.Limiter
	MaxBody int64 // 0 = 64 MiB
}

// Do performs the request with retries and returns the body of a 2xx response.
func (c *Client) Do(ctx context.Context, r Request) ([]byte, http.Header, error) {
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	if r.MaxBody == 0 {
		r.MaxBody = 64 << 20
	}
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if r.Limiter != nil {
			if err := r.Limiter.Wait(ctx); err != nil {
				return nil, nil, err
			}
		}
		var body io.Reader
		if r.Body != nil {
			body = bytes.NewReader(r.Body)
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
		if err != nil {
			return nil, nil, err
		}
		for k, vs := range r.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set("User-Agent", c.UserAgent)
		if r.Body != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			lastErr = err
			if !c.sleep(ctx, c.backoff(attempt)) {
				return nil, nil, ctx.Err()
			}
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, r.MaxBody))
		resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if rerr != nil {
				lastErr = rerr
				continue
			}
			return data, resp.Header, nil
		case resp.StatusCode == http.StatusTooManyRequests:
			wait, ok := retryAfter(resp.Header)
			if !ok || wait > c.MaxWait || attempt == c.Retries {
				return nil, resp.Header, fmt.Errorf("%w (HTTP 429%s)", ErrRateLimited, waitHint(wait, ok))
			}
			if !c.sleep(ctx, wait) {
				return nil, nil, ctx.Err()
			}
			lastErr = ErrRateLimited
		case resp.StatusCode >= 500:
			lastErr = &StatusError{Code: resp.StatusCode, Body: string(data)}
			wait, ok := retryAfter(resp.Header)
			if !ok || wait > c.MaxWait {
				wait = c.backoff(attempt)
			}
			if attempt < c.Retries && !c.sleep(ctx, wait) {
				return nil, nil, ctx.Err()
			}
		default:
			return nil, resp.Header, &StatusError{Code: resp.StatusCode, Body: string(data)}
		}
	}
	return nil, nil, lastErr
}

// GetJSON fetches url and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, url string, header http.Header, lim *rate.Limiter, out any) (http.Header, error) {
	data, h, err := c.Do(ctx, Request{URL: url, Header: header, Limiter: lim})
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return h, fmt.Errorf("decode JSON: %w", err)
	}
	return h, nil
}

func (c *Client) backoff(attempt int) time.Duration {
	d := c.BaseBackof << attempt
	return d + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(v); err == nil {
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t), true
	}
	return 0, false
}

func waitHint(d time.Duration, ok bool) string {
	if !ok {
		return ""
	}
	return ", retry after " + d.Round(time.Second).String()
}
