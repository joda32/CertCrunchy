package source

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/time/rate"

	"github.com/joda32/certcrunchy/internal/httpx"
)

// crt.sh exposes its certwatch database read-only to the public. Going
// straight to Postgres avoids the web front end, which frequently answers 502
// or times out on bigger domains.
const crtshDSN = "postgres://guest@crt.sh:5432/certwatch?sslmode=disable&connect_timeout=15&default_query_exec_mode=simple_protocol&application_name=certcrunchy"

// The tsquery uses crt.sh's full-text index; the ILIKE trims it down to
// names actually under the domain.
const crtshSQL = `SELECT DISTINCT lower(cai.name_value)
FROM certificate_and_identities cai
WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.certificate)
  AND cai.name_value ILIKE ('%' || $1)
LIMIT $2`

type CrtshDB struct {
	dsn   string
	limit int
}

func NewCrtshDB() *CrtshDB { return &CrtshDB{dsn: crtshDSN, limit: 100000} }

func (s *CrtshDB) Info() Info {
	return Info{Name: "crtsh-db", Kind: CT, Default: true, Desc: "crt.sh certwatch Postgres (guest access)"}
}

func (s *CrtshDB) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if err = s.query(ctx, domain, emit); err == nil || ctx.Err() != nil {
			return err
		}
		// Replicas cancel long queries during recovery; one retry usually works.
		if !strings.Contains(err.Error(), "conflict with recovery") {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	return err
}

func (s *CrtshDB) query(ctx context.Context, domain string, emit func(string)) error {
	conn, err := pgx.Connect(ctx, s.dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())
	rows, err := conn.Query(ctx, crtshSQL, domain, s.limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		emit(name)
	}
	return rows.Err()
}

// CrtshHTTP is the JSON web endpoint, used as a fallback for crtsh-db.
type CrtshHTTP struct{ base }

func NewCrtshHTTP(c *httpx.Client) *CrtshHTTP {
	return &CrtshHTTP{base{
		info:    Info{Name: "crtsh", Kind: CT, Default: true, FallbackFor: "crtsh-db", Desc: "crt.sh JSON API (fallback when the DB fails)"},
		http:    c,
		lim:     rate.NewLimiter(rate.Every(2*time.Second), 1),
		baseURL: "https://crt.sh/",
	}}
}

func (s *CrtshHTTP) Enumerate(ctx context.Context, domain string, emit func(string)) error {
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	u := s.baseURL + "?q=" + url.QueryEscape("%."+domain) + "&output=json"
	if _, err := s.http.GetJSON(ctx, u, nil, s.lim, &rows); err != nil {
		return err
	}
	for _, r := range rows {
		for _, n := range strings.Split(r.NameValue, "\n") {
			emit(n)
		}
		emit(r.CommonName)
	}
	return nil
}
