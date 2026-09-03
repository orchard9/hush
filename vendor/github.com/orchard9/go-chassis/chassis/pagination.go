package chassis

import "strconv"

// Page is a parsed cursor-pagination request (?limit=&cursor=). Cursor is opaque
// to the chassis; handlers encode/decode it (e.g. an id or keyset token).
type Page struct {
	Limit  int
	Cursor string
}

// Page parses pagination params from the query string, clamping limit to
// [1, maxLimit] and defaulting to defLimit.
func (c *Context) Page(defLimit, maxLimit int) Page {
	q := c.r.URL.Query()
	p := Page{Limit: defLimit, Cursor: q.Get("cursor")}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.Limit = n
		}
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}
	if p.Limit < 1 {
		p.Limit = 1
	}
	return p
}

// ListResponse is the standard list envelope. NextCursor is "" on the last page.
type ListResponse[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// List builds a ListResponse, normalizing a nil slice to []. nextCursor is the
// token a client passes as ?cursor= to fetch the next page ("" = no more).
func List[T any](items []T, nextCursor string) ListResponse[T] {
	if items == nil {
		items = []T{}
	}
	return ListResponse[T]{Items: items, NextCursor: nextCursor}
}
