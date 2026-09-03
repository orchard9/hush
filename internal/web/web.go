// Package web serves hush's two pages. Both are static: they read no storage,
// so a link previewer fetching either one cannot destroy a secret.
package web

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
)

//go:embed templates/*.html
var files embed.FS

// Pages renders the create and reveal pages. Templates are embedded, so the
// container carries no template directory to go missing at runtime.
type Pages struct {
	create *template.Template
	reveal *template.Template
}

// Data is everything a page needs. MaxCiphertextBytes is passed through so the
// browser enforces the same cap the server does and a user learns their secret
// is too large before uploading it, not after. DefaultTTLSeconds is the only
// other value: the UI does not offer a TTL choice, so the page states the
// lifetime the server will apply rather than asking for one.
type Data struct {
	MaxCiphertextBytes int
	DefaultTTLSeconds  int
}

// view is what the templates actually execute against: Data plus the two values
// that are derived per render. Nonce is NOT on Data on purpose — a caller that
// could set it could reuse one, and a reused nonce is the same as no nonce.
type view struct {
	Data
	Nonce      string
	DefaultTTL string
}

// New parses the embedded templates. It fails at boot rather than on first
// request: a template error is a build defect and should not wait for traffic
// to surface.
func New() (*Pages, error) {
	create, err := template.ParseFS(files, "templates/base.html", "templates/create.html")
	if err != nil {
		return nil, fmt.Errorf("parse create template: %w", err)
	}
	reveal, err := template.ParseFS(files, "templates/base.html", "templates/reveal.html")
	if err != nil {
		return nil, fmt.Errorf("parse reveal template: %w", err)
	}
	return &Pages{create: create, reveal: reveal}, nil
}

// Create writes the create page.
func (p *Pages) Create(w http.ResponseWriter, d Data) error {
	return render(w, p.create, d)
}

// Reveal writes the reveal page.
//
// The secret id is NOT passed in and is NOT interpolated into the HTML. The
// page reads it from location.pathname in the browser, alongside the key it
// reads from location.hash. That keeps the template free of any value that
// could be reflected, and means this handler needs no escaping decisions about
// a capability.
func (p *Pages) Reveal(w http.ResponseWriter, d Data) error {
	return render(w, p.reveal, d)
}

// contentSecurityPolicy is the page policy, keyed to one per-response nonce.
//
// It is sent as a HEADER and the pages carry no CSP <meta>, which is not a
// style preference — both halves are load-bearing:
//
//   - The chassis sets `default-src 'none'` for its JSON API surface. Two
//     policies delivered on one response INTERSECT, so a <meta> loosening
//     script-src cannot re-enable anything the header forbids; the browser
//     blocked this page's own inline script and style, and its fetch to /api,
//     while the <meta> looked permissive. Overriding the header here leaves
//     exactly one policy on the response.
//   - `frame-ancestors` is ignored entirely when delivered via <meta>, so the
//     clickjacking half of the policy only exists as a header.
//
// A nonce rather than 'unsafe-inline': the whole guarantee is that no code
// except this reviewed, same-document script can reach the key in the
// fragment, and 'unsafe-inline' would extend that permission to any script an
// injection managed to place on the page.
func contentSecurityPolicy(nonce string) string {
	return "default-src 'none'" +
		"; script-src 'nonce-" + nonce + "'" +
		"; style-src 'nonce-" + nonce + "'" +
		// The pages fetch /api/secrets and /api/secrets/{id}/reveal. Same-origin
		// only: there is no other host this page may ever talk to.
		"; connect-src 'self'" +
		// No image, font, media or frame is loaded by either page, so every
		// remaining fetch directive stays at default-src 'none'.
		"; form-action 'none'" +
		"; base-uri 'none'" +
		"; frame-ancestors 'none'"
}

func render(w http.ResponseWriter, t *template.Template, d Data) error {
	nonce, err := newNonce()
	if err != nil {
		// No entropy means no nonce, and a page rendered without one is a page
		// whose own script the browser will refuse. Fail loudly instead.
		return fmt.Errorf("csp nonce: %w", err)
	}

	h := w.Header()
	// no-store on both pages: a cached create page is harmless, but a cached
	// reveal page in a shared proxy would be a copy of a one-time URL.
	h.Set("Cache-Control", "no-store, max-age=0")
	h.Set("Content-Type", "text/html; charset=utf-8")
	// Referrer-Policy is load-bearing here, not boilerplate: without it a click
	// on any link from the reveal page could send the full URL — including the
	// fragment-adjacent path — to a third party.
	h.Set("Referrer-Policy", "no-referrer")
	// Set, not Add: this REPLACES the chassis API policy for these two routes.
	h.Set("Content-Security-Policy", contentSecurityPolicy(nonce))

	return t.ExecuteTemplate(w, "base.html", view{
		Data:       d,
		Nonce:      nonce,
		DefaultTTL: humanSeconds(d.DefaultTTLSeconds),
	})
}

// newNonce returns 128 bits of base64 for one response. CSP's nonce grammar is
// base64, so the encoding is part of the contract rather than a convenience —
// and the URL alphabet specifically, because '+' and '/' are escaped to
// character references inside an HTML attribute, leaving the nonce the browser
// parses to depend on entity decoding rather than on these bytes.
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// humanSeconds renders a TTL the way the page says it out loud. The server owns
// the number; this only decides whether to call it days, hours or minutes.
func humanSeconds(sec int) string {
	switch {
	case sec%86400 == 0 && sec >= 86400:
		return plural(sec/86400, "day")
	case sec%3600 == 0 && sec >= 3600:
		return plural(sec/3600, "hour")
	case sec >= 60:
		return plural(sec/60, "minute")
	default:
		return plural(sec, "second")
	}
}

func plural(n int, unit string) string {
	s := strconv.Itoa(n) + " " + unit
	if n != 1 {
		s += "s"
	}
	return s
}
