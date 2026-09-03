// Package web serves hush's two pages. Both are static: they read no storage,
// so a link previewer fetching either one cannot destroy a secret.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var files embed.FS

// Pages renders the create and reveal pages. Templates are embedded, so the
// container carries no template directory to go missing at runtime.
type Pages struct {
	create *template.Template
	reveal *template.Template
}

// Data is everything a page needs. The limits are passed through so the browser
// enforces the same caps the server does and a user learns their secret is too
// large before uploading it, not after.
type Data struct {
	MaxCiphertextBytes int
	DefaultTTLSeconds  int
	MinTTLSeconds      int
	MaxTTLSeconds      int
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

func render(w http.ResponseWriter, t *template.Template, d Data) error {
	// no-store on both pages: a cached create page is harmless, but a cached
	// reveal page in a shared proxy would be a copy of a one-time URL.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Referrer-Policy is load-bearing here, not boilerplate: without it a click
	// on any link from the reveal page could send the full URL — including the
	// fragment-adjacent path — to a third party.
	w.Header().Set("Referrer-Policy", "no-referrer")
	return t.ExecuteTemplate(w, "base.html", d)
}
