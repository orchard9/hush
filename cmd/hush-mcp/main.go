// Command hush-mcp exposes hush to an MCP host (omp, Claude Code, any client)
// as two tools: hush_create and hush_reveal.
//
// It runs LOCALLY, on the operator's machine, and does the AES-256-GCM itself.
// That is the whole reason it is a stdio binary rather than an endpoint served
// by hushd: if the server did the encrypting, the server could read every
// secret created through MCP, and hush's central claim would hold for browser
// users and quietly not hold for agent users. Two guarantees behind one URL is
// worse than one honest guarantee.
//
// So this binary is a peer of the browser, not a peer of the server: it mints
// the key, encrypts, posts ciphertext, and assembles the `#fragment` link.
// hushd sees exactly what it sees from a browser.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

// stderr is indirected so tests can capture diagnostics. stdout is reserved
// for protocol frames — a stray write there corrupts the stream.
var stderr io.Writer = os.Stderr

// b64 matches the server and the browser: base64url, unpadded. One spelling of
// the wire format across all three implementations.
var b64 = base64.RawURLEncoding

func main() {
	base := strings.TrimSuffix(os.Getenv("HUSH_BASE_URL"), "/")
	if base == "" {
		base = "https://hush.threesix.ai"
	}
	c := &client{
		base: base,
		http: &http.Client{Timeout: 15 * time.Second},
		// A create token is only needed if the deployment has closed anonymous
		// create (HUSH_REQUIRE_AUTH). Empty is the normal case.
		token: os.Getenv("HUSH_CREATE_TOKEN"),
	}

	srv := NewServer("hush", version, os.Stdout, tools(c))
	if err := srv.Serve(os.Stdin); err != nil {
		fmt.Fprintf(stderr, "hush-mcp: %v\n", err)
		os.Exit(1)
	}
}

func tools(c *client) []Tool {
	return []Tool{
		{
			Name:  "hush_create",
			Title: "Create a one-time secret link",
			Description: "Encrypt a secret locally and store the ciphertext on hush, returning a " +
				"link that works exactly once. The encryption key is generated on this machine and " +
				"travels only in the link's #fragment, so the hush server never receives it and " +
				"cannot read the secret. Use this to hand a credential to someone instead of " +
				"pasting it into chat or email. The returned link is shown once and cannot be " +
				"recovered — pass it on immediately.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"secret": map[string]any{
						"type":        "string",
						"description": "The plaintext to send. Never leaves this machine unencrypted.",
					},
					"ttl_seconds": map[string]any{
						"type":        "integer",
						"description": "Lifetime in seconds, 300 to 604800. Defaults to 86400 (24h).",
						"minimum":     300,
						"maximum":     604800,
					},
				},
				"required":             []string{"secret"},
				"additionalProperties": false,
			},
			Handler: c.create,
		},
		{
			Name:  "hush_reveal",
			Title: "Open a one-time secret link",
			Description: "Fetch and decrypt a hush link, DESTROYING it in the process. This is " +
				"irreversible: after this call the link is dead and nobody else can open it, " +
				"including the intended recipient. Only call this on a link meant for you.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"link": map[string]any{
						"type":        "string",
						"description": "The full hush link including the #fragment key.",
					},
				},
				"required":             []string{"link"},
				"additionalProperties": false,
			},
			Handler: c.reveal,
		},
	}
}

type client struct {
	base  string
	http  *http.Client
	token string
}

func (c *client) create(raw json.RawMessage) (string, error) {
	var args struct {
		Secret     string `json:"secret"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("bad arguments: %w", err)
	}
	if args.Secret == "" {
		return "", errors.New("secret is empty — nothing to send")
	}

	ciphertext, key, err := seal(args.Secret)
	if err != nil {
		return "", fmt.Errorf("encrypt locally: %w", err)
	}

	body, _ := json.Marshal(map[string]any{"ciphertext": ciphertext, "ttl_seconds": args.TTLSeconds})
	req, err := http.NewRequest(http.MethodPost, c.base+"/api/secrets", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("reach hush at %s: %w", c.base, err)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))

	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("hush refused the secret (%s): %s", res.Status, apiMessage(payload))
	}
	var out struct {
		ID         string `json:"id"`
		ExpiresAt  string `json:"expires_at"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(payload, &out); err != nil || out.ID == "" {
		return "", fmt.Errorf("unexpected response from hush: %s", string(payload))
	}

	// The key is appended HERE, on this machine. It was never in the request.
	link := c.base + "/s/" + out.ID + "#" + key
	return fmt.Sprintf(
		"%s\n\nOne-time link — works exactly once, expires %s.\n"+
			"The key is in the #fragment, so hush cannot read the secret.\n"+
			"This link cannot be shown again: send it now.",
		link, out.ExpiresAt), nil
}

func (c *client) reveal(raw json.RawMessage) (string, error) {
	var args struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("bad arguments: %w", err)
	}

	u, err := url.Parse(strings.TrimSpace(args.Link))
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	if u.Fragment == "" {
		// The commonest real failure: a chat client or mail rewriter dropped
		// the fragment. Say so precisely, because the secret is still intact
		// and the fix is to ask the sender for the whole link.
		return "", errors.New("this link has no #fragment, so it carries no key. " +
			"Chat and email clients sometimes truncate it — ask the sender for the full link. " +
			"The secret has NOT been opened.")
	}
	id := strings.TrimPrefix(u.Path, "/s/")
	if id == "" || strings.Contains(id, "/") {
		return "", fmt.Errorf("cannot find a secret id in the path %q", u.Path)
	}

	// Reveal against the link's OWN origin, not the configured base: a link
	// from a different hush deployment must not be posted to this one, where
	// the id would be meaningless.
	origin := u.Scheme + "://" + u.Host
	res, err := c.http.Post(origin+"/api/secrets/"+url.PathEscape(id)+"/reveal", "application/json", nil)
	if err != nil {
		return "", fmt.Errorf("reach hush at %s: %w", origin, err)
	}
	defer res.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))

	if res.StatusCode == http.StatusGone {
		return "", errors.New("gone: this link was already opened, expired, or never existed. " +
			"If you did not open it yourself, assume someone else did and ask the sender to rotate the secret.")
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hush returned %s: %s", res.Status, apiMessage(payload))
	}

	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("unexpected response from hush: %s", string(payload))
	}
	plain, err := open(out.Ciphertext, u.Fragment)
	if err != nil {
		// The ciphertext is already destroyed at this point, so there is
		// nothing to retry. Say that plainly.
		return "", fmt.Errorf("the key in this link does not open this secret, and the ciphertext "+
			"has now been destroyed (%w). The link was probably altered in transit; ask for a new one", err)
	}
	return plain, nil
}

// seal encrypts with AES-256-GCM and returns (ciphertext, key), both base64url.
// The nonce is prepended to the ciphertext so the stored blob is self-contained
// — byte-for-byte the format templates/base.html produces.
func seal(plaintext string) (string, string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	blob := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return b64.EncodeToString(blob), b64.EncodeToString(key), nil
}

func open(ciphertext, keyStr string) (string, error) {
	blob, err := b64.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("ciphertext is not base64url: %w", err)
	}
	key, err := b64.DecodeString(keyStr)
	if err != nil {
		return "", fmt.Errorf("key is not base64url: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(blob) < gcm.NonceSize() {
		return "", errors.New("ciphertext is too short to contain a nonce")
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("authentication failed")
	}
	return string(plain), nil
}

// apiMessage pulls the human message out of hush's error envelope, falling back
// to the raw body so a proxy's HTML error page is still readable.
func apiMessage(payload []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &e); err == nil && e.Error.Message != "" {
		return e.Error.Code + ": " + e.Error.Message
	}
	s := strings.TrimSpace(string(payload))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
