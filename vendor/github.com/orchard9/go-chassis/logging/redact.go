package logging

import "encoding/json"

// Forbidden reports whether key is a secrets/PII field name that must never be
// persisted in cleartext (logs, audit snapshots, alert payloads).
func Forbidden(key string) bool { return forbiddenKeys[key] }

// Redact returns "[REDACTED]" when key is forbidden, otherwise val. Use it when
// projecting attributes into a non-log sink (e.g. alert events).
func Redact(key, val string) string {
	if forbiddenKeys[key] {
		return "[REDACTED]"
	}
	return val
}

// RedactJSON returns a copy of a JSON document with every forbidden key's value
// (at any depth) replaced by "[REDACTED]". This is the defense-in-depth scrubber
// the audit sink applies to before/after snapshots so PII cannot land in the
// immutable audit log. Non-JSON or unparseable input is returned unchanged.
func RedactJSON(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return b
	}
	redactValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

func redactValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if forbiddenKeys[k] {
				t[k] = "[REDACTED]"
				continue
			}
			redactValue(val)
		}
	case []any:
		for _, e := range t {
			redactValue(e)
		}
	}
}
