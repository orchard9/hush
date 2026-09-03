#!/usr/bin/env python3
"""Render VictoriaLogs' JSON-lines output as one readable line per entry.

Kept as a file rather than inlined in logs.sh: quoting a python f-string inside
a shell heredoc inside a pipeline is how you get a SyntaxError that only shows
up against the live cluster.
"""
import json
import sys

# Fields Vector or the wire format always sets. They are shown in fixed columns
# or are pod plumbing, so they are not repeated in the trailing key=value list.
FIXED = {
    "_time", "_stream", "_stream_id", "_msg", "msg",
    "level", "service", "env", "host", "unit", "k8s_pod", "k8s_container",
}

rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        rows.append(json.loads(line))
    except ValueError:
        print("unparseable line:", line[:200], file=sys.stderr)

if not rows:
    print("no lines matched — has hush served a request in this window?")
    sys.exit(0)

# Oldest first, so reading top-to-bottom follows the sequence of events.
for r in sorted(rows, key=lambda x: x.get("_time", "")):
    ts = r.get("_time", "")[:23]
    level = r.get("level", "")
    msg = r.get("_msg") or r.get("msg", "")
    extra = " ".join(f"{k}={v}" for k, v in sorted(r.items()) if k not in FIXED)
    print("{:24} {:8} {:34} {}".format(ts, level, msg, extra))

print("\n{} lines".format(len(rows)), file=sys.stderr)
