#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_data.py -- generate tools/review-ui/data.js for the operator review UI.

i1745 review UI ③implementation. Plan bundle (source of truth):
main-repo docs/task-id/i1745-review-ui/bundle.md, section 2.1.

python3 stdlib only. Reads every candidates/*.json in this repository and
emits one self-contained data file that review.html loads via a single
<script> tag. Every validation failure is fatal (exit 1); stdout carries
the counts and the per-hint statistics the operator cross-checks against
the plan's measured expectations.

Embedded constants (keep in sync -- see README.md re-synchronization
procedure; each block names its upstream source line):
- GENERIC_WORDS (94 words)  : src/gate/lint.rs L55-150 (GENERIC_WORDS)
- PATTERN_MIN_BYTES = 4     : src/gate/lint.rs L37
- PATTERN_MAX_BYTES = 256   : src/gate/lint.rs L39
- RECOMMENDED_BYTES = 8     : src/gate/lint.rs L35-37 comment (review
                              checklist floor, enforced by review not lint)
- SOURCE_NOTE_MAX_BYTES 256 : src/gate/lint.rs L34
- SEEDS (60 entries)        : main repo
                              crates/waf-bundle-encoder/data/seed_patterns.json
                              ("entries"; the codec seed_blocklist asset).
                              Embedded so this generator runs standalone in
                              this repository (stdlib + repo files only).

Escape note (bundle 2.1): the serialized JSON escapes the less-than
character (U+003C) into its JSON string escape. JSON grammar allows that
character inside string literals only, so a global replace over the
serialized text is safe (this rationale sentence is the only place it is
documented, per the bundle). This file never spells the escape sequence as
a literal; it is built by concatenation (chr(92) + "u003c") so a source
edit cannot collapse it into the character itself, and the synthetic
self-check below mechanically proves the replace is a real no-op guard
against accidental removal.
"""

import glob
import hashlib
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone

LT = chr(60)             # the less-than character itself, never typed raw in strings here
ESC = chr(92) + "u003c"  # its JSON string escape, built by concatenation

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CANDIDATES_DIR = os.path.join(REPO_ROOT, "candidates")
TSV_PATH = os.path.join(CANDIDATES_DIR, "_REVIEW-INDEX.tsv")
OUTPUT_PATH = os.path.join(REPO_ROOT, "tools", "review-ui", "data.js")

FORMAT = "vpatch-review-data"
VERSION = 1
ALLOWED_KINDS = {"poc_reference", "nvd_cpe"}
ALLOWED_STATUSES = {"proposed"}
ALLOWED_PATTERN_TYPES = {
    "query_string",
    "request_uri",
    "user_agent",
    "request_method",
    "request_body",
}

# --- embedded constants (sources in the module docstring) -------------------

PATTERN_MIN_BYTES = 4      # lint.rs L37
RECOMMENDED_BYTES = 8      # lint.rs L35-37 comment
PATTERN_MAX_BYTES = 256    # lint.rs L39
SOURCE_NOTE_MAX_BYTES = 256  # lint.rs L34
ID_FORMAT = "vp-cve-<year>-<nnnnn>[-suffix]"  # lint.rs Diagnostic::IdFormat
CATEGORY = "cve-virtual-patch"                # design 7 feed convention

GENERIC_WORDS_EXPECTED = 94  # lint.rs L55-150 carries exactly 94 words
GENERIC_WORDS = [
    "select", "union", "insert", "update", "delete", "drop", "alert",
    "script", "error", "admin", "administrator", "login", "logout",
    "password", "passwd", "username", "user", "users", "test", "testing",
    "debug", "config", "configuration", "settings", "setup", "install",
    "backup", "restore", "export", "import", "upload", "download", "file",
    "files", "image", "images", "search", "query", "index", "home", "main",
    "about", "contact", "account", "profile", "dashboard", "panel",
    "console", "shell", "root", "system", "temp", "tmp", "cache", "log",
    "logs", "cookie", "session", "token", "auth", "secret", "key", "data",
    "name", "value", "page", "site", "web", "mail", "email", "list",
    "item", "items", "order", "status", "create", "new", "edit", "view",
    "show", "get", "post", "put", "set", "add", "remove", "info", "api",
    "app", "help", "docs", "static", "assets", "media",
]

SEEDS_EXPECTED = 60  # seed_patterns.json entries at embedding time
SEEDS = [
    {"pattern_type": "query_string", "pattern": "' --"},
    {"pattern_type": "query_string", "pattern": "' and '"},
    {"pattern_type": "query_string", "pattern": "' or '"},
    {"pattern_type": "query_string", "pattern": "@@version"},
    {"pattern_type": "query_string", "pattern": "alert("},
    {"pattern_type": "query_string", "pattern": "benchmark("},
    {"pattern_type": "query_string", "pattern": "document.cookie"},
    {"pattern_type": "query_string", "pattern": "drop table"},
    {"pattern_type": "query_string", "pattern": "expression("},
    {"pattern_type": "query_string", "pattern": "file=http"},
    {"pattern_type": "query_string", "pattern": "group_concat("},
    {"pattern_type": "query_string", "pattern": "include=http"},
    {"pattern_type": "query_string", "pattern": "information_schema"},
    {"pattern_type": "query_string", "pattern": "into outfile"},
    {"pattern_type": "query_string", "pattern": "load_file("},
    {"pattern_type": "query_string", "pattern": "onerror="},
    {"pattern_type": "query_string", "pattern": "onload="},
    {"pattern_type": "query_string", "pattern": "onmouseover="},
    {"pattern_type": "query_string", "pattern": "or 1=1"},
    {"pattern_type": "query_string", "pattern": "prompt("},
    {"pattern_type": "query_string", "pattern": "select database("},
    {"pattern_type": "query_string", "pattern": "select version("},
    {"pattern_type": "query_string", "pattern": "sleep("},
    {"pattern_type": "query_string", "pattern": "union all select"},
    {"pattern_type": "query_string", "pattern": "union select"},
    {"pattern_type": "query_string", "pattern": "waitfor delay"},
    {"pattern_type": "request_body", "pattern": "<script"},
    {"pattern_type": "request_body", "pattern": "union select"},
    {"pattern_type": "request_method", "pattern": "connect"},
    {"pattern_type": "request_method", "pattern": "trace"},
    {"pattern_type": "request_method", "pattern": "track"},
    {"pattern_type": "request_uri", "pattern": "../"},
    {"pattern_type": "request_uri", "pattern": "..\\\\"},
    {"pattern_type": "request_uri", "pattern": ".env"},
    {"pattern_type": "request_uri", "pattern": ".htaccess"},
    {"pattern_type": "request_uri", "pattern": "/etc/passwd"},
    {"pattern_type": "request_uri", "pattern": "/etc/shadow"},
    {"pattern_type": "request_uri", "pattern": "/proc/self"},
    {"pattern_type": "request_uri", "pattern": "<iframe"},
    {"pattern_type": "request_uri", "pattern": "<img"},
    {"pattern_type": "request_uri", "pattern": "<script"},
    {"pattern_type": "request_uri", "pattern": "<svg"},
    {"pattern_type": "request_uri", "pattern": "boot.ini"},
    {"pattern_type": "request_uri", "pattern": "data:text/html"},
    {"pattern_type": "request_uri", "pattern": "javascript:"},
    {"pattern_type": "request_uri", "pattern": "vbscript:"},
    {"pattern_type": "request_uri", "pattern": "win.ini"},
    {"pattern_type": "user_agent", "pattern": "acunetix"},
    {"pattern_type": "user_agent", "pattern": "dirbuster"},
    {"pattern_type": "user_agent", "pattern": "gobuster"},
    {"pattern_type": "user_agent", "pattern": "havij"},
    {"pattern_type": "user_agent", "pattern": "hydra"},
    {"pattern_type": "user_agent", "pattern": "masscan"},
    {"pattern_type": "user_agent", "pattern": "nessus"},
    {"pattern_type": "user_agent", "pattern": "nikto"},
    {"pattern_type": "user_agent", "pattern": "nmap scripting"},
    {"pattern_type": "user_agent", "pattern": "owasp zap"},
    {"pattern_type": "user_agent", "pattern": "sqlmap"},
    {"pattern_type": "user_agent", "pattern": "w3af"},
    {"pattern_type": "user_agent", "pattern": "wfuzz"},
]

GENERIC_WORDS_SET = frozenset(GENERIC_WORDS)
SEED_PAIRS = frozenset((s["pattern_type"], s["pattern"]) for s in SEEDS)

# lint.rs L635-645: split on non-alphanumeric, drop empties, single part
# that is itself a generic word.
SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")


def die(message):
    sys.stderr.write("build_data.py: " + message + "\n")
    sys.exit(1)


def compute_hints(literal, pattern_type):
    """Mirror lint_candidate_literal (src/gate/lint.rs L608-662) at the
    literal level. Advisory only -- the final gate is the producer CI."""
    raw = literal.encode("utf-8")
    size = len(raw)
    not_lower_ascii = (not literal.isascii()) or any(65 <= byte <= 90 for byte in raw)
    parts = [p for p in SPLIT_RE.split(literal) if p]
    generic_standalone = (
        pattern_type != "request_method"
        and len(parts) == 1
        and parts[0] in GENERIC_WORDS_SET
    )
    return {
        "bytes": size,
        "lt_recommended": size < RECOMMENDED_BYTES,
        "gt_max": size > PATTERN_MAX_BYTES,
        "generic_standalone": generic_standalone,
        "not_lower_ascii": not_lower_ascii,
        "not_canonical": literal != literal.strip(),  # lint.rs L625
        "control_char": any(  # lint.rs L628 (Unicode Cc category)
            unicodedata.category(ch) == "Cc" for ch in literal
        ),
        "seed_duplicate": (pattern_type, literal) in SEED_PAIRS,  # lint.rs L652
    }


def recommended_severity(kev, cvss):
    # design 7 severity mapping: KEV or CVSS >= 9.0 -> critical, else warning
    return "critical" if (kev or cvss >= 9.0) else "warning"


def group_sort_key(group):
    # bundle 2.1: kev desc, cvss desc, cve asc
    return (0 if group["kev"] else 1, -group["cvss"], group["cve"])


def serialize(obj):
    """The single serialization path: ensure_ascii JSON, then the global
    less-than escape. The synthetic self-check proves this is a real
    transform (see main)."""
    return json.dumps(obj, ensure_ascii=True).replace(LT, ESC)


def main():
    if len(GENERIC_WORDS) != GENERIC_WORDS_EXPECTED:
        die("GENERIC_WORDS count %d != expected %d -- re-sync with lint.rs" % (
            len(GENERIC_WORDS), GENERIC_WORDS_EXPECTED))
    if len(SEEDS) != SEEDS_EXPECTED:
        die("SEEDS count %d != expected %d -- re-sync with seed_patterns.json" % (
            len(SEEDS), SEEDS_EXPECTED))
    if len(SEED_PAIRS) != len(SEEDS):
        die("seed list carries duplicate (pattern_type, pattern) pairs")

    files = sorted(glob.glob(os.path.join(CANDIDATES_DIR, "*.json")))
    if not files:
        die("no candidates/*.json found under " + CANDIDATES_DIR)

    # -- validation 1: full parse of every file (all-or-nothing) ----------
    groups = []
    keys = []          # composite keys in file order
    key_set = set()
    pair_set = set()   # (cve, literal)
    kind_counts = {"poc_reference": 0, "nvd_cpe": 0}
    hint_counts = {
        "lt_recommended": 0, "gt_max": 0, "generic_standalone": 0,
        "not_lower_ascii": 0, "not_canonical": 0, "control_char": 0,
        "seed_duplicate": 0,
    }
    non_ascii = 0
    uppercase_ascii = 0
    lt_literals = 0

    for path in files:
        rel = os.path.relpath(path, CANDIDATES_DIR)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError) as error:
            die("parse failure in %s: %s" % (rel, error))
        cve = record.get("cve")
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            die("%s: missing or malformed cve" % rel)
        kev = record.get("kev")
        if not isinstance(kev, bool):
            die("%s: missing boolean kev" % rel)
        cvss = record.get("cvss")
        if not isinstance(cvss, (int, float)) or isinstance(cvss, bool):
            die("%s: missing numeric cvss" % rel)
        tokens = record.get("tokens")
        if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
            die("%s: missing tokens list" % rel)
        candidates = record.get("candidates")
        if not isinstance(candidates, list):
            die("%s: missing candidates list" % rel)

        built = []
        for index, entry in enumerate(candidates):
            literal = entry.get("literal")
            pattern_type = entry.get("pattern_type")
            provenance = entry.get("provenance")
            status = entry.get("status")
            if not isinstance(literal, str) or literal == "":
                die("%s candidate %d: missing literal" % (rel, index))
            if pattern_type not in ALLOWED_PATTERN_TYPES:
                die("%s candidate %d: pattern_type %r not allowed" % (rel, index, pattern_type))
            if not isinstance(provenance, dict):
                die("%s candidate %d: missing provenance object" % (rel, index))
            kind = provenance.get("kind")
            # -- validation 5: provenance.kind subset check ----------------
            if kind not in ALLOWED_KINDS:
                die("%s candidate %d: provenance.kind %r not in %s" % (
                    rel, index, kind, sorted(ALLOWED_KINDS)))
            if status not in ALLOWED_STATUSES:
                die("%s candidate %d: status %r not in %s" % (
                    rel, index, status, sorted(ALLOWED_STATUSES)))
            key = cve + "\t" + pattern_type + "\t" + literal
            # -- validation 4: composite key uniqueness --------------------
            if key in key_set:
                die("duplicate composite key: %r" % key)
            key_set.add(key)
            keys.append(key)
            pair_set.add((cve, literal))
            kind_counts[kind] += 1
            if LT in literal:
                lt_literals += 1
            hints = compute_hints(literal, pattern_type)
            for name, flag in hints.items():
                if name != "bytes" and flag:
                    hint_counts[name] += 1
            if not literal.isascii():
                non_ascii += 1
            elif any(65 <= byte <= 90 for byte in literal.encode("utf-8")):
                uppercase_ascii += 1
            built.append({
                "key": key,
                "literal": literal,
                "pattern_type": pattern_type,
                "provenance": provenance,
                "status": status,
                "hints": hints,
            })

        if built:
            groups.append({
                "cve": cve,
                "kev": kev,
                "cvss": float(cvss),
                "tokens": tokens,
                "recommended_severity": recommended_severity(kev, float(cvss)),
                "candidates": built,
            })

    candidates_total = len(keys)
    tsv_rows = 0
    tsv_pairs = set()
    try:
        with open(TSV_PATH, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as error:
        die("cannot read review index: %s" % error)
    if not lines:
        die("review index is empty: %s" % TSV_PATH)
    for row in lines[1:]:
        if not row:
            continue
        columns = row.split("\t")
        if len(columns) != 6:
            die("review index row has %d columns (expected 6): %r" % (len(columns), row))
        tsv_rows += 1
        pair = (columns[0], columns[2])
        # -- validation 3: every TSV (cve, literal) pair exists ----------
        if pair not in pair_set:
            die("review index pair not found in candidates: (%s, %s)" % pair)
        # a duplicate row plus a missing row would pass both the total and
        # the subset checks above -- TSV rows must be unique on (cve, literal)
        if pair in tsv_pairs:
            die("duplicate review index row on (cve, literal): (%s, %s)" % pair)
        tsv_pairs.add(pair)

    # -- validation 2: total candidates == TSV data rows -------------------
    if candidates_total != tsv_rows:
        die("candidate total %d != review index rows %d" % (candidates_total, tsv_rows))

    groups.sort(key=group_sort_key)

    fingerprint = "sha256:" + hashlib.sha256(
        ("\t".join(sorted(keys))).encode("utf-8")
    ).hexdigest()

    payload = {
        "format": FORMAT,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint": fingerprint,
        "counts": {
            "files": len(files),
            "candidates": candidates_total,
            "cves_with_candidates": len(groups),
            "poc_reference": kind_counts["poc_reference"],
            "nvd_cpe": kind_counts["nvd_cpe"],
        },
        "constants": {
            "pattern_min_bytes": PATTERN_MIN_BYTES,
            "recommended_bytes": RECOMMENDED_BYTES,
            "pattern_max_bytes": PATTERN_MAX_BYTES,
            "generic_words": GENERIC_WORDS,
            "seeds": SEEDS,
            "source_note_max_bytes": SOURCE_NOTE_MAX_BYTES,
            "id_format": ID_FORMAT,
            "category": CATEGORY,
        },
        "cves": groups,
    }

    # -- validation 6a: synthetic no-op defense -----------------------------
    # A synthetic input that carries the less-than character must come out
    # of serialize() escaped and clean. This is what makes the absence
    # check below meaningful even though the current corpus has zero such
    # characters: if the replace were deleted (a no-op), this check fails.
    synthetic_raw = {"a": "x" + LT + "y"}
    synthetic_unescaped = json.dumps(synthetic_raw, ensure_ascii=True)
    if LT not in synthetic_unescaped:
        die("self-check broken: synthetic input lost its less-than character")
    synthetic_out = serialize(synthetic_raw)
    if LT in synthetic_out or ESC not in synthetic_out:
        die("self-check FAILED: the escape replace is a no-op -- "
            "serialization output would carry a raw less-than character")

    body = serialize(payload)
    # -- validation 6b: output text carries no raw less-than character -----
    if LT in body:
        die("output text carries a raw less-than character after escaping")
    output = "window.VPATCH_REVIEW_DATA = " + body + ";\n"

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="ascii", newline="\n") as handle:
        handle.write(output)
    # belt and suspenders: re-read bytes and assert absence + ascii
    with open(OUTPUT_PATH, "rb") as handle:
        raw = handle.read()
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as error:
        die("output is not pure ASCII: %s" % error)
    if LT.encode("ascii") in raw:
        die("output bytes carry a raw less-than character")

    counts = payload["counts"]
    print("generated %s" % os.path.relpath(OUTPUT_PATH, REPO_ROOT))
    print("format=%s version=%d generated_at=%s" % (FORMAT, VERSION, payload["generated_at"]))
    print("fingerprint=%s" % fingerprint)
    print("counts: files=%d candidates=%d cves_with_candidates=%d poc_reference=%d nvd_cpe=%d" % (
        counts["files"], counts["candidates"], counts["cves_with_candidates"],
        counts["poc_reference"], counts["nvd_cpe"]))
    print("hints: lt_recommended(<%dB)=%d gt_max(>%dB)=%d generic_standalone=%d" % (
        RECOMMENDED_BYTES, hint_counts["lt_recommended"], PATTERN_MAX_BYTES,
        hint_counts["gt_max"], hint_counts["generic_standalone"]))
    print("hints: not_lower_ascii=%d (non_ascii=%d uppercase_ascii=%d) not_canonical=%d" % (
        hint_counts["not_lower_ascii"], non_ascii, uppercase_ascii,
        hint_counts["not_canonical"]))
    print("hints: control_char=%d seed_duplicate=%d literals_with_lt_char=%d" % (
        hint_counts["control_char"], hint_counts["seed_duplicate"], lt_literals))
    print("self-check: synthetic escape OK (raw in, escaped out); output %d bytes, "
          "pure ascii, no raw less-than character" % len(raw))
    print("ALL VALIDATIONS PASSED (parse %d files, %d==%d keys, kinds %s, keys unique)" % (
        len(files), candidates_total, tsv_rows, sorted(ALLOWED_KINDS)))


if __name__ == "__main__":
    main()
