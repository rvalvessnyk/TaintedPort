#!/usr/bin/env python3
"""
Guard against leaking TaintedPort vuln "answer-key" content into the PUBLIC repo.

The public TaintedPort repo legitimately contains the *vulnerable code* (it is
the system under test). It must NEVER contain the *answer key*: the known-vuln
catalog, the vuln -> endpoint -> CWE -> severity mapping, exploit/PoC
descriptions, or "notes for testers". That material lives only in the private
companion repo (TaintedPort-Vulns) and is injected at container-build time.

Two independent detectors:

  1. NARRATIVE match (needs the private repo). Derives "narrative" fingerprint
     lines from the private catalog files (KnownVulnerabilities*.txt) -- every
     line EXCEPT code-shaped ones, because the PoC files quote real app code
     that legitimately lives here. Any public file containing such a line is a
     leak, unless its hash is whitelisted in tests/.vuln-leak-baseline
     (legitimate overlaps, stored as one-way hashes -- never plaintext).

  2. STRUCTURAL heuristic (always runs, no private repo needed). Flags any
     tracked text file shaped like a vuln catalog: many "CWE-####" lines paired
     with severities. Catches an accidentally committed catalog even on a
     machine without the private repo.

This file and the baseline contain NO answer-key content (only logic + hashes),
so the guard cannot itself taint the repo it protects.

Usage:
  python3 tests/check_no_vuln_leak.py                  # scan tracked working tree
  python3 tests/check_no_vuln_leak.py --range A B       # scan blobs introduced in A..B
  python3 tests/check_no_vuln_leak.py --update-baseline # accept current narrative overlaps

Exit 0 = clean, 1 = potential leak, 2 = usage/internal error.
The private repo is located via $TAINTEDPORT_VULNS, else ../TaintedPort-Vulns.
"""
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()
BASELINE = os.path.join(HERE, ".vuln-leak-baseline")

# Files the scanner should never flag (it scans content, not these meta files).
SELF_SKIP = {
    os.path.relpath(os.path.join(HERE, "check_no_vuln_leak.py"), ROOT),
    os.path.relpath(BASELINE, ROOT),
}

MIN_LEN = 35  # ignore short/generic lines
STRUCTURAL_CWE_THRESHOLD = 5  # >= this many CWE rows in one file => looks like a catalog

_ws = re.compile(r"\s+")
_codey = re.compile(r"[;{}$]|=>|<\?|\?>|</|==|&&|\|\||\bfunction \b|\breturn \b|"
                    r"console\.|\bclass \b|::|\$_|//|/\*")
_cwe = re.compile(r"\bCWE-\d{1,4}\b")
_sev = re.compile(r"\b(critical|high|medium|low)\b", re.I)


def norm(s):
    return _ws.sub(" ", s).strip()


def is_codey(line):
    """True if a line looks like source code rather than answer-key prose."""
    if _codey.search(line):
        return True
    punct = sum(1 for c in line if c in "(){}[]<>;=$/\\|`")
    return punct / max(len(line), 1) > 0.15


def line_hash(line):
    return hashlib.sha256(norm(line).encode("utf-8")).hexdigest()


def find_vulns_repo():
    cand = os.environ.get("TAINTEDPORT_VULNS")
    if cand and os.path.isdir(cand):
        return cand
    sibling = os.path.normpath(os.path.join(ROOT, "..", "TaintedPort-Vulns"))
    return sibling if os.path.isdir(sibling) else None


def narrative_fingerprints(vulns_repo):
    """Distinctive answer-key narrative lines (catalog rows, CWE/severity, prose)."""
    fps = set()
    for name in sorted(os.listdir(vulns_repo)):
        if not re.match(r"KnownVulnerabilities.*\.txt$", name):
            continue
        with open(os.path.join(vulns_repo, name), encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                n = norm(raw)
                if len(n) >= MIN_LEN and not is_codey(n):
                    fps.add(n)
    return fps


def load_baseline():
    if not os.path.exists(BASELINE):
        return set()
    out = set()
    for ln in open(BASELINE, encoding="utf-8"):
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.add(ln)
    return out


def is_binary(data):
    return b"\x00" in data[:4096]


def iter_tracked_files():
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    for path in raw.decode("utf-8", "replace").split("\0"):
        if not path or path in SELF_SKIP:
            continue
        full = os.path.join(ROOT, path)
        try:
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if is_binary(data):
            continue
        yield path, data.decode("utf-8", "replace")


def iter_pushed_blobs(rev_a, rev_b):
    """Yield (label, text) for every blob introduced in rev_a..rev_b."""
    if re.fullmatch(r"0+", rev_a or ""):
        spec = [rev_b, "--not", "--remotes"]  # new branch: objects not already on a remote
    else:
        spec = [f"{rev_a}..{rev_b}"]
    out = subprocess.check_output(["git", "rev-list", "--objects"] + spec, cwd=ROOT)
    for ln in out.decode("utf-8", "replace").splitlines():
        parts = ln.split(" ", 1)
        if len(parts) != 2:
            continue  # commit/tree object with no path
        sha, path = parts
        if path in SELF_SKIP:
            continue
        try:
            t = subprocess.check_output(["git", "cat-file", "-t", sha], cwd=ROOT).decode().strip()
            if t != "blob":
                continue
            data = subprocess.check_output(["git", "cat-file", "blob", sha], cwd=ROOT)
        except subprocess.CalledProcessError:
            continue
        if is_binary(data):
            continue
        yield f"{path}@{sha[:8]}", data.decode("utf-8", "replace")


def scan(sources, fps, baseline):
    """sources: iterable of (label, text). Returns list of (label, lineno, line)."""
    leaks = []
    for label, text in sources:
        seen_structural = 0
        for i, raw in enumerate(text.splitlines(), 1):
            n = norm(raw)
            if len(n) < MIN_LEN:
                # still count CWE rows for the structural heuristic
                if _cwe.search(raw) and _sev.search(raw):
                    seen_structural += 1
                continue
            # detector 1: narrative fingerprint
            if fps and n in fps and line_hash(n) not in baseline:
                leaks.append((label, i, n))
            # detector 2: structural catalog rows
            if _cwe.search(raw) and _sev.search(raw):
                seen_structural += 1
        if seen_structural >= STRUCTURAL_CWE_THRESHOLD:
            leaks.append((label, 0,
                          f"[structural] file has {seen_structural} CWE+severity rows "
                          f"-- looks like a leaked vuln catalog"))
    return leaks


def main(argv):
    update = "--update-baseline" in argv
    rng = None
    if "--range" in argv:
        idx = argv.index("--range")
        try:
            rng = (argv[idx + 1], argv[idx + 2])
        except IndexError:
            print("usage: --range <old-sha> <new-sha>", file=sys.stderr)
            return 2

    vulns_repo = find_vulns_repo()
    if vulns_repo:
        fps = narrative_fingerprints(vulns_repo)
    else:
        fps = set()
        print("WARN: private repo (TaintedPort-Vulns) not found -- "
              "narrative check skipped, structural check only.", file=sys.stderr)

    if update:
        if not fps:
            print("Cannot update baseline without the private repo.", file=sys.stderr)
            return 2
        leaks = scan(iter_tracked_files(), fps, set())
        hashes = sorted({line_hash(l) for _, n, l in leaks if n})  # n==0 are structural
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write("# Accepted answer-key overlaps (sha256 of normalized lines).\n")
            fh.write("# Hashes only -- no plaintext. Regenerate: "
                     "python3 tests/check_no_vuln_leak.py --update-baseline\n")
            for h in hashes:
                fh.write(h + "\n")
        print(f"Baseline updated with {len(hashes)} accepted overlap(s): {BASELINE}")
        return 0

    baseline = load_baseline()
    sources = iter_pushed_blobs(*rng) if rng else iter_tracked_files()
    leaks = scan(sources, fps, baseline)

    if not leaks:
        print("OK: no vuln answer-key content detected in the public repo.")
        return 0

    print("\n*** VULN INFO LEAK DETECTED -- push blocked ***\n", file=sys.stderr)
    print("The following look like private answer-key content that must not enter\n"
          "the public TaintedPort repo (it would persist in git history):\n", file=sys.stderr)
    for label, lineno, line in leaks:
        where = f"{label}:{lineno}" if lineno else label
        print(f"  {where}\n      {line[:120]}", file=sys.stderr)
    print("\nIf a match is a genuine, intentional overlap with real app code, accept it:\n"
          "  python3 tests/check_no_vuln_leak.py --update-baseline\n"
          "Otherwise remove the content before committing/pushing.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as e:  # noqa: BLE001 -- a guard must fail loud, not crash silently
        print(f"check_no_vuln_leak: internal error: {e}", file=sys.stderr)
        sys.exit(2)
