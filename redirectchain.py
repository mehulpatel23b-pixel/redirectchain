#!/usr/bin/env python3
"""redirectchain - trace and score a URL redirect chain before a user clicks.

A phishing link is rarely one hop. It is a shortener, then a tracking domain, then an
open redirect on a trusted site, then a clone of your login page. Each hop is chosen to
look innocent on its own.

This tool walks the chain, classifies every hop, and reports where the trust breaks.

Zero dependencies. Pure standard library. Network only when you ask for it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 40, "high": 22, "medium": 11, "low": 5, "info": 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (85, "E"), (999, "F")]

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "t.ly", "s.id", "bl.ink",
    "clck.ru", "vk.cc", "trib.al", "shorte.st", "adf.ly", "bc.vc", "soo.gd", "urlz.fr",
}

REDIRECT_PARAMS = {
    "url", "uri", "next", "redirect", "redirect_uri", "redirect_url", "return", "returnto",
    "return_url", "continue", "continue_url", "dest", "destination", "target", "goto", "go",
    "out", "link", "to", "r", "u", "forward", "redir", "callback", "checkout_url",
}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid",
    "msclkid", "mc_eid", "igshid", "yclid", "dclid", "twclid",
}

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "com.au",
    "net.au", "org.au", "co.nz", "co.za", "com.br", "com.mx", "com.tr", "com.sg", "com.hk",
    "co.kr", "com.cn", "com.tw", "com.ar", "com.co", "com.my", "co.id", "com.ph", "com.vn",
}

BASE64ISH = re.compile(r"^[A-Za-z0-9_\-=]{40,}$")
META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url=([^"'>\s]+)""",
    re.I)
JS_REDIRECT = re.compile(
    r"""(?:window\.|document\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["']([^"']+)["']""",
    re.I)


class ChainError(Exception):
    """Raised when a chain cannot be read or fetched."""


def registrable(host):
    """Last two labels, honouring common multi-part suffixes. Heuristic, not a full PSL."""
    if not host:
        return ""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split_url(url):
    """Return (scheme, host, path, query dict) with no crashes on junk input."""
    parsed = urllib.parse.urlsplit(url.strip())
    return parsed.scheme.lower(), parsed.hostname or "", parsed.path, urllib.parse.parse_qs(parsed.query)


def is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "")) or bool(re.fullmatch(r"\[[0-9a-f:]+\]", host or ""))


def base64_blob_in_path(path):
    for segment in (path or "").split("/"):
        if BASE64ISH.match(segment):
            return segment
    return ""


def hop_from_dict(item, index):
    if isinstance(item, str):
        return {"n": index, "url": item, "status": None, "location": None, "body": ""}
    return {
        "n": item.get("n", index),
        "url": item.get("url", ""),
        "status": item.get("status"),
        "location": item.get("location"),
        "body": item.get("body", "") or "",
    }


def load_chain(path):
    """Read a chain from JSON (list of hops) or plain text (one URL per line)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ChainError("%s: %s" % (path, exc)) from exc
    stripped = raw.strip()
    if not stripped:
        raise ChainError("%s: file is empty" % path)
    if stripped[0] in "[{":
        try:
            data = json.loads(stripped)
        except ValueError as exc:
            raise ChainError("%s: invalid JSON (%s)" % (path, exc)) from exc
        if isinstance(data, dict):
            data = data.get("hops") or data.get("chain") or []
        if not isinstance(data, list):
            raise ChainError("%s: JSON must be a list of hops" % path)
        return [hop_from_dict(item, i) for i, item in enumerate(data)]
    hops = []
    for i, line in enumerate(stripped.splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        status = None
        match = re.match(r"^(\d{3})\s+(.+)$", line)
        if match:
            status, line = int(match.group(1)), match.group(2).strip()
        hops.append({"n": len(hops), "url": line, "status": status, "location": None, "body": ""})
    if not hops:
        raise ChainError("%s: no URLs found" % path)
    return hops


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def fetch_chain(url, max_hops=10, timeout=8.0, body_bytes=65536):
    """Walk the chain live, one hop at a time, without following redirects automatically."""
    opener = urllib.request.build_opener(NoRedirect)
    opener.addheaders = [("User-Agent", "redirectchain/%s (+defensive triage)" % __version__)]
    hops, seen = [], set()
    current = url.strip()
    for index in range(max_hops + 1):
        if not current:
            break
        key = current.split("#")[0]
        if key in seen:
            hops.append({"n": index, "url": current, "status": None, "location": None,
                         "body": "", "note": "loop"})
            break
        seen.add(key)
        body, status, location = "", None, None
        try:
            with opener.open(current, timeout=timeout) as resp:
                status = resp.status
                location = resp.headers.get("Location")
                body = resp.read(body_bytes).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            location = exc.headers.get("Location")
            try:
                body = exc.read(body_bytes).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - body is best effort
                body = ""
        except (urllib.error.URLError, ValueError, OSError) as exc:
            hops.append({"n": index, "url": current, "status": None, "location": None,
                         "body": "", "note": "unreachable: %s" % exc})
            break
        hops.append({"n": index, "url": current, "status": status, "location": location, "body": body})
        if location:
            current = urllib.parse.urljoin(current, location)
        elif status and 200 <= status < 300:
            break
        else:
            break
    if not hops:
        raise ChainError("could not fetch %s" % url)
    return hops


def analyse(hops):
    """Classify every hop and return (findings, hops_enriched, chain_summary)."""
    found = []

    def add(sev, code, hop, detail, fix):
        found.append({"severity": sev, "code": code, "hop": hop["n"], "url": hop["url"],
                      "detail": detail, "fix": fix})

    enriched, domains, previous = [], [], None
    for hop in hops:
        scheme, host, path, query = split_url(hop["url"])
        target = hop.get("location") or ""
        target_scheme, target_host, _tp, _tq = split_url(target) if target else ("", "", "", {})
        domains.append(registrable(host))
        item = dict(hop)
        item.update({"scheme": scheme, "host": host, "host_domain": registrable(host),
                     "target_host": target_host, "target_domain": registrable(target_host)})
        enriched.append(item)

        if scheme in ("javascript", "data", "vbscript"):
            add("critical", "RC-SCRIPT-SCHEME", hop,
                "%s: URI used as a redirect destination" % scheme,
                "No legitimate link ends in a %s: URI. Treat it as a script payload." % scheme)
        if scheme == "http":
            add("medium", "RC-PLAINTEXT", hop,
                "hop is served over plain http",
                "Use https, and never let a chain leave https for http mid-flow.")
        if previous == "https" and scheme == "http":
            add("high", "RC-DOWNGRADE", hop,
                "chain drops from https to http at this hop",
                "A downgrade mid-chain means the last hop can be rewritten in transit.")
        if "@" in urllib.parse.urlsplit(hop["url"]).netloc:
            add("high", "RC-USERINFO", hop,
                "URL carries userinfo before the host (looks like a domain, connects elsewhere)",
                "Read only the text after the @: that is the real host.")
        if is_ip(host):
            add("medium", "RC-IP-HOST", hop,
                "host is a bare IP address (%s)" % host,
                "Brands do not link to raw IPs. Treat as suspicious unless you know the host.")
        if "xn--" in host:
            add("medium", "RC-PUNYCODE", hop,
                "punycode host, may render as a lookalike of a known brand",
                "Decode the host and compare it to the brand it imitates.")
        if host in SHORTENERS:
            add("medium", "RC-SHORTENER", hop,
                "%s hides the true destination from the user" % host,
                "Expand before delivery. Users cannot judge a link they cannot see.")
        blob = base64_blob_in_path(path)
        if blob:
            add("low", "RC-ENCODED-PATH", hop,
                "path contains a %d-character encoded blob" % len(blob),
                "Encoded blobs in paths usually carry the final destination or a victim identifier.")
        tracked = sorted(p for p in query if p.lower() in TRACKING_PARAMS)
        if tracked:
            add("info", "RC-TRACKING", hop,
                "tracking parameters present: %s" % ", ".join(tracked),
                "Strip them before sharing the link so it cannot be tied to a campaign.")
        target_params = {k.lower(): v for k, v in query.items()}
        redirecting = sorted(p for p in target_params if p in REDIRECT_PARAMS)
        if redirecting:
            value = (target_params[redirecting[0]] or [""])[0]
            if value.lower().startswith(("http://", "https://", "/", "//")):
                resolved = urllib.parse.urljoin(hop["url"], value)
                _s, param_host, _p, _q = split_url(resolved)
                crosses = registrable(param_host) and registrable(param_host) != registrable(host)
                if crosses:
                    add("high", "RC-OPEN-REDIRECT", hop,
                        "parameter '%s' redirects off-site to %s" % (redirecting[0], param_host),
                        "Add an allowlist for that parameter. An open redirect borrows the "
                        "trust of your own domain for someone else's landing page.")
                else:
                    add("low", "RC-REDIRECT-PARAM", hop,
                        "parameter '%s' controls the next destination" % redirecting[0],
                        "Confirm the value is constrained to expected paths.")
        if scheme == "https" and target_scheme == "http" and target_host:
            add("high", "RC-DOWNGRADE", hop, "Location header points to plain http", "Reject http destinations.")
        body = hop.get("body") or ""
        if body:
            match = META_REFRESH.search(body)
            if match:
                add("medium", "RC-META-REFRESH", hop,
                    "page redirects via meta refresh to %s" % match.group(1)[:80],
                    "Meta refresh is the cheapest way to hide the real destination from link scanners.")
            match = JS_REDIRECT.search(body)
            if match and match.group(1).lower().startswith(("http", "//")):
                add("medium", "RC-JS-REDIRECT", hop,
                    "page redirects via JavaScript to %s" % match.group(1)[:80],
                    "Link scanners do not execute JavaScript, so these hops stay hidden.")
        previous = scheme or previous

    transitions = []
    for i in range(1, len(domains)):
        if domains[i] and domains[i - 1] and domains[i] != domains[i - 1]:
            transitions.append((domains[i - 1], domains[i]))
    if len(transitions) >= 2:
        add("low", "RC-CROSS-DOMAIN", hops[-1] if hops else {"n": 0, "url": ""},
            "chain changes registrable domain %d times (%s)" % (
                len(transitions), " -> ".join(d for pair in transitions[:4] for d in pair)),
            "Every domain change is a place to hide the payload. More than two is a smell.")
    if len(hops) > 5:
        add("low", "RC-LONG-CHAIN", hops[-1],
            "%d hops before reaching the destination" % len(hops),
            "Legitimate marketing links use one or two hops. Five or more is deliberate layering.")
    loops = [h for h in hops if h.get("note") == "loop"]
    for hop in loops:
        add("medium", "RC-LOOP", hop, "chain returns to a URL already visited",
            "A loop wastes the user's time and defeats simple prefetch scanners.")
    final = hops[-1] if hops else None
    if final and final.get("status") and final["status"] >= 400:
        add("info", "RC-DEAD-END", final, "final hop answered HTTP %s" % final["status"],
            "Either the campaign is down or it only answers to the right user agent.")

    found.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["hop"]))
    return found, enriched


def score(findings):
    total = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    total = max(0, min(100, total))
    grade = next(g for threshold, g in GRADES if total <= threshold)
    return total, grade


def build_report(hops, source):
    found, enriched = analyse(hops)
    risk, grade = score(found)
    counts = {sev: sum(1 for f in found if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    summary = {
        "source": source,
        "hops": len(hops),
        "final_url": hops[-1]["url"] if hops else "",
        "final_domain": registrable(split_url(hops[-1]["url"])[1]) if hops else "",
        "risk": risk,
        "grade": grade,
        "counts": counts,
        "gate": "FAIL" if counts["critical"] or counts["high"] else "PASS",
    }
    return {"summary": summary, "hops": enriched, "findings": found}


def render(payload):
    s, lines = payload["summary"], []
    lines.append("redirectchain %s" % __version__)
    lines.append("source   : %s" % s["source"])
    lines.append("hops     : %d   final: %s" % (s["hops"], s["final_url"][:88]))
    lines.append("risk     : %d/100  grade %s  gate %s" % (s["risk"], s["grade"], s["gate"]))
    lines.append("")
    lines.append("chain")
    lines.append("-" * 100)
    for hop in payload["hops"]:
        status = hop.get("status") if hop.get("status") is not None else "-"
        lines.append("  [%d] %-4s %s" % (hop["n"], status, hop["url"][:90]))
    if payload["findings"]:
        lines.append("")
        lines.append("%-8s %-20s %-6s %s" % ("SEVERITY", "RULE", "HOP", "DETAIL"))
        lines.append("-" * 100)
        for f in payload["findings"]:
            lines.append("%-8s %-20s [%d]    %s"
                         % (f["severity"].upper(), f["code"], f["hop"], f["detail"]))
        lines.append("")
        lines.append("fixes")
        lines.append("-" * 100)
        for f in payload["findings"]:
            if f["severity"] in ("critical", "high", "medium"):
                lines.append("[%s] %s (hop %d)" % (f["severity"][:4].upper(), f["code"], f["hop"]))
                lines.append("      %s" % f["fix"])
    else:
        lines.append("")
        lines.append("no findings: the chain looks clean")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="redirectchain",
        description="Trace and score a URL redirect chain before a user clicks it.")
    parser.add_argument("url", nargs="?", help="starting URL")
    parser.add_argument("--chain", help="analyse an offline chain: JSON list of hops or one URL per line")
    parser.add_argument("--fetch", action="store_true", help="walk the chain live (network)")
    parser.add_argument("--max-hops", type=int, default=10, help="stop after this many hops (default 10)")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-hop timeout in seconds (default 8)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="lowest severity that fails the run (default high)")
    parser.add_argument("--version", action="version", version="redirectchain " + __version__)
    args = parser.parse_args(argv)

    source = args.chain or args.url
    if not source:
        parser.print_usage(sys.stderr)
        sys.stderr.write("redirectchain: give a URL, or --chain FILE\n")
        return 2

    try:
        if args.chain:
            hops = load_chain(args.chain)
        elif args.fetch:
            hops = fetch_chain(args.url, max_hops=args.max_hops, timeout=args.timeout)
        else:
            hops = [{"n": 0, "url": args.url, "status": None, "location": None, "body": ""}]
    except ChainError as exc:
        sys.stderr.write("redirectchain: %s\n" % exc)
        return 2

    payload = build_report(hops, source)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render(payload))

    if args.fail_on == "none":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= limit for f in payload["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
