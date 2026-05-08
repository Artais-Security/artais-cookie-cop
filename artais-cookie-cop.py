#!/usr/bin/env python3
"""
artais-cookie-cop - HTTP Cookie Security Auditor
=================================================

Probes a URL, follows redirects, and audits every Set-Cookie header it
observes against modern best practices (RFC 6265bis + OWASP guidance).

Designed to slot in next to artais-sht and artais-cors-scout: one shot,
one URL, one report.

Checks performed per cookie:
    - Secure flag (required on HTTPS)
    - HttpOnly flag (required for session/auth cookies)
    - SameSite attribute (missing -> warn, =None without Secure -> error)
    - __Host- prefix rules (Secure + Path=/ + no Domain)
    - __Secure- prefix rules (Secure)
    - Session-like cookies marked as persistent (Expires / Max-Age set)
    - Overly broad Domain attribute relative to the host that set it

Usage:
    artais-cookie-cop.py <url> [options]

Examples:
    artais-cookie-cop.py https://example.com
    artais-cookie-cop.py https://example.com --json
    artais-cookie-cop.py https://example.com -H "Authorization: Bearer xxx"
    artais-cookie-cop.py https://app.example.com \
        --post-url https://app.example.com/login \
        --post-data "user=admin&pass=hunter2"

Exit codes:
    0  no HIGH/MEDIUM findings
    1  HIGH or MEDIUM findings present
    2  request failed

No third-party dependencies. Python 3.8+.

License: MIT
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import ssl
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# Cookie names that look like a session, auth, or CSRF token. These should
# carry the full hardening set: Secure + HttpOnly + an explicit SameSite.
SESSION_COOKIE_PATTERNS = [
    r"^PHPSESSID$",
    r"^JSESSIONID$",
    r"^ASP\.NET_SessionId$",
    r"^ASPSESSIONID[A-Z]+$",
    r"^CFID$",
    r"^CFTOKEN$",
    r"^connect\.sid$",
    r"^laravel_session$",
    r"^_session$",
    r"^session$",
    r"^sessionid$",
    r"^sid$",
    r"^csrf[_-]?token$",
    r"^xsrf[_-]?token$",
    r"^auth$",
    r"^auth[_-].*$",
    r"^token$",
    r"^access[_-]?token$",
    r"^refresh[_-]?token$",
    r"^id[_-]?token$",
    r"^jwt$",
    r"^remember[_-]?me$",
    r"^remember[_-]?token$",
]
SESSION_COOKIE_RE = re.compile("|".join(SESSION_COOKIE_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class Cookie:
    name: str
    value: str
    attributes: Dict[str, str] = field(default_factory=dict)  # keys lowercased
    raw: str = ""
    set_by: str = ""  # which URL emitted this Set-Cookie

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> Optional[str]:
        v = self.attributes.get("samesite")
        return v.lower() if v else None

    @property
    def domain(self) -> Optional[str]:
        return self.attributes.get("domain") or None

    @property
    def path(self) -> Optional[str]:
        return self.attributes.get("path") or None

    @property
    def is_persistent(self) -> bool:
        return "expires" in self.attributes or "max-age" in self.attributes

    @property
    def looks_session(self) -> bool:
        return bool(SESSION_COOKIE_RE.match(self.name))


@dataclass
class Finding:
    severity: str  # HIGH, MEDIUM, LOW, INFO
    cookie: str
    issue: str
    detail: str
    fix: str


# ---------------------------------------------------------------------------
# Set-Cookie parsing
# ---------------------------------------------------------------------------

def parse_set_cookie(raw: str) -> Optional[Cookie]:
    """Parse a single Set-Cookie header value into a Cookie object.

    Note: this expects ONE Set-Cookie value, not multiple comma-joined. We get
    them individually from HTTPResponse.headers.get_all().
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None

    name, value = parts[0].split("=", 1)
    name, value = name.strip(), value.strip()
    if not name:
        return None

    attrs: Dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.strip().lower()] = ""

    return Cookie(name=name, value=value, attributes=attrs, raw=raw)


# ---------------------------------------------------------------------------
# HTTP fetching (manual redirect handling so we capture cookies at every hop)
# ---------------------------------------------------------------------------

def fetch_chain(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    follow_redirects: bool = True,
    insecure: bool = False,
    max_redirects: int = 5,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Fetch a URL, following redirects manually, and return per-hop info."""
    headers = dict(headers or {})
    headers.setdefault("User-Agent", f"artais-cookie-cop/{VERSION}")
    headers.setdefault("Accept", "*/*")

    visits: List[Dict[str, Any]] = []
    current_url = url
    current_method = method
    current_data = data

    for _ in range(max_redirects + 1):
        parsed = urllib.parse.urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise ValueError(f"URL missing hostname: {current_url!r}")

        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                parsed.hostname, parsed.port or 443,
                timeout=timeout, context=ctx,
            )
        else:
            conn = http.client.HTTPConnection(
                parsed.hostname, parsed.port or 80, timeout=timeout,
            )

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        body: Optional[bytes] = None
        req_headers = dict(headers)
        req_headers.setdefault("Host", parsed.hostname)
        if current_data is not None and current_method in ("POST", "PUT", "PATCH"):
            body = current_data.encode() if isinstance(current_data, str) else current_data
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            req_headers["Content-Length"] = str(len(body))

        try:
            conn.request(current_method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
        except (socket.error, ssl.SSLError, OSError) as e:
            raise RuntimeError(f"Connection error to {current_url}: {e}") from e

        try:
            set_cookies = resp.headers.get_all("Set-Cookie") or []
        except AttributeError:
            set_cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]

        location = resp.headers.get("Location")
        status = resp.status

        try:
            resp.read()
        except Exception:
            pass
        conn.close()

        visits.append({
            "url": current_url,
            "status": status,
            "set_cookies": list(set_cookies),
        })

        if not follow_redirects or status not in (301, 302, 303, 307, 308) or not location:
            break

        current_url = urllib.parse.urljoin(current_url, location)
        # 301/302/303 demote to GET in browser behavior; 307/308 preserve method.
        if status in (301, 302, 303):
            current_method = "GET"
            current_data = None

    return visits


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------

def is_https(url: str) -> bool:
    return urllib.parse.urlparse(url).scheme == "https"


def audit_cookie(cookie: Cookie, source_url: str) -> List[Finding]:
    findings: List[Finding] = []
    name = cookie.name
    target_is_https = is_https(source_url)
    is_session_like = cookie.looks_session

    # 1. Secure flag
    if target_is_https and not cookie.secure:
        findings.append(Finding(
            severity="HIGH" if is_session_like else "MEDIUM",
            cookie=name,
            issue="Missing Secure flag",
            detail=("Cookie set over HTTPS without the Secure attribute. "
                    "It can leak over plaintext HTTP if the user is ever downgraded."),
            fix="Add the `Secure` attribute to the Set-Cookie header.",
        ))

    # 2. HttpOnly flag
    if not cookie.httponly:
        findings.append(Finding(
            severity="HIGH" if is_session_like else "LOW",
            cookie=name,
            issue="Missing HttpOnly flag",
            detail=("Cookie is readable from client-side JavaScript. "
                    "Session/auth cookies should be inaccessible to scripts to limit XSS impact."),
            fix="Add the `HttpOnly` attribute.",
        ))

    # 3. SameSite
    if cookie.samesite is None:
        findings.append(Finding(
            severity="LOW",
            cookie=name,
            issue="No explicit SameSite attribute",
            detail=("Browsers default to SameSite=Lax, but this varies by vendor and version. "
                    "Set it explicitly so CSRF posture is deterministic across user agents."),
            fix="Add `SameSite=Lax` (or `Strict` for high-sensitivity flows).",
        ))
    elif cookie.samesite == "none" and not cookie.secure:
        findings.append(Finding(
            severity="HIGH",
            cookie=name,
            issue="SameSite=None without Secure",
            detail=("Modern browsers reject SameSite=None cookies that lack the Secure attribute. "
                    "The cookie may be silently dropped, breaking the application or "
                    "leaving an insecure fallback in place."),
            fix="Add the `Secure` attribute, or change SameSite to `Lax`/`Strict`.",
        ))

    # 4. __Host- prefix rules (case-sensitive per spec)
    if name.startswith("__Host-"):
        if not cookie.secure:
            findings.append(Finding(
                "HIGH", name,
                "__Host- prefix without Secure",
                "Cookies prefixed with __Host- must include Secure or browsers will reject them.",
                "Add `Secure`.",
            ))
        if cookie.path != "/":
            findings.append(Finding(
                "HIGH", name,
                "__Host- prefix with non-root path",
                f"__Host- prefixed cookies require Path=/, got Path={cookie.path!r}.",
                "Set `Path=/`.",
            ))
        if cookie.domain:
            findings.append(Finding(
                "HIGH", name,
                "__Host- prefix with Domain attribute",
                "__Host- prefixed cookies must NOT specify a Domain attribute.",
                "Remove the `Domain` attribute.",
            ))

    # 5. __Secure- prefix rules
    if name.startswith("__Secure-") and not cookie.secure:
        findings.append(Finding(
            "HIGH", name,
            "__Secure- prefix without Secure",
            "Cookies prefixed with __Secure- must include Secure or browsers will reject them.",
            "Add `Secure`.",
        ))

    # 6. Session-like cookie that survives browser restart
    if is_session_like and cookie.is_persistent:
        findings.append(Finding(
            "LOW", name,
            "Session-like cookie is persistent",
            "Cookie name suggests a session/auth role but Expires/Max-Age is set, "
            "so it survives browser restarts and increases the theft window.",
            "Drop Expires/Max-Age so it becomes a session cookie, "
            "or shorten the lifetime substantially.",
        ))

    # 7. Domain wider than the host that set it
    if cookie.domain:
        host = (urllib.parse.urlparse(source_url).hostname or "").lower()
        d = cookie.domain.lstrip(".").lower()
        if host and d and d != host and host.endswith("." + d):
            findings.append(Finding(
                "LOW", name,
                "Domain scope wider than host",
                f"Cookie scoped to `{cookie.domain}` but was set on `{host}`. "
                "All sibling subdomains will receive this cookie.",
                "Scope cookies to the host that needs them when feasible.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

class Color:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: Any) -> str:
        s = str(text)
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def red(self, t):    return self._wrap("31", t)
    def yellow(self, t): return self._wrap("33", t)
    def cyan(self, t):   return self._wrap("36", t)
    def green(self, t):  return self._wrap("32", t)
    def dim(self, t):    return self._wrap("2",  t)
    def bold(self, t):   return self._wrap("1",  t)


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def print_text_report(
    visits: List[Dict[str, Any]],
    results: List[Tuple[Cookie, List[Finding]]],
    c: Color,
) -> None:
    print(c.bold(f"artais-cookie-cop v{VERSION}"))
    print(c.dim(f"Visited {len(visits)} URL(s):"))
    for v in visits:
        print(c.dim(f"  [{v['status']}] {v['url']}  ({len(v['set_cookies'])} Set-Cookie)"))
    print()

    if not results:
        print(c.green("No cookies observed."))
        return

    for cookie, findings in results:
        title = cookie.name
        if cookie.looks_session:
            title += " " + c.cyan("[session-like]")
        print(c.bold(title))

        attrs: List[str] = []
        attrs.append("Secure" if cookie.secure else c.red("no Secure"))
        attrs.append("HttpOnly" if cookie.httponly else c.red("no HttpOnly"))
        attrs.append(f"SameSite={cookie.samesite or c.red('unset')}")
        if cookie.domain:
            attrs.append(f"Domain={cookie.domain}")
        if cookie.path:
            attrs.append(f"Path={cookie.path}")
        attrs.append("Persistent" if cookie.is_persistent else "Session")
        print("  " + c.dim(" | ".join(attrs)))
        print("  " + c.dim(f"set by: {cookie.set_by}"))

        if not findings:
            print("  " + c.green("OK"))
        else:
            findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
            for f in findings:
                if f.severity == "HIGH":
                    sev = c.red(f"[{f.severity}]")
                elif f.severity == "MEDIUM":
                    sev = c.yellow(f"[{f.severity}]")
                else:
                    sev = c.cyan(f"[{f.severity}]")
                print(f"  {sev} {f.issue}")
                print(f"        {c.dim(f.detail)}")
                print(f"        {c.dim('Fix: ' + f.fix)}")
        print()

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for _, findings in results:
        for f in findings:
            counts[f.severity] += 1
    print(c.bold("Summary"))
    print(f"  Cookies analysed : {len(results)}")
    high = c.red(counts["HIGH"]) if counts["HIGH"] else "0"
    med  = c.yellow(counts["MEDIUM"]) if counts["MEDIUM"] else "0"
    print(f"  HIGH   : {high}")
    print(f"  MEDIUM : {med}")
    print(f"  LOW    : {counts['LOW']}")


def print_json_report(
    visits: List[Dict[str, Any]],
    results: List[Tuple[Cookie, List[Finding]]],
) -> None:
    out = {
        "tool": "artais-cookie-cop",
        "version": VERSION,
        "visits": visits,
        "cookies": [
            {
                "name": cookie.name,
                "set_by": cookie.set_by,
                "attributes": cookie.attributes,
                "secure": cookie.secure,
                "httponly": cookie.httponly,
                "samesite": cookie.samesite,
                "domain": cookie.domain,
                "path": cookie.path,
                "persistent": cookie.is_persistent,
                "looks_session": cookie.looks_session,
                "findings": [asdict(f) for f in findings],
            }
            for cookie, findings in results
        ],
    }
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_header_args(header_args: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for h in header_args:
        if ":" not in h:
            print(f"Ignoring malformed header: {h!r} (use 'Name: value')", file=sys.stderr)
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def main() -> None:
    p = argparse.ArgumentParser(
        prog="artais-cookie-cop",
        description="Audit a URL's Set-Cookie headers for security best practices.",
    )
    p.add_argument("url", help="Target URL (http:// or https://)")
    p.add_argument(
        "-H", "--header", action="append", default=[],
        help="Extra request header. Repeatable. e.g. -H 'Authorization: Bearer xxx'",
    )
    p.add_argument("--post-url", help="If set, POST here first (e.g. for a login flow).")
    p.add_argument("--post-data", default="", help="Body for the POST. Form-encoded by default.")
    p.add_argument("--no-redirect", action="store_true", help="Don't follow redirects.")
    p.add_argument("--max-redirects", type=int, default=5)
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification.")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"artais-cookie-cop {VERSION}")
    args = p.parse_args()

    headers = parse_header_args(args.header)

    visits: List[Dict[str, Any]] = []
    try:
        if args.post_url:
            visits += fetch_chain(
                args.post_url, method="POST", headers=headers, data=args.post_data,
                follow_redirects=not args.no_redirect, insecure=args.insecure,
                max_redirects=args.max_redirects, timeout=args.timeout,
            )
        visits += fetch_chain(
            args.url, method="GET", headers=headers,
            follow_redirects=not args.no_redirect, insecure=args.insecure,
            max_redirects=args.max_redirects, timeout=args.timeout,
        )
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(2)

    results: List[Tuple[Cookie, List[Finding]]] = []
    for v in visits:
        for raw in v["set_cookies"]:
            cookie = parse_set_cookie(raw)
            if cookie is None:
                continue
            cookie.set_by = v["url"]
            findings = audit_cookie(cookie, v["url"])
            results.append((cookie, findings))

    color_enabled = (not args.no_color) and sys.stdout.isatty() and not args.json
    c = Color(color_enabled)

    if args.json:
        print_json_report(visits, results)
    else:
        print_text_report(visits, results, c)

    has_high_or_med = any(
        f.severity in ("HIGH", "MEDIUM") for _, fs in results for f in fs
    )
    sys.exit(1 if has_high_or_med else 0)


if __name__ == "__main__":
    main()
