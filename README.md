# artais-cookie-cop

> HTTP cookie security auditor. One URL in, one verdict out.

A small CLI that probes a target URL, follows redirects (and an optional login POST), and audits every `Set-Cookie` header it sees against modern best practices — RFC 6265bis, OWASP guidance, and current browser enforcement rules.

Designed to slot in next to [`artais-sht`](https://github.com/Artais-Security/artais-sht) and [`artais-cors-scout`](https://github.com/Artais-Security/artais-cors-scout): same shape, same output style, single Python file, no third-party dependencies.

## Why

Cookies are where session security lives, and the modern rules are subtle:

- `SameSite=None` cookies are silently dropped by browsers if `Secure` is missing.
- `__Host-` prefixed cookies are rejected unless they have `Secure`, `Path=/`, and **no** `Domain`.
- `__Secure-` prefixed cookies are rejected without `Secure`.
- Persistent session cookies massively widen the theft window.
- An overly broad `Domain` attribute leaks the cookie to sibling subdomains.

Real applications get one or more of these wrong all the time. This tool flags them in seconds.

## Install

~~~bash
git clone https://github.com/Artais-Security/artais-cookie-cop.git
cd artais-cookie-cop
chmod +x artais-cookie-cop.py
~~~

Requires Python 3.8+. Stdlib only — no `pip install` needed.

## Usage

~~~bash
# Basic
./artais-cookie-cop.py https://example.com

# Hit a login flow first so we audit the post-auth cookies too
./artais-cookie-cop.py https://app.example.com \
    --post-url https://app.example.com/login \
    --post-data "user=admin&pass=hunter2"

# Add headers (e.g. an existing bearer token)
./artais-cookie-cop.py https://api.example.com -H "Authorization: Bearer xxx"

# Pipe-able machine output
./artais-cookie-cop.py https://example.com --json | jq

# Self-signed cert? Skip TLS verification (use carefully)
./artais-cookie-cop.py https://staging.example.com -k

# Don't follow redirects (audit only the first hop)
./artais-cookie-cop.py https://example.com --no-redirect
~~~

### All flags

| Flag | Description |
| --- | --- |
| `-H`, `--header` | Extra request header. Repeatable. |
| `--post-url` | Send a POST to this URL first (login flow). |
| `--post-data` | Body for the POST. Form-encoded. |
| `--no-redirect` | Don't follow redirects. |
| `--max-redirects` | Cap redirect chain (default 5). |
| `-k`, `--insecure` | Skip TLS verification. |
| `--timeout` | Per-request timeout in seconds (default 15). |
| `--json` | JSON output instead of text. |
| `--no-color` | Disable ANSI color in text output. |

## Checks performed

| # | Check | Severity |
| --- | --- | --- |
| 1 | `Secure` flag missing on HTTPS | HIGH if session-like, else MEDIUM |
| 2 | `HttpOnly` flag missing | HIGH if session-like, else LOW |
| 3 | `SameSite` attribute not set explicitly | LOW |
| 4 | `SameSite=None` without `Secure` (browsers reject this) | HIGH |
| 5 | `__Host-` prefix without `Secure`, `Path=/`, or with `Domain` | HIGH |
| 6 | `__Secure-` prefix without `Secure` | HIGH |
| 7 | Session-like cookie with `Expires` / `Max-Age` set | LOW |
| 8 | `Domain` scope wider than the host that set it | LOW |

"Session-like" is matched against a list of common session/auth/CSRF cookie names: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `laravel_session`, `jwt`, `access_token`, `csrf_token`, etc. Tune the list in `SESSION_COOKIE_PATTERNS` at the top of the script.

## Output

### Text (default)

~~~
artais-cookie-cop v0.1.0
Visited 2 URL(s):
  [302] https://example.com/  (1 Set-Cookie)
  [200] https://example.com/home  (2 Set-Cookie)

sessionid [session-like]
  no Secure | no HttpOnly | SameSite=unset | Path=/ | Session
  set by: https://example.com/home
  [HIGH] Missing Secure flag
        Cookie set over HTTPS without the Secure attribute. ...
        Fix: Add the `Secure` attribute to the Set-Cookie header.
  [HIGH] Missing HttpOnly flag
        ...
  [LOW] No explicit SameSite attribute
        ...

Summary
  Cookies analysed : 3
  HIGH   : 2
  MEDIUM : 0
  LOW    : 1
~~~

### JSON

~~~bash
./artais-cookie-cop.py https://example.com --json
~~~

~~~json
{
  "tool": "artais-cookie-cop",
  "version": "0.1.0",
  "visits": [],
  "cookies": [
    {
      "name": "sessionid",
      "set_by": "https://example.com/home",
      "secure": false,
      "httponly": false,
      "samesite": null,
      "domain": null,
      "path": "/",
      "persistent": false,
      "looks_session": true,
      "findings": [
        {
          "severity": "HIGH",
          "cookie": "sessionid",
          "issue": "Missing Secure flag",
          "detail": "...",
          "fix": "..."
        }
      ]
    }
  ]
}
~~~

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No HIGH or MEDIUM findings |
| `1` | HIGH or MEDIUM findings present |
| `2` | Request failed |

Suitable for CI gating:

~~~yaml
- name: Cookie audit
  run: ./artais-cookie-cop.py https://staging.example.com
~~~

## Limitations

- Doesn't execute JavaScript, so cookies set by client-side `document.cookie` won't be seen.
- The session-cookie name list is heuristic. Apps with unusual cookie names may need a tweak to `SESSION_COOKIE_PATTERNS`.
- The `Domain` scope check uses suffix matching, not the Public Suffix List, so `Domain=co.uk`-style edge cases aren't specially flagged.
- One URL per invocation. Wrap in a shell loop for bulk scans.

## License

MIT.

## Related Artais tools

- [`artais-sht`](https://github.com/Artais-Security/artais-sht) — security headers tester
- [`artais-cors-scout`](https://github.com/Artais-Security/artais-cors-scout) — CORS misconfiguration probes
- [`artais-csp-builder-evaluator`](https://github.com/Artais-Security/artais-csp-builder-evaluator) — CSP authoring + evaluation
