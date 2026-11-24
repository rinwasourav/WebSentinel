# Passive check catalogue

`websentinel checks list` returns the registered check sets. Current checks are grouped as `passive-baseline` and run against every successfully assessed page.

| Area | Checks | Interpretation |
| --- | --- | --- |
| Browser headers | CSP, frame protection, nosniff, Referrer-Policy, Permissions-Policy | Missing protections can be findings; severity is a baseline and needs application context. |
| Cross-origin policies | CORP, COOP, COEP | Missing policies are informational because applicability and compatibility vary by application. |
| Transport | HSTS presence and short max-age; negotiated obsolete TLS; verified certificate expiry within 30 days | HSTS is evaluated on HTTPS responses. TLS certificate validation is never disabled. |
| Cookies | HttpOnly, Secure on HTTPS, SameSite=None without Secure, `__Host-`/`__Secure-` prefixes, persistence attributes on session-like names | Cookie values are never included in findings. Session naming is heuristic and low confidence. |
| Metadata | Server header presence | Values are not copied into evidence. |

OWASP mapping uses [OWASP Top 10 2021](../mappings/owasp/2021.json). Treat mappings as pointers to review guidance, not evidence of a complete category assessment. Optional headers are informational where their omission alone does not establish a vulnerability.
