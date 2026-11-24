# Assessment limitations

WebSentinel currently performs passive HTTP response checks and optional bounded same-origin page discovery. It does not authenticate, submit forms, execute JavaScript, run active probes, exploit vulnerabilities, enumerate ports, or start ephemeral targets. The extension packages do not imply these capabilities are implemented.

Coverage describes the pages and checks WebSentinel actually observed during a run. It does not establish that unvisited features are secure. Server-side behavior hidden behind login, client-side routes that require JavaScript, inaccessible pages, and non-HTML resources may not be assessed. Header presence is a baseline observation and does not prove a policy is correctly tuned for an application.

TLS certificate validation and hostname verification are enforced by the HTTP stack. The scanner reports the negotiated protocol and warns for a verified certificate nearing expiry; a failed TLS handshake is not bypassed to gather more evidence. It does not provide a full certificate-chain or cipher-suite audit.

Risk scores are severity weight × confidence weight, rounded to one decimal: severity weights are 10/8/5/2/0 for critical/high/medium/low/info and confidence weights are 1.0/0.7/0.4 for high/medium/low. This is a prioritization aid, not a probability of compromise or a compliance result. OWASP labels use the 2021 mapping and remain contextual. Findings require human review.

Scope validation, IP pinning, peer checks, request caps, timeouts, and redaction reduce scanner-side risk. They cannot guarantee that an authorized remote request has no effect on its target. Local container or process isolation also cannot prevent target-server impact.
