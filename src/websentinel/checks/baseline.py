"""Deterministic passive HTTP header, cookie, TLS and metadata checks."""

from __future__ import annotations

import ssl
from http.cookies import CookieError, SimpleCookie
from time import time

from websentinel.http.client import SafeResponse
from websentinel.models import Confidence, Finding, Severity


def inspect_response(response: SafeResponse) -> list[Finding]:
    findings: list[Finding] = []
    headers = response.headers
    rules = [
        (
            "headers.csp",
            "content-security-policy",
            Severity.MEDIUM,
            "Content Security Policy is missing",
            "Add a restrictive Content-Security-Policy tailored to the application.",
            "A CSP can reduce the impact of some injection flaws.",
            "A content security policy was not present.",
        ),
        (
            "headers.frame",
            "x-frame-options",
            Severity.LOW,
            "Clickjacking protection header is missing",
            "Set Content-Security-Policy frame-ancestors; X-Frame-Options supports older clients.",
            "Framing may enable clickjacking when the application has sensitive actions.",
            "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
        ),
        (
            "headers.nosniff",
            "x-content-type-options",
            Severity.LOW,
            "MIME sniffing protection is missing",
            "Set X-Content-Type-Options: nosniff.",
            "MIME sniffing can cause browsers to interpret content as a different type.",
            "X-Content-Type-Options: nosniff was not observed.",
        ),
        (
            "headers.referrer",
            "referrer-policy",
            Severity.LOW,
            "Referrer Policy is missing",
            "Set an appropriate Referrer-Policy, such as strict-origin-when-cross-origin.",
            "Referrer data can disclose URL information to other origins.",
            "A Referrer-Policy header was not observed.",
        ),
        (
            "headers.permissions",
            "permissions-policy",
            Severity.INFO,
            "Permissions Policy is missing",
            "Set a Permissions-Policy that disables browser features the application does not use.",
            "Unused browser features can increase exposure if misused.",
            "A Permissions-Policy header was not observed.",
        ),
    ]
    for check, header, severity, title, remediation, impact, evidence in rules:
        if header not in headers and not (
            check == "headers.frame"
            and "frame-ancestors" in headers.get("content-security-policy", "").lower()
        ):
            findings.append(
                Finding(
                    check,
                    title,
                    title,
                    severity,
                    Confidence.HIGH,
                    evidence,
                    impact,
                    remediation,
                    response.url,
                    ("A05:2021",),
                )
            )
    for header, title, guidance in (
        (
            "cross-origin-resource-policy",
            "Cross-Origin Resource Policy was not observed",
            "Consider an appropriate Cross-Origin-Resource-Policy for resources served here.",
        ),
        (
            "cross-origin-opener-policy",
            "Cross-Origin Opener Policy was not observed",
            "Consider Cross-Origin-Opener-Policy if opener isolation is needed.",
        ),
        (
            "cross-origin-embedder-policy",
            "Cross-Origin Embedder Policy was not observed",
            "Consider Cross-Origin-Embedder-Policy when cross-origin isolation is required.",
        ),
    ):
        if header not in headers:
            findings.append(
                Finding(
                    f"headers.{header}",
                    title,
                    "Optional cross-origin isolation policy was not observed.",
                    Severity.INFO,
                    Confidence.HIGH,
                    f"{header} was not present; applicability depends on the application.",
                    "Cross-origin isolation policies can reduce certain cross-origin data risks.",
                    guidance,
                    response.url,
                )
            )
    if response.url.lower().startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                "headers.hsts",
                "HTTP Strict Transport Security is missing",
                "HTTPS response did not include Strict-Transport-Security.",
                Severity.MEDIUM,
                Confidence.HIGH,
                "Strict-Transport-Security was not present on an HTTPS response.",
                "Clients may be more exposed to protocol downgrade or insecure initial requests.",
                "Configure Strict-Transport-Security with a max-age appropriate to the deployment.",
                response.url,
                ("A05:2021",),
            )
        )
    elif response.url.lower().startswith("https://"):
        try:
            max_age = next(
                int(part.strip().split("=", 1)[1])
                for part in headers["strict-transport-security"].split(";")
                if part.strip().lower().startswith("max-age=")
            )
        except (KeyError, StopIteration, ValueError):
            max_age = None
        if max_age is not None and max_age < 15_552_000:
            findings.append(
                Finding(
                    "headers.hsts_max_age",
                    "HSTS max-age is shorter than six months",
                    "The observed HSTS lifetime is below the commonly recommended "
                    "six-month period.",
                    Severity.LOW,
                    Confidence.HIGH,
                    f"Observed max-age: {max_age} seconds.",
                    "A short lifetime reduces the period in which browsers remember "
                    "HTTPS-only policy.",
                    "Choose a max-age appropriate to operational recovery and security "
                    "requirements.",
                    response.url,
                )
            )
    if "server" in headers:
        findings.append(
            Finding(
                "metadata.server",
                "Server software metadata is disclosed",
                "The response includes a Server header.",
                Severity.INFO,
                Confidence.MEDIUM,
                "Server header is present; its value is redacted from evidence.",
                "Detailed version metadata can help attackers fingerprint software.",
                "Remove or minimize version details in server response headers.",
                response.url,
                ("A05:2021",),
            )
        )
    for raw in response.cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            pass
        for name, morsel in cookie.items():
            safe_name = name[:64]
            base = f"Cookie '{safe_name}'"
            if not morsel["httponly"]:
                findings.append(
                    Finding(
                        "cookies.httponly",
                        f"{base} lacks HttpOnly",
                        "Cookie is readable by client-side scripts.",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        f"{base} is missing HttpOnly; value redacted.",
                        "Script injection can expose cookies that are readable by scripts.",
                        "Set HttpOnly unless client-side access is required.",
                        response.url,
                        ("A07:2021",),
                    )
                )
            if response.url.lower().startswith("https://") and not morsel["secure"]:
                findings.append(
                    Finding(
                        "cookies.secure",
                        f"{base} lacks Secure",
                        "Cookie may be sent over unencrypted HTTP.",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        f"{base} is missing Secure; value redacted.",
                        "The cookie may be exposed if a client sends it over HTTP.",
                        "Set the Secure attribute for cookies used over HTTPS.",
                        response.url,
                        ("A07:2021",),
                    )
                )
            if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                findings.append(
                    Finding(
                        "cookies.samesite_none",
                        f"{base} uses SameSite=None without Secure",
                        "SameSite=None cookies must be protected with Secure in modern browsers.",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        f"{base} has SameSite=None without Secure; value redacted.",
                        "Cross-site cookie use lacks transport protection.",
                        "Add Secure and confirm the cross-site use is needed.",
                        response.url,
                        ("A07:2021",),
                    )
                )
            if name.startswith(("__Host-", "__Secure-")):
                invalid_prefix = not morsel["secure"] or (
                    name.startswith("__Host-") and (morsel["path"] != "/" or bool(morsel["domain"]))
                )
                if invalid_prefix:
                    findings.append(
                        Finding(
                            "cookies.prefix",
                            f"{base} does not satisfy its cookie prefix requirements",
                            "The cookie name uses a security prefix but its attributes do not "
                            "satisfy the browser prefix contract.",
                            Severity.MEDIUM,
                            Confidence.HIGH,
                            f"{base} prefix requirements are not satisfied; value redacted.",
                            "Browsers may ignore the intended prefix protection.",
                            "Set Secure; __Host- cookies also require Path=/ and no Domain "
                            "attribute.",
                            response.url,
                            ("A05:2021",),
                        )
                    )
            if name.lower() in {"session", "sessionid", "sid", "phpsessid"} and (
                morsel["expires"] or morsel["max-age"]
            ):
                findings.append(
                    Finding(
                        "cookies.session_persistence",
                        f"{base} appears to be a persistent session cookie",
                        "A session-like cookie includes an explicit persistence attribute; "
                        "intent cannot be inferred passively.",
                        Severity.INFO,
                        Confidence.LOW,
                        f"{base} has an Expires or Max-Age attribute; value redacted.",
                        "Persistent authentication state can increase exposure if a device is "
                        "shared or lost.",
                        "Confirm that session persistence is intentional and appropriately "
                        "bounded.",
                        response.url,
                    )
                )
    if response.url.lower().startswith("https://") and response.tls:
        not_after = response.tls.get("not_after")
        if not_after:
            try:
                seconds_remaining = ssl.cert_time_to_seconds(not_after) - time()
            except (ValueError, OverflowError):
                seconds_remaining = None
            if seconds_remaining is not None and 0 <= seconds_remaining < 30 * 24 * 60 * 60:
                findings.append(
                    Finding(
                        "tls.certificate_expiry",
                        "TLS certificate expires within 30 days",
                        "The verified peer certificate is nearing its expiry date.",
                        Severity.LOW,
                        Confidence.HIGH,
                        f"Certificate notAfter: {not_after}.",
                        "An expired certificate can interrupt service and browser trust.",
                        "Renew and deploy the certificate before its expiry date.",
                        response.url,
                    )
                )
        if response.tls.get("version") in {"TLSv1", "TLSv1.1", "SSLv3"}:
            findings.append(
                Finding(
                    "tls.protocol",
                    "Obsolete TLS protocol observed",
                    "The negotiated TLS version is obsolete.",
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"Negotiated protocol: {response.tls['version']}.",
                    "Obsolete protocols have known weaknesses.",
                    "Disable obsolete protocols and allow modern TLS versions.",
                    response.url,
                    ("A02:2021",),
                )
            )
    return findings
