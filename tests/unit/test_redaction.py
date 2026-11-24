from websentinel.findings.normalize import redact, redact_tree


def test_redacts_sensitive_fields() -> None:
    assert "topsecret" not in redact("Authorization: Bearer topsecret")
    assert "abc" not in redact("https://example.test/?token=abc")


def test_redacts_sensitive_metadata_keys() -> None:
    assert redact_tree({"access_token": "topsecret", "safe": "visible"}) == {
        "access_token": "[REDACTED]",
        "safe": "visible",
    }
