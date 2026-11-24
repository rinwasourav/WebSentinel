import httpx

from websentinel.cli import main


def test_cli_requires_command() -> None:
    try:
        main([])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("expected argparse to require a command")


def test_unauthorized_cli_stops_before_network(capsys: object) -> None:
    code = main(["assess", "--target", "https://example.test", "--scope", "example.test"])
    assert code == 2


def test_http_timeout_is_reported_as_clean_failure(monkeypatch: object, tmp_path: object) -> None:
    from websentinel import cli

    monkeypatch.setattr(cli, "validate_url", lambda target, policy: target)

    def timeout(self: object, url: str) -> object:
        raise httpx.ReadTimeout("request timed out")

    monkeypatch.setattr(cli.PolicyHTTPClient, "get", timeout)
    code = main(
        [
            "assess",
            "--target",
            "https://example.test",
            "--scope",
            "example.test",
            "--authorized",
            "--output",
            str(tmp_path / "reports"),
            "--database",
            str(tmp_path / "history.sqlite3"),
        ]
    )
    assert code == 2
