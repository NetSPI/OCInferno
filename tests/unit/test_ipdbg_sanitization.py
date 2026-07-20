"""_ipdbg (instance/resource-principal debug tracing) must never behave like a bare
print(): it previously ran unconditionally and unsanitized, so any caller passing
extra_args/cfg containing a delegation token or key material leaked it to stdout on
every credential add, regardless of --debug-http. It must now be gated on
self.debug_http and sanitize its kv payload the same way UtilityTools.dlog does."""
from __future__ import annotations

from ocinferno.core.session import SessionUtility


def _bare_session():
    return SessionUtility.__new__(SessionUtility)


def test_ipdbg_silent_by_default(capsys):
    s = _bare_session()
    s.debug_http = False
    s._ipdbg("start add_instance_profile_token", credname="mycred", extra_args={"delegation_token": "eyJsecret"})
    assert capsys.readouterr().out == ""


def test_ipdbg_prints_when_enabled(capsys):
    s = _bare_session()
    s.debug_http = True
    s._ipdbg("detect tenancy start", imds_version="v2", attempts=3)
    out = capsys.readouterr().out
    assert "detect tenancy start" in out
    assert "imds_version='v2'" in out


def test_ipdbg_redacts_sensitive_values_when_enabled(capsys):
    s = _bare_session()
    s.debug_http = True
    s._ipdbg(
        "start add_instance_profile_token",
        credname="mycred",
        extra_args={"delegation_token": "eyJraWQi.super.secret", "region": "us-phoenix-1"},
    )
    out = capsys.readouterr().out
    assert "eyJraWQi.super.secret" not in out
    assert "<redacted>" in out
    assert "us-phoenix-1" in out


def test_ipdbg_defaults_to_silent_without_debug_http_attr(capsys):
    s = _bare_session()
    s._ipdbg("no debug_http attribute set yet", foo="bar")
    assert capsys.readouterr().out == ""
