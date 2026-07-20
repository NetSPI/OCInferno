"""Credential loading + OCI signer building, extracted from the SessionUtility god-object.

A mixin (SessionUtility inherits it); method bodies and `self.*` access are unchanged, so
behaviour is identical -- this only relocates the ~1400-LOC auth cluster out of session.py.
Covers all five auth types: API key, config profile, session token, instance principal,
resource principal. `CredRecord` (the stored-cred row shape) moves here with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import oci
import requests
from cryptography.hazmat.primitives import serialization

try:
    from oci.config import from_file, validate_config
except Exception:  # pragma: no cover - allows lightweight test stubs to import this module
    def from_file(**_kwargs):
        return {}

    def validate_config(_cfg):
        return True

try:
    from oci.exceptions import ConfigFileNotFound, InvalidKeyFilePath, ProfileNotFound
except Exception:  # pragma: no cover
    class ConfigFileNotFound(Exception):
        pass

    class InvalidKeyFilePath(Exception):
        pass

    class ProfileNotFound(Exception):
        pass

try:
    from oci.auth.certificate_retriever import PEMStringCertificateRetriever
    from oci.auth.federation_client import X509FederationClient
    from oci.auth.session_key_supplier import SessionKeySupplier
    from oci.auth.signers import SecurityTokenSigner, X509FederationClientBasedSecurityTokenSigner
except Exception:  # pragma: no cover
    PEMStringCertificateRetriever = None
    X509FederationClient = None
    SessionKeySupplier = None
    SecurityTokenSigner = None
    X509FederationClientBasedSecurityTokenSigner = None

from ocinferno.core.coerce import _safe_str, _truthy
from ocinferno.core.console import UtilityTools
from ocinferno.core.contracts import AuthError, ErrorCode


def _jwt_exp(token: str) -> int:
    """Decode a JWT's ``exp`` claim (payload is the base64url middle segment). 0 on failure."""
    parts = token.split(".")
    if len(parts) < 2:
        return 0
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
    except Exception:
        return 0
    try:
        return int(payload.get("exp") or 0)
    except Exception:
        return 0


def _build_instance_delegation_signer(federation_client, delegation_token: str):
    """Wrap the off-box X509 federation signer to also send an OBO delegation token.

    Replicates the SDK's ``InstancePrincipalsDelegationTokenSigner`` (which is itself a
    thin subclass of the X509 federation signer): it adds ``opc-obo-token`` to the SIGNED
    generic-headers set and stamps the token on every request. We layer the same two
    additions onto the federation signer OCInferno already reconstructs off-instance from
    user-supplied leaf/intermediate/key material, so delegation works without being on the
    Cloud Shell/instance box. Signing (X509 federation) is otherwise identical.
    """
    base = X509FederationClientBasedSecurityTokenSigner

    class _InstanceDelegationTokenSigner(base):  # type: ignore[misc, valid-type]
        def __init__(self, fed, token):
            self._obo_token = token
            super().__init__(fed, generic_headers=["date", "(request-target)", "host", "opc-obo-token"])

        def do_request_sign(self, request, enforce_content_headers=True):
            request.headers["opc-obo-token"] = self._obo_token
            return super().do_request_sign(request, enforce_content_headers)

    return _InstanceDelegationTokenSigner(federation_client, delegation_token)


@dataclass
class CredRecord:
    credname: str
    credtype: str
    session_creds: str


class AuthMixin:
    def _maybe_refresh_session_token(
        self,
        rec: CredRecord,
        *,
        skew_seconds: int = 600,          # refresh if expiring within 10 minutes
        min_interval_seconds: int = 60,   # don't refresh more than once per minute per session
        debug: bool = False,
    ) -> Optional[bool]:
        """
        If this credential contains a session token, check JWT exp and refresh if needed.

        Refresh is a signed POST to the auth service's own refresh endpoint (the same call
        ``oci session refresh`` makes internally) using the profile's own key -- no external
        CLI process involved.

        Returns:
        None  -> nothing to do (not a token cred, undecodable exp, rate-limited, or still
                 valid well beyond ``skew_seconds``)
        True  -> refresh was attempted and succeeded; rec.session_creds updated in-memory
        False -> refresh was attempted (token within ``skew_seconds`` of expiry) but failed
                 -- caller should check whether the CURRENT token is now actually past its
                 own exp (see ``ensure_fresh_creds``) to decide whether this is fatal

        Requires stored metadata:
        - key_content (required) -- the profile's own private key, already on file
        - region (required)
        """
        # Parse stored JSON
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception:
            return None

        token = (stored.get("security_token_content") or "").strip()
        if not token:
            return None  # not a session-token cred

        exp = _jwt_exp(token)
        if exp <= 0:
            # Can't decode exp safely; don't auto-refresh (avoid loops)
            if debug:
                print(f"[!] Session token for '{rec.credname}' has no decodable exp; skip refresh.")
            return None
        now = int(time.time())

        # Rate-limit refresh attempts per session instance
        last_ts = int(getattr(self, "_last_session_token_refresh_ts", 0) or 0)
        if last_ts and (now - last_ts) < min_interval_seconds:
            return None

        seconds_left = exp - now
        if seconds_left > skew_seconds:
            return None  # still valid enough

        region = (stored.get("region") or "").strip()
        key_content = (stored.get("key_content") or "").strip()

        if not region or not key_content:
            print(f"[!] Session token for '{rec.credname}' expiring in {seconds_left}s but missing region/key_content; can't refresh.")
            return False

        try:
            pass_phrase = stored.get("pass_phrase")
            pass_phrase_b = pass_phrase.encode("utf-8") if isinstance(pass_phrase, str) else None
            private_key_obj = serialization.load_pem_private_key(key_content.encode("utf-8"), password=pass_phrase_b)
            signer = SecurityTokenSigner(token, private_key_obj)
        except Exception as e:
            print(f"[!] Could not build signer to refresh session token for '{rec.credname}': {e}")
            return False

        refresh_url = f"{oci.regions.endpoint_for('auth', region)}/v1/authentication/refresh"
        print(f"[*] Session token for '{rec.credname}' expires in {seconds_left}s -> refreshing via POST {refresh_url}")

        effective_proxy = self._resolve_proxy(include_auth_proxy=True)
        proxies = {"http": effective_proxy, "https": effective_proxy} if effective_proxy else None

        try:
            resp = requests.post(
                refresh_url,
                headers={"content-type": "application/json"},
                data=json.dumps({"currentToken": token}),
                auth=signer,
                proxies=proxies,
                timeout=30,
            )
        except Exception as e:
            print(f"[!] Session token refresh request to {refresh_url} failed: {e}")
            return False

        if resp.status_code == 401:
            print(f"[!] Session for '{rec.credname}' was rejected by {refresh_url} (401) and cannot be refreshed; re-authenticate with 'oci session authenticate'.")
            return False
        if resp.status_code != 200:
            print(f"[!] OCI session refresh failed (status={resp.status_code}): {resp.text[:400]}")
            if debug:
                print(f"    URL: {refresh_url}")
            return False

        try:
            new_token = str((resp.json() or {}).get("token") or "").strip()
        except Exception as e:
            print(f"[!] Session refresh returned 200 but response could not be parsed: {e}")
            return False
        if not new_token:
            print("[!] Session refresh returned 200 but no token in response.")
            return False

        # Update stored JSON and persist back to DB
        stored["security_token_content"] = new_token
        token_file = (stored.get("security_token_file") or "").strip()
        if token_file:
            try:
                Path(token_file).expanduser().write_text(new_token, encoding="utf-8")
            except Exception:
                pass  # best-effort mirror to disk; the DB copy is authoritative either way

        self.data_master.save_value_to_table_column(
            db="metadata",
            table_name="sessions",
            target_column="session_creds",
            value=json.dumps(stored),
            where={"workspace_id": self.workspace_id, "credname": rec.credname},
        )

        # Update in-memory record so caller uses the fresh token immediately
        rec.session_creds = json.dumps(stored)

        # Update rate-limit timestamp
        self._last_session_token_refresh_ts = now

        new_exp = _jwt_exp(new_token)
        if new_exp:
            print(f"[*] Refreshed session token for '{rec.credname}': new expiry in {new_exp - now}s.")
        else:
            print(f"[*] Refreshed session token for '{rec.credname}' (new expiry could not be decoded).")

        return True

    def ensure_fresh_creds(self, *, skew_seconds: int = 600) -> bool:
        """Call before dispatching a module: if the active credential is a session
        token within ``skew_seconds`` of expiring, refresh it and rebuild the active
        signer in place so subsequent API calls use the new token immediately.

        A cheap no-op the vast majority of calls -- ``_maybe_refresh_session_token``
        is internally rate-limited (at most once per minute) and returns instantly
        for non-session-token credentials or a token that still has plenty of time
        left. Safe to call before every module dispatch in a long enum_all sweep.

        If a refresh is attempted and fails, the outcome depends on whether the
        CURRENT token is still technically valid: still valid -> a warning is
        printed and the run continues on the current token (it may still work for
        a while); already past its own exp -> raises ``AuthError`` so the caller
        can stop cleanly instead of grinding through doomed API calls one module
        at a time.
        """
        credname = getattr(self, "credname", None)
        if not credname:
            return False
        rec = self._fetch_cred_record(credname)
        if not rec:
            return False

        result = self._maybe_refresh_session_token(rec, skew_seconds=skew_seconds, debug=self.individual_run_debug)
        if result is True:
            self.load_stored_creds(credname)  # rebuild self.credentials from the new token
            return True
        if result is None:
            return False

        # result is False: refresh was attempted and failed. Check whether the
        # CURRENT (unrefreshed) token is now actually past its own expiry.
        try:
            stored = json.loads(rec.session_creds or "{}")
            token = (stored.get("security_token_content") or "").strip()
            exp = _jwt_exp(token) if token else 0
        except Exception:
            exp = 0
        now = int(time.time())

        if exp > 0 and exp <= now:
            raise AuthError(
                code=ErrorCode.AUTH_REQUIRED,
                message=(
                    f"Session token for '{credname}' has expired and could not be refreshed. "
                    "Re-authenticate with 'oci session authenticate' and re-add the credential."
                ),
                details={"credname": credname},
            )

        print(f"{UtilityTools.YELLOW}[!] Could not proactively refresh session token for '{credname}'; "
              f"continuing on the current token, which may still be valid for a short while.{UtilityTools.RESET}")
        return False

    def load_stored_creds(self, credname: str, *, force_refresh: bool = False) -> Optional[int]:
        print(f"[*] Loading creds: {credname}")
        rec = self._fetch_cred_record(credname)
        if not rec:
            print(f"[X] Unknown credname: {credname}")
            return None

        # NEW: refresh session tokens on load
        if not force_refresh:
            self._maybe_refresh_session_token(rec, skew_seconds=600, debug=self.individual_run_debug)
        else:
            self._maybe_refresh_session_token(rec, skew_seconds=10**9, debug=True)  # effectively "always refresh"

        if "Profile" in rec.credtype:
            return self._load_profile_from_record(rec)
        if rec.credtype == "session-token":
            try:
                stored = json.loads(rec.session_creds or "{}")
            except Exception as e:
                print(f"[X] Bad stored JSON for {rec.credname}: {e}")
                return -1
            if force_refresh and _safe_str(stored.get("security_token_file")).strip():
                refreshed, err = self._read_text_file(stored["security_token_file"], "session token")
                if err:
                    print(f"[X] {err}")
                    return -1
                stored["security_token_content"] = _safe_str(refreshed).strip()
                rec = CredRecord(credname=rec.credname, credtype=rec.credtype, session_creds=json.dumps(stored))
            profile_rec = CredRecord(
                credname=rec.credname,
                credtype="Profile - Session - INLINE",
                session_creds=rec.session_creds,
            )
            return self._load_profile_from_record(profile_rec)
        if rec.credtype == "api-key":
            profile_rec = CredRecord(
                credname=rec.credname,
                credtype="Profile - API Key - INLINE",
                session_creds=rec.session_creds,
            )
            return self._load_profile_from_record(profile_rec)
        if rec.credtype == "instance-principal":
            return self._load_instance_profile_from_record(rec, force_refresh=force_refresh)
        if rec.credtype == "resource-principal":
            return self._load_resource_profile_from_record(rec, force_refresh=force_refresh)

        print(f"[X] Unsupported credtype: {rec.credtype}")
        return None

    def add_profile_name(self, credname: str, extra_args: dict, assume: bool = False):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        profile_name = extra_args.get("profile_name")
        filepath = extra_args.get("filepath")

        try:
            kwargs = {}

            if profile_name:
                kwargs["profile_name"] = profile_name
            if filepath:
                kwargs["file_location"] = filepath

            config = from_file(**kwargs)

        except (ConfigFileNotFound, InvalidKeyFilePath, ProfileNotFound) as e:
            print(f"[X] Failed loading OCI profile: {e}")
            return None

        # Detect whether this profile is API-key or session-token style
        security_token_file = config.get("security_token_file")
        key_file = config.get("key_file")

        # Inline file reader (no separate function on the class)
        _read = lambda p, label: (
            ""
            if not p
            else Path(p).expanduser().read_text(encoding="utf-8").strip()
        )

        try:
            key_content = (config.get("key_content") or "").strip() or _read(key_file, "key")
        except Exception as e:
            print(f"[X] Could not read key_file '{key_file}': {e}")
            return None

        if not key_content:
            print("[X] Missing key_file/key_content in config")
            return None

        try:
            security_token_content = (config.get("security_token_content") or "").strip() or _read(
                security_token_file, "security_token"
            )
        except Exception as e:
            print(f"[X] Could not read security_token_file '{security_token_file}': {e}")
            return None

        serialized = {
            "user": config.get("user"),
            "fingerprint": config.get("fingerprint"),
            "tenancy": config.get("tenancy"),
            "region": config.get("region"),
            "key_content": key_content,
        }

        if profile_name:
            serialized["profile_name"] = profile_name
        if filepath:
            serialized["file_location"] = filepath
        if security_token_file:
            serialized["security_token_file"] = str(security_token_file)

        if security_token_content:
            serialized.update(
                {
                    "security_token_content": security_token_content,
                    "security_token_file": str(security_token_file or ""),
                }
            )

        profile_type = f"Profile - Session - {profile_name}" if security_token_content else f"Profile - API Key - {profile_name}"

        self.data_master.insert_creds(self.workspace_id, credname, profile_type, json.dumps(serialized))
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")

        if assume:
            self.load_stored_creds(credname)

        tenancy_ocid = serialized.get("tenancy")
        if tenancy_ocid:
            self.add_compartment_id(tenancy_ocid, parent_compartment_id="N/A", override=False)

        return 1

    def _load_profile_from_record(self, rec: CredRecord) -> int:
        cred = rec.credname

        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        tenancy = (stored.get("tenancy") or "").strip()
        region = (stored.get("region") or "").strip()
        key_content = (stored.get("key_content") or "").strip()
        token = (stored.get("security_token_content") or "").strip()

        user = (stored.get("user") or "").strip()
        fingerprint = (stored.get("fingerprint") or "").strip()

        if not tenancy or not region:
            print(f"[X] Profile '{cred}' missing tenancy/region in DB")
            return -1
        if not key_content:
            print(f"[X] Profile '{cred}' missing key_content in DB")
            return -1

        # ---- Session-token profile ----
        if token:
            try:
                pass_phrase = stored.get("pass_phrase")
                if isinstance(pass_phrase, str):
                    pass_phrase_b = pass_phrase.encode("utf-8")
                else:
                    pass_phrase_b = None

                private_key_obj = serialization.load_pem_private_key(
                    key_content.encode("utf-8"),
                    password=pass_phrase_b,
                )
                signer = SecurityTokenSigner(token, private_key_obj)
            except Exception as e:
                print(f"[X] Could not build session-token signer for '{cred}': {e}")
                return -1

            cfg = {
                "tenancy": tenancy,
                "region": region,
            }

            self.credentials = {"config": cfg, "signer": signer}
            self.credentials_type = "Profile Session"

        # ---- API-key profile ----
        else:
            if not user or not fingerprint:
                print(f"[X] API-key profile '{cred}' missing user/fingerprint in DB")
                return -1

            cfg = {
                "user": user,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region,
                "key_content": key_content,   # <-- matches Oracle example
            }

            # Optional: validate here if you want early fail (not required)
            try:
                validate_config(cfg)
            except Exception as e:
                print(f"[X] Loaded profile config failed validation: {e}")
                return -1

            self.credentials = {"config": cfg, "signer": None}
            self.credentials_type = "Profile"

        self.credname = cred
        self.tenant_id = tenancy
        self.compartment_id = tenancy
        self.region = region
        self._sync_region_config_from_loaded_creds(region)

        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded profile {cred}{UtilityTools.RESET}")
        self._set_logger_credname(cred or "")
        return 1

    def add_api_key(self, credname: str, extra_args: dict):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        user = _pick_first(extra_args.get("user"), extra_args.get("user_ocid"))
        fingerprint = _pick_first(extra_args.get("fingerprint"))
        tenancy = _pick_first(extra_args.get("tenancy_id"), extra_args.get("tenancy"))
        region = _pick_first(extra_args.get("region")).lower()

        key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_key_file"),
            extra_args.get("key_content"),
            extra_args.get("key_file"),
        )
        key_content, key_file, err = self._resolve_resource_text_or_file(key_source, "api-key private key")
        if err:
            print(f"[X] {err}")
            return None

        passphrase = _pick_first(extra_args.get("passphrase"), extra_args.get("pass_phrase"))
        passphrase_file = _pick_first(extra_args.get("passphrase_file"))
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "api-key private key passphrase")
            if err:
                print(f"[X] {err}")
                return None

        if not user:
            print("[X] Missing user OCID for api-key auth. Provide --user <user_ocid>.")
            return None
        if not fingerprint:
            print("[X] Missing fingerprint for api-key auth. Provide --fingerprint <fingerprint>.")
            return None
        if not tenancy:
            print("[X] Missing tenancy for api-key auth. Provide --tenancy-id <tenancy_ocid>.")
            return None
        if not region:
            print("[X] Missing region for api-key auth. Provide --region <oci_region>.")
            return None
        if not key_content:
            print("[X] Missing private key for api-key auth. Provide --private-key or --private-key-file.")
            return None

        serialized: Dict[str, Any] = {
            "auth_type": "api_key",
            "user": user,
            "fingerprint": fingerprint,
            "tenancy": tenancy,
            "region": region,
            "key_content": key_content,
        }
        if key_file:
            serialized["key_file"] = key_file
        if passphrase:
            serialized["pass_phrase"] = passphrase
        if passphrase_file:
            serialized["passphrase_file"] = passphrase_file

        # Reuse existing profile API-key loader behavior for validation + runtime state.
        load_rec = CredRecord(
            credname=credname,
            credtype="Profile - API Key - INLINE",
            session_creds=json.dumps(serialized),
        )
        ok = self._load_profile_from_record(load_rec)
        if ok != 1:
            print("[X] Could not initialize api-key credentials from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "api-key", json.dumps(serialized))
        self.credname = credname
        self._set_logger_credname(credname or "")
        self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def add_session_token(self, credname: str, extra_args: dict):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        token_source = _pick_first(
            extra_args.get("token"),
            extra_args.get("token_value"),
            extra_args.get("token_file"),
            extra_args.get("security_token_content"),
            extra_args.get("security_token"),
            extra_args.get("security_token_file"),
        )
        token, token_file, err = self._resolve_resource_text_or_file(token_source, "session token")
        if err:
            print(f"[X] {err}")
            return None
        if not token:
            print("[X] Missing session token. Provide --token or --token-file.")
            return None

        key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_key_file"),
            extra_args.get("key_content"),
            extra_args.get("key_file"),
        )
        key_content, key_file, err = self._resolve_resource_text_or_file(key_source, "session token private key")
        if err:
            print(f"[X] {err}")
            return None
        if not key_content:
            print("[X] Missing private key for session-token auth. Provide --private-key or --private-key-file.")
            return None

        passphrase = _pick_first(extra_args.get("passphrase"), extra_args.get("pass_phrase"))
        passphrase_file = _pick_first(extra_args.get("passphrase_file"))
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "session token private key passphrase")
            if err:
                print(f"[X] {err}")
                return None

        region = _pick_first(extra_args.get("region")).lower()
        tenancy = _pick_first(
            extra_args.get("tenancy_id"),
            extra_args.get("tenancy"),
            self._extract_tenancy_from_token(token),
        )

        if not region:
            print("[X] Missing region for session-token auth. Provide --region <oci_region>.")
            return None
        if not tenancy:
            print("[X] Missing tenancy for session-token auth. Provide --tenancy-id <tenancy_ocid>.")
            return None

        serialized: Dict[str, Any] = {
            "auth_type": "session_token",
            "security_token_content": token,
            "key_content": key_content,
            "region": region,
            "tenancy": tenancy,
        }
        if token_file:
            serialized["security_token_file"] = token_file
        if key_file:
            serialized["key_file"] = key_file
        if passphrase:
            serialized["pass_phrase"] = passphrase
        if passphrase_file:
            serialized["passphrase_file"] = passphrase_file

        # Reuse existing profile session-token loader behavior for validation + runtime state.
        load_rec = CredRecord(
            credname=credname,
            credtype="Profile - Session - INLINE",
            session_creds=json.dumps(serialized),
        )
        ok = self._load_profile_from_record(load_rec)
        if ok != 1:
            print("[X] Could not initialize session-token signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "session-token", json.dumps(serialized))
        self.credname = credname
        self._set_logger_credname(credname or "")
        self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def add_instance_profile_token(self, credname: str, extra_args: dict, proxy: str = "", debug_http: bool = False):
        _ea = extra_args or {}
        self.debug_http = bool(debug_http or _truthy(_ea.get("debug_http")) or _truthy(_ea.get("log_requests")))
        self._ipdbg("start add_instance_profile_token", credname=credname, extra_args=extra_args)
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        ref_file = (extra_args.get("reference_file") or extra_args.get("filepath") or "").strip()
        on_host = _truthy(extra_args.get("on_host"))
        imds_version = _safe_str(extra_args.get("imds_version")).strip().lower() or "v2"
        region = (extra_args.get("region") or "").strip()
        cli_proxy = _safe_str(extra_args.get("proxy")).strip()
        debug_http = bool(debug_http or _truthy(extra_args.get("debug_http")) or _truthy(extra_args.get("log_requests")))

        if on_host and ref_file:
            print("[X] Use either --on-host OR --reference-file, not both.")
            return None

        if not on_host and not ref_file:
            print("[X] Missing instance-principal mode. Use --on-host or --reference-file.")
            return None

        explicit_proxy = (proxy or "").strip() or cli_proxy
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)
        cfg: Dict[str, Any]
        if on_host:
            self._ipdbg("mode on-host selected", imds_version=imds_version, region=region or "<auto>", proxy=effective_proxy or "<none>")
            if not region:
                region = self._detect_instance_region(imds_version=imds_version)
            if not region:
                print("[X] Missing region. Provide --region when using --on-host.")
                return None
            tenancy_id = self._detect_instance_tenancy_ocid(imds_version=imds_version)
            self._ipdbg("on-host metadata resolved", region=region, tenancy_id=tenancy_id or "<empty>")
            cfg = {
                "mode": "on-host",
                "region": region,
                "tenancy_id": tenancy_id,
                "imds_version": imds_version,
                "proxy": effective_proxy,
                "log_requests": bool(debug_http),
            }
        else:
            self._ipdbg("mode reference-file selected", ref_file=ref_file, imds_version=imds_version)
            ref_cfg, err = self._load_instance_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading instance-principal reference file: {err}")
                return None
            if not region:
                region = _safe_str(ref_cfg.get("region")).strip()
            if not region:
                region = self._detect_instance_region(imds_version=imds_version)
            if not region:
                print("[X] Missing region. Provide --region, set 'region' in reference file, or run where IMDS /opc is reachable.")
                return None
            tenancy_id = _safe_str(ref_cfg.get("tenancy_id")).strip() or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            if not tenancy_id:
                print("[X] Missing tenancy_id in reference file and could not auto-detect via instance metadata.")
                return None
            cfg = {
                "mode": "reference-file",
                "reference_file": str(Path(ref_file).expanduser().resolve()),
                "region": region,
                "tenancy_id": tenancy_id,
                "imds_version": imds_version,
                "proxy": effective_proxy,
                "log_requests": bool(ref_cfg.get("log_requests", False)) or bool(debug_http),
            }

        # Optional delegation (OBO) token -> instance-principal federation + opc-obo-token.
        # Explicit only (no env auto-pick), so a plain instance-principal stays plain.
        deleg_token, deleg_file, deleg_err = self._resolve_delegation_token(
            token_file=_safe_str(extra_args.get("delegation_token_file")).strip(),
            token_inline=_safe_str(extra_args.get("delegation_token")).strip(),
            allow_env=False,
        )
        if deleg_err:
            print(f"[X] {deleg_err}")
            return None
        if deleg_token:
            cfg["delegation_token_file"] = deleg_file
            cfg["delegation_token"] = "" if deleg_file else deleg_token

        self._ipdbg("attempting initial load", mode=cfg.get("mode"), region=cfg.get("region"), tenancy_id=cfg.get("tenancy_id"), delegation=bool(deleg_token))
        load_rec = CredRecord(credname=credname, credtype="instance-principal", session_creds=json.dumps(cfg))
        ok = self._load_instance_profile_from_record(load_rec, force_refresh=True, debug_http=debug_http)
        if ok != 1:
            print("[X] Could not initialize instance-principal signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "instance-principal", json.dumps(cfg))
        self.credname = credname
        self._set_logger_credname(credname or "")
        tenancy_for_root = _safe_str(cfg.get("tenancy_id")).strip()
        if tenancy_for_root:
            self.add_compartment_id(tenancy_for_root, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def _load_instance_profile_from_record(self, rec: CredRecord, force_refresh: bool = False, debug_http: bool = False) -> int:
        cred = rec.credname
        self.debug_http = bool(debug_http)
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            self._ipdbg("start _load_instance_profile_from_record", credname=cred, force_refresh=force_refresh)
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        # Merge the credential's own persisted --debug-http flag in BEFORE the first
        # _ipdbg call below, so a reload (no explicit debug_http kwarg -- e.g. resume /
        # set_active_creds) still traces when the stored record itself asked for it.
        log_requests = _truthy(stored.get("log_requests")) or bool(debug_http)
        self.debug_http = bool(self.debug_http or log_requests)
        self._ipdbg("start _load_instance_profile_from_record", credname=cred, force_refresh=force_refresh)

        mode = _safe_str(stored.get("mode")).strip().lower()
        ref_file = _safe_str(stored.get("reference_file")).strip()
        region = _safe_str(stored.get("region")).strip()
        tenancy_id = _safe_str(stored.get("tenancy_id")).strip()
        imds_version = _safe_str(stored.get("imds_version")).strip().lower() or "v2"
        proxy = _safe_str(stored.get("proxy")).strip()

        if not mode:
            mode = "reference-file" if ref_file else "on-host"

        # Optional delegation (OBO) token -> layer opc-obo-token on the instance principal.
        # Re-resolved each load (Cloud Shell rotates the file); explicit source only.
        deleg_token, _deleg_file, deleg_err = self._resolve_delegation_token(
            token_file=_safe_str(stored.get("delegation_token_file")).strip(),
            token_inline=_safe_str(stored.get("delegation_token")).strip(),
            allow_env=False,
        )
        if deleg_err:
            print(f"[X] instance-principal '{cred}': {deleg_err}")
            return -1
        self._ipdbg("parsed stored mode", mode=mode, region=region or "<auto>", imds_version=imds_version, delegation=bool(deleg_token))

        if not region:
            region = self._detect_instance_region(imds_version=imds_version)
        if not region:
            print(f"[X] instance-principal '{cred}' missing region and IMDS lookup failed")
            return -1
        if mode == "on-host":
            tenancy_id = tenancy_id or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            self._ipdbg("building on-host signer", region=region, tenancy_id=tenancy_id or "<empty>", delegation=bool(deleg_token))
            if deleg_token:
                signer, cfg, err = self._build_on_host_delegation_signer(region=region, tenancy_id=tenancy_id, delegation_token=deleg_token)
            else:
                signer, cfg, err = self._build_on_host_instance_profile_signer(
                    region=region,
                    tenancy_id=tenancy_id,
                    force_refresh=force_refresh,
                    debug_http=debug_http,
                )
            if err:
                print(f"[X] Failed building on-host instance-principal signer for '{cred}': {err}")
                return -1
        else:
            if not ref_file:
                print(f"[X] instance-principal '{cred}' missing reference_file in DB")
                return -1
            tenancy_id = tenancy_id or self._detect_instance_tenancy_ocid(imds_version=imds_version)
            if not tenancy_id:
                print(f"[X] instance-principal '{cred}' missing tenancy_id and metadata lookup failed")
                return -1
            self._ipdbg("building reference-file signer", ref_file=ref_file, region=region, tenancy_id=tenancy_id, delegation=bool(deleg_token))
            ref_cfg, err = self._load_instance_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading reference file for '{cred}': {err}")
                return -1
            signer, cfg, err = self._build_instance_profile_signer(
                ref_cfg=ref_cfg,
                region=region,
                tenancy_id=tenancy_id,
                proxy=proxy,
                log_requests=log_requests,
                force_refresh=force_refresh,
                delegation_token=deleg_token or None,
            )
            if err:
                print(f"[X] Failed building instance-principal signer for '{cred}': {err}")
                return -1

        if deleg_token:
            user_tenancy = self._tenancy_from_delegation_token(deleg_token)
            if user_tenancy:
                if isinstance(cfg, dict):
                    cfg["tenancy"] = user_tenancy
                tenancy_id = user_tenancy

        self.credentials = {"config": cfg, "signer": signer}
        self.credentials_type = "instance-principal"
        self.credname = cred
        self.tenant_id = _safe_str(cfg.get("tenancy")).strip() or tenancy_id
        self.compartment_id = self.tenant_id or tenancy_id
        self.region = region
        self._sync_region_config_from_loaded_creds(region)
        self._set_logger_credname(cred or "")
        label = "instance-principal (delegation)" if deleg_token else "instance-principal"
        self._ipdbg("load complete", credname=cred, tenancy_id=self.tenant_id or "<empty>", region=self.region or "<empty>", delegation=bool(deleg_token))
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded {label} {cred}{UtilityTools.RESET}")
        return 1

    # =============================================================================
    # Delegation token (OBO) -- instance-principal federation + an opc-obo-token.
    # Reuses the off-box reference-file signer; the user supplies the same leaf/
    # intermediate/key material PLUS the delegation token (source stored, re-read
    # each load so Cloud Shell's ~hourly rotation is picked up).
    # =============================================================================

    def _resolve_delegation_token(self, *, token_file: str, token_inline: str, allow_env: bool = True) -> Tuple[str, str, Optional[str]]:
        """Return (token, token_file_used, err). Prefers a file (rotatable) over inline."""
        tf = _safe_str(token_file).strip()
        if tf:
            text, err = self._read_text_file(tf, "delegation token")
            if err:
                return "", "", err
            return _safe_str(text).strip(), tf, None
        inline = _safe_str(token_inline).strip()
        if inline:
            return inline, "", None
        if allow_env:
            env_file = _safe_str(os.environ.get("OCI_DELEGATION_TOKEN_FILE")).strip()
            if env_file:
                text, err = self._read_text_file(env_file, "delegation token")
                if err:
                    return "", "", err
                return _safe_str(text).strip(), env_file, None
            env_tok = _safe_str(os.environ.get("OCI_DELEGATION_TOKEN")).strip()
            if env_tok:
                return env_tok, "", None
            for default_path in ("/etc/oci/delegation_token", "~/.oci/delegation_token"):
                p = Path(default_path).expanduser()
                if p.is_file():
                    text, err = self._read_text_file(str(p), "delegation token")
                    if err:
                        return "", "", err
                    return _safe_str(text).strip(), str(p), None
        return "", "", None

    def _tenancy_from_delegation_token(self, token: str) -> str:
        """Resolve the session tenancy from the delegation token. Best-effort; returns "" on failure."""
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            return _safe_str(claims.get("tenant") or claims.get("tenancy") or claims.get("own")).strip()
        except Exception:
            return ""

    def _build_on_host_delegation_signer(self, *, region: str, tenancy_id: str, delegation_token: str):
        """On-host (Cloud Shell / OCI instance) delegation: the SDK's native signer
        bootstraps the instance principal from IMDS and stamps the obo token itself."""
        signers_mod = getattr(getattr(oci, "auth", None), "signers", None)
        cls = getattr(signers_mod, "InstancePrincipalsDelegationTokenSigner", None)
        if cls is None:
            return None, {}, "OCI SDK missing InstancePrincipalsDelegationTokenSigner"
        try:
            kwargs: Dict[str, Any] = {"delegation_token": delegation_token}
            if region:
                kwargs["federation_endpoint"] = f"https://auth.{region}.oraclecloud.com/v1/x509"
            signer = cls(**kwargs)
        except Exception as e:
            return None, {}, str(e)
        return signer, {"tenancy": tenancy_id, "region": region}, None

    def add_resource_profile_token(self, credname: str, extra_args: dict, proxy: str = "", debug_http: bool = False):
        if not credname:
            print("[X] Missing credname")
            return None

        if self.data_master.fetch_cred(self.workspace_id, credname):
            print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] {credname} already exists.{UtilityTools.RESET}")
            return None

        extra_args = extra_args or {}
        self.debug_http = bool(debug_http or _truthy(extra_args.get("debug_http")) or _truthy(extra_args.get("log_requests")))
        ref_file_arg = _safe_str(extra_args.get("reference_file")).strip()
        filepath_arg = _safe_str(extra_args.get("filepath")).strip()
        if ref_file_arg and filepath_arg and ref_file_arg != filepath_arg:
            print("[X] Use only one resource-principal reference file path.")
            return None
        ref_file = ref_file_arg or filepath_arg
        ref_cfg: Dict[str, Any] = {}
        if ref_file:
            ref_cfg, err = self._load_resource_profile_reference_file(ref_file)
            if err:
                print(f"[X] Failed loading resource-principal reference file: {err}")
                return None

        def _pick_first(*vals: Any) -> str:
            for v in vals:
                s = _safe_str(v).strip()
                if s:
                    return s
            return ""

        token_source = _pick_first(
            extra_args.get("token"),
            extra_args.get("rpst"),
            extra_args.get("token_file"),
            ref_cfg.get("rpst_content"),
            ref_cfg.get("rpst"),
            ref_cfg.get("security_token_content"),
            ref_cfg.get("security_token"),
            ref_cfg.get("token"),
            ref_cfg.get("rpst_file"),
            ref_cfg.get("security_token_file"),
            ref_cfg.get("token_file"),
        )
        token, token_file, err = self._resolve_resource_text_or_file(token_source, "resource principal token")
        if err:
            print(f"[X] {err}")
            return None
        if not token:
            print(
                "[X] Missing resource principal token (RPST). "
                "Provide --token, --token-file, or --reference-file."
            )
            return None

        private_key_source = _pick_first(
            extra_args.get("private_key"),
            extra_args.get("private_pem"),
            extra_args.get("private_key_file"),
            ref_cfg.get("private_pem_content"),
            ref_cfg.get("private_pem"),
            ref_cfg.get("private_key"),
            ref_cfg.get("key_content"),
            ref_cfg.get("private_pem_file"),
            ref_cfg.get("private_key_file"),
            ref_cfg.get("key_file"),
        )
        private_pem, private_pem_file, err = self._resolve_resource_text_or_file(private_key_source, "resource principal private key")
        if err:
            print(f"[X] {err}")
            return None
        if not private_pem:
            print(
                "[X] Missing resource principal private key. "
                "Provide --private-key, --private-key-file, or --reference-file."
            )
            return None

        passphrase = _pick_first(
            extra_args.get("passphrase"),
            ref_cfg.get("passphrase"),
        )
        passphrase_file = _pick_first(
            extra_args.get("passphrase_file"),
            ref_cfg.get("passphrase_file"),
        )
        if not passphrase and passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "resource principal passphrase")
            if err:
                print(f"[X] {err}")
                return None

        region = _pick_first(
            extra_args.get("region"),
            ref_cfg.get("region"),
        ).lower()
        tenancy = _pick_first(
            extra_args.get("tenancy_id"),
            extra_args.get("tenancy"),
            ref_cfg.get("tenancy_id"),
            ref_cfg.get("tenancy"),
        )
        if not tenancy:
            tenancy = self._extract_tenancy_from_token(token)

        version = _pick_first(
            extra_args.get("version"),
            ref_cfg.get("version"),
        )

        explicit_proxy = _pick_first(proxy, extra_args.get("proxy"), ref_cfg.get("proxy"))
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)

        stored: Dict[str, Any] = {
            "resource_principal": True,
            "auth_type": "resource_principal",
            "rpst_content": token,
            "private_pem_content": private_pem,
            "region": region,
            "tenancy": tenancy,
            "version": version,
            "proxy": effective_proxy,
            "log_requests": bool(debug_http or _truthy(extra_args.get("debug_http"))),
        }
        if token_file:
            stored["rpst_file"] = token_file
        if private_pem_file:
            stored["private_pem_file"] = private_pem_file
        if passphrase:
            stored["passphrase"] = passphrase
        if passphrase_file:
            stored["passphrase_file"] = passphrase_file
        if ref_file:
            stored["filepath"] = str(Path(ref_file).expanduser().resolve())

        load_rec = CredRecord(credname=credname, credtype="resource-principal", session_creds=json.dumps(stored))
        ok = self._load_resource_profile_from_record(load_rec, force_refresh=True, debug_http=debug_http)
        if ok != 1:
            print("[X] Could not initialize resource-principal signer from supplied settings.")
            return None

        self.data_master.insert_creds(self.workspace_id, credname, "resource-principal", json.dumps(stored))
        self.credname = credname
        self._set_logger_credname(credname or "")
        if tenancy:
            self.add_compartment_id(tenancy, parent_compartment_id="N/A", override=False)
        print(f"{UtilityTools.BRIGHT_GREEN}[*] Credentials added: {credname}{UtilityTools.RESET}")
        return 1

    def _load_resource_profile_from_record(self, rec: CredRecord, force_refresh: bool = False, debug_http: bool = False) -> int:
        cred = rec.credname
        self.debug_http = bool(debug_http)
        try:
            stored = json.loads(rec.session_creds or "{}")
        except Exception as e:
            print(f"[X] Bad stored JSON for {cred}: {e}")
            return -1

        signer = self.build_or_reuse_signer(
            stored,
            force_refresh=force_refresh,
            debug_http=debug_http,
            type_of_cred="resource-principal",
        )
        if signer is None:
            print(f"[X] Failed building resource-principal signer for '{cred}'.")
            return -1

        token = _safe_str(stored.get("rpst_content") or stored.get("security_token_content") or stored.get("token")).strip()
        region = _safe_str(stored.get("region")).strip().lower()
        tenancy = _safe_str(stored.get("tenancy") or stored.get("tenancy_id")).strip()
        if not tenancy and token:
            tenancy = self._extract_tenancy_from_token(token)

        cfg: Dict[str, Any] = {}
        if tenancy:
            cfg["tenancy"] = tenancy
        if region:
            cfg["region"] = region

        self.credentials = {"config": cfg, "signer": signer}
        self.credentials_type = "resource-principal"
        self.credname = cred

        if tenancy:
            self.tenant_id = tenancy
            self.compartment_id = tenancy
        if region:
            self.region = region
            self._sync_region_config_from_loaded_creds(region)

        self._set_logger_credname(cred or "")
        print(f"{UtilityTools.GREEN}{UtilityTools.BOLD}[*] Loaded resource-principal {cred}{UtilityTools.RESET}")
        return 1

    def build_or_reuse_signer(self, cfg: Dict[str, Any], force_refresh: bool = False, debug_http: bool = False, type_of_cred: Optional[str] = None):
        cred_type = _safe_str(type_of_cred).strip().lower()
        if cred_type and cred_type != "resource-principal":
            if debug_http:
                print(f"[!] build_or_reuse_signer does not support type '{type_of_cred}'")
            return None

        if not isinstance(cfg, dict):
            if debug_http:
                print("[!] build_or_reuse_signer: cfg must be a dict")
            return None

        token = _safe_str(cfg.get("rpst_content") or cfg.get("security_token_content") or cfg.get("token")).strip()
        token_file = _safe_str(cfg.get("rpst_file") or cfg.get("security_token_file") or cfg.get("token_file")).strip()
        if token_file and (force_refresh or not token):
            text, err = self._read_text_file(token_file, "resource principal token")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            token = _safe_str(text).strip()
            cfg["rpst_content"] = token
            cfg["rpst_file"] = token_file
        if not token:
            if debug_http:
                print("[!] Missing RPST token for resource-principal signer")
            return None

        private_pem = _safe_str(cfg.get("private_pem_content") or cfg.get("private_key") or cfg.get("key_content")).strip()
        private_pem_file = _safe_str(cfg.get("private_pem_file") or cfg.get("private_key_file") or cfg.get("key_file")).strip()
        if private_pem_file and (force_refresh or not private_pem):
            text, err = self._read_text_file(private_pem_file, "resource principal private key")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            private_pem = _safe_str(text).strip()
            cfg["private_pem_content"] = private_pem
            cfg["private_pem_file"] = private_pem_file
        if not private_pem:
            if debug_http:
                print("[!] Missing private key for resource-principal signer")
            return None

        passphrase = _safe_str(cfg.get("passphrase")).strip()
        passphrase_file = _safe_str(cfg.get("passphrase_file")).strip()
        if passphrase_file and (force_refresh or not passphrase):
            text, err = self._read_text_file(passphrase_file, "resource principal passphrase")
            if err:
                if debug_http:
                    print(f"[!] {err}")
                return None
            passphrase = _safe_str(text).strip()
            cfg["passphrase"] = passphrase

        cache = getattr(self, "_resource_principal_signer_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            self._resource_principal_signer_cache = cache

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cached = cache.get(token_hash)
        if not force_refresh and isinstance(cached, dict):
            exp = int(cached.get("token_exp", 0) or 0)
            signer = cached.get("signer")
            now = int(time.time())
            if signer is not None and (exp == 0 or exp > now + 30):
                return signer

        pw = passphrase.encode("utf-8") if passphrase else None
        try:
            private_key_obj = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=pw)
            signer = SecurityTokenSigner(token, private_key_obj)
        except Exception as e:
            if debug_http:
                print(f"[!] Could not build resource-principal signer: {e}")
            return None

        cache[token_hash] = {"signer": signer, "token_exp": self._decode_jwt_exp(token)}
        return signer

    def _detect_instance_tenancy_ocid(self, imds_version: str = "v2") -> str:
        endpoints = self._metadata_lookup_order(imds_version=imds_version)
        self._ipdbg("detect tenancy start", imds_version=imds_version, attempts=len(endpoints))
        for url, headers in endpoints:
            try:
                self._ipdbg("detect tenancy request", url=url)
                self._wait_for_http_rate_limit()
                r = requests.get(url, headers=headers, timeout=2)
                self._ipdbg("detect tenancy response", url=url, status=r.status_code)
                if r.status_code != 200:
                    continue
                data = r.json() if r.text else {}
                if not isinstance(data, dict):
                    continue
                tid = _safe_str(data.get("tenantId") or data.get("tenancyId") or data.get("tenancy_id")).strip()
                if tid:
                    self._ipdbg("detect tenancy success", tenancy_id=tid)
                    return tid
            except Exception:
                self._ipdbg("detect tenancy error", url=url)
                continue
        self._ipdbg("detect tenancy failed")
        return ""

    def _detect_instance_region(self, imds_version: str = "v2") -> str:
        endpoints = self._metadata_lookup_order(imds_version=imds_version)
        self._ipdbg("detect region start", imds_version=imds_version, attempts=len(endpoints))
        for url, headers in endpoints:
            try:
                self._ipdbg("detect region request", url=url)
                self._wait_for_http_rate_limit()
                r = requests.get(url, headers=headers, timeout=2)
                self._ipdbg("detect region response", url=url, status=r.status_code)
                if r.status_code != 200:
                    continue
                data = r.json() if r.text else {}
                if not isinstance(data, dict):
                    continue
                region = _safe_str(
                    data.get("regionName")
                    or data.get("regionIdentifier")
                    or data.get("canonicalRegionName")
                    or data.get("region")
                ).strip()
                if region:
                    self._ipdbg("detect region success", region=region.lower())
                    return region.lower()
            except Exception:
                self._ipdbg("detect region error", url=url)
                continue
        self._ipdbg("detect region failed")
        return ""

    def _build_on_host_instance_profile_signer(
        self,
        *,
        region: str,
        tenancy_id: str,
        force_refresh: bool,
        debug_http: bool,
    ) -> Tuple[Optional[Any], Dict[str, Any], Optional[str]]:
        self._ipdbg("build on-host signer start", region=region, tenancy_id=tenancy_id or "<empty>", force_refresh=force_refresh)
        signer_cls = getattr(getattr(oci, "auth", None), "signers", None)
        signer_cls = getattr(signer_cls, "InstancePrincipalsSecurityTokenSigner", None)
        if signer_cls is None:
            return None, {}, "OCI SDK missing InstancePrincipalsSecurityTokenSigner"

        signer = None
        try:
            self._ipdbg("construct signer with kwargs")
            signer = signer_cls(federation_client_cert_bundle_verify=False, log_requests=bool(debug_http))
        except TypeError:
            try:
                self._ipdbg("construct signer fallback no-arg")
                signer = signer_cls()
            except Exception as e:
                return None, {}, str(e)
        except Exception as e:
            return None, {}, str(e)

        if force_refresh and hasattr(signer, "refresh_security_token"):
            try:
                self._ipdbg("refresh_security_token start")
                signer.refresh_security_token()
                self._ipdbg("refresh_security_token done")
            except Exception:
                self._ipdbg("refresh_security_token failed")
                pass

        cfg: Dict[str, Any] = {"region": region}
        if tenancy_id:
            cfg["tenancy"] = tenancy_id
        self._ipdbg("build on-host signer done")
        return signer, cfg, None

    def _build_instance_profile_signer(
        self,
        *,
        ref_cfg: Dict[str, Any],
        region: str,
        tenancy_id: str,
        proxy: str,
        log_requests: bool,
        force_refresh: bool,
        delegation_token: Optional[str] = None,
    ) -> Tuple[Optional[X509FederationClientBasedSecurityTokenSigner], Dict[str, Any], Optional[str]]:
        leaf_cert_path = _safe_str(ref_cfg.get("leaf_cert_file")).strip()
        leaf_key_path = _safe_str(ref_cfg.get("leaf_key_file")).strip()
        if not leaf_cert_path or not leaf_key_path:
            return None, {}, "reference file must define leaf_cert_file and leaf_key_file"

        leaf_cert_pem, err = self._read_text_file(leaf_cert_path, "leaf_cert")
        if err:
            return None, {}, err
        leaf_key_pem, err = self._read_text_file(leaf_key_path, "leaf_key")
        if err:
            return None, {}, err

        passphrase: Optional[str] = None
        passphrase_file = _safe_str(ref_cfg.get("passphrase_file")).strip()
        if passphrase_file:
            passphrase, err = self._read_text_file(passphrase_file, "passphrase")
            if err:
                return None, {}, err

        intermediate_pems: List[str] = []
        one_intermediate = _safe_str(ref_cfg.get("intermediate_cert_file")).strip()
        if one_intermediate:
            text, err = self._read_text_file(one_intermediate, "intermediate_cert")
            if err:
                return None, {}, err
            intermediate_pems.append(text or "")

        many_intermediates = ref_cfg.get("intermediate_cert_files")
        if isinstance(many_intermediates, list):
            for idx, ipath in enumerate(many_intermediates):
                if not isinstance(ipath, str) or not ipath.strip():
                    continue
                text, err = self._read_text_file(ipath.strip(), f"intermediate_cert[{idx}]")
                if err:
                    return None, {}, err
                intermediate_pems.append(text or "")

        if not intermediate_pems:
            return None, {}, "reference file must define intermediate_cert_file or intermediate_cert_files"

        try:
            self._validate_pems(
                leaf_cert_pem or "",
                leaf_key_pem or "",
                intermediate_pems[0] if intermediate_pems else None,
                passphrase=passphrase,
            )
        except Exception as e:
            return None, {}, f"invalid PEM material: {e}"

        leaf = PEMStringCertificateRetriever(
            certificate_pem=leaf_cert_pem or "",
            private_key_pem=leaf_key_pem or "",
            passphrase=(passphrase or None),
        )
        intermediates = [PEMStringCertificateRetriever(certificate_pem=x) for x in intermediate_pems if x]

        req_sess = requests.Session()
        self._apply_http_rate_limit_to_requests_session(req_sess)
        explicit_proxy = (proxy or "").strip()
        effective_proxy = self._resolve_proxy(explicit_proxy, include_auth_proxy=True)
        self._ipdbg("instance-principal proxy", proxy=effective_proxy or "<none>")
        req_sess.trust_env = False
        proxy_env_keys = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
        prior_proxy_env = {k: os.environ.get(k) for k in proxy_env_keys}
        if effective_proxy:
            # Ensure proxy is honored even if other libs read env
            os.environ["HTTP_PROXY"] = effective_proxy
            os.environ["HTTPS_PROXY"] = effective_proxy
            os.environ["http_proxy"] = effective_proxy
            os.environ["https_proxy"] = effective_proxy
            req_sess.proxies.update({"http": effective_proxy, "https": effective_proxy})
        try:
            ca_bundle_file = _safe_str(ref_cfg.get("ca_bundle_file")).strip()
            if ca_bundle_file:
                req_sess.verify = ca_bundle_file
                self._ipdbg("instance-principal CA bundle", ca_bundle_file=ca_bundle_file)

            federation_endpoint = _safe_str(ref_cfg.get("federation_endpoint")).strip() or f"https://auth.{region}.oraclecloud.com/v1/x509"
            self._ipdbg("instance-principal federation endpoint", endpoint=federation_endpoint, log_requests=bool(log_requests))
            session_keys = SessionKeySupplier(key_size=2048)
            try:
                if log_requests:
                    try:
                        preflight = req_sess.get(federation_endpoint, timeout=5)
                        self._ipdbg("instance-principal preflight", status=preflight.status_code)
                    except Exception as e:
                        self._ipdbg("instance-principal preflight failed", err=f"{type(e).__name__}: {e}")
                fed = X509FederationClient(
                    federation_endpoint=federation_endpoint,
                    tenancy_id=tenancy_id,
                    session_key_supplier=session_keys,
                    leaf_certificate_retriever=leaf,
                    intermediate_certificate_retrievers=intermediates,
                    cert_bundle_verify=False,
                    requests_session=req_sess,
                    log_requests=bool(log_requests),
                )
                if force_refresh:
                    try:
                        fed.get_security_token()
                    except Exception:
                        pass
                if delegation_token:
                    signer = _build_instance_delegation_signer(fed, delegation_token)
                else:
                    signer = X509FederationClientBasedSecurityTokenSigner(fed)
            except Exception as e:
                return None, {}, str(e)

            cfg = {"tenancy": tenancy_id, "region": region}
            return signer, cfg, None
        finally:
            if effective_proxy:
                for key, old_value in prior_proxy_env.items():
                    if old_value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = old_value
