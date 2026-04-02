import argparse
import json
import hashlib
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import domain_matches, parse_csv_args
from ocinferno.core.utils.service_runtime import _init_client


# =============================================================================
# Table names (service DB)
# =============================================================================

TABLE_COMPARTMENTS = "resource_compartments"

TABLE_USERS = "identity_users"
TABLE_GROUPS = "identity_groups"
TABLE_USER_GROUP_MEMBERSHIPS = "identity_user_group_memberships"
TABLE_USER_API_KEYS = "identity_user_api_keys"
TABLE_DYNAMIC_GROUPS = "identity_dynamic_groups"

TABLE_IDENTITY_DOMAINS = "identity_domains"

TABLE_IDD_USERS = "identity_domain_users"
TABLE_IDD_GROUPS = "identity_domain_groups"
TABLE_IDD_DYNAMIC_GROUPS = "identity_domain_dynamic_groups"
TABLE_IDD_USER_GROUP_MEMBERSHIPS = "identity_domain_user_group_memberships"

# Identity Domain IAM-ish artifacts (kept for enum_iam)
TABLE_IDD_POLICIES = "identity_domain_policies"
TABLE_IDD_APPS = "identity_domain_apps"
TABLE_IDD_APP_ROLES = "identity_domain_app_roles"
TABLE_IDD_GRANTS = "identity_domain_grants"

# Identity Domain "settings/posture" artifacts (for enum_identity --domains)
TABLE_IDD_PASSWORD_POLICIES = "identity_domain_password_policies"
TABLE_IDD_LOCKOUT_POLICIES = "identity_domain_lockout_policies"
TABLE_IDD_IDENTITY_PROVIDERS = "identity_domain_identity_providers"
TABLE_IDD_SIGN_ON_POLICIES = "identity_domain_sign_on_policies"
TABLE_IDD_MFA_SETTINGS = "identity_domain_authentication_factor_settings"  # AuthenticationFactorSetting

# Identity Domain "credential-ish" artifacts (for enum_identity --domains)
TABLE_IDD_USER_DB_CREDENTIALS = "identity_domain_user_db_credentials"
TABLE_IDD_USER_SMTP_CREDENTIALS = "identity_domain_user_smtp_credentials"
TABLE_IDD_USER_API_KEYS = "identity_domain_user_api_keys"
TABLE_IDD_USER_AUTH_TOKENS = "identity_domain_user_auth_tokens"

TABLE_POLICIES = "identity_policies"
TABLE_POLICY_PARSED = "identity_policy_statements"

# =============================================================================
# Common dataclasses
# =============================================================================

@dataclass(frozen=True)
class PrincipalEnumResult:
    compartment_users: list[dict[str, Any]]
    compartment_groups: list[dict[str, Any]]
    compartment_memberships: list[dict[str, Any]]
    compartment_dynamic_groups: list[dict[str, Any]]

    domain_users: list[dict[str, Any]]
    domain_groups: list[dict[str, Any]]
    domain_memberships: list[dict[str, Any]]
    domain_dynamic_groups: list[dict[str, Any]]

    domains: list[dict[str, Any]]


@dataclass(frozen=True)
class IdentityDomainCredsEnumResult:
    domains: list[dict[str, Any]]
    smtp_credentials: list[dict[str, Any]]
    db_credentials: list[dict[str, Any]]
    api_keys: list[dict[str, Any]]


@dataclass(frozen=True)
class IamEnumResult:
    policies: list[dict[str, Any]]
    parsed: list[dict[str, Any]]


@dataclass(frozen=True)
class IdentityDomainEnumResult:
    domains: list[dict[str, Any]]


@dataclass(frozen=True)
class IdentityDomainSettingsEnumResult:
    domains: list[dict[str, Any]]
    password_policies: list[dict[str, Any]]
    lockout_policies: list[dict[str, Any]]
    identity_providers: list[dict[str, Any]]
    sign_on_policies: list[dict[str, Any]]
    mfa_settings: list[dict[str, Any]]


# =============================================================================
# Small helpers
# =============================================================================

class IdentityHelperUtils:
    @staticmethod
    def to_dict(obj: Any) -> dict[str, Any]:
        try:
            return oci.util.to_dict(obj) if obj is not None else {}
        except Exception:
            return obj if isinstance(obj, dict) else {}

    @staticmethod
    def safe_str(x: Any) -> str:
        return x if isinstance(x, str) else ""

    @classmethod
    def first_email(cls, emails: Any) -> Optional[str]:
        if not isinstance(emails, list):
            return None
        primary = None
        for entry in emails:
            if isinstance(entry, dict) and entry.get("primary") is True and isinstance(entry.get("value"), str):
                primary = entry["value"]
                break
        if primary:
            return primary
        for entry in emails:
            if isinstance(entry, dict) and isinstance(entry.get("value"), str):
                return entry["value"]
        return None

    @staticmethod
    def dedupe_by_key(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for row in rows or []:
            value = row.get(key)
            if not value:
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append(row)
        return out

    @classmethod
    def normalize_idd_user(cls, user_row: dict[str, Any]) -> dict[str, Any]:
        """
        SCIM user objects use camelCase for some keys; your DB uses snake_case.
        We only map the small handful you actually query/print/save commonly.
        """
        if "user_name" not in user_row and "userName" in user_row:
            user_row["user_name"] = user_row.get("userName")
        if "display_name" not in user_row and "displayName" in user_row:
            user_row["display_name"] = user_row.get("displayName")

        if "email" not in user_row:
            email = cls.first_email(user_row.get("emails"))
            if email:
                user_row["email"] = email

        return user_row

    @staticmethod
    def normalize_idd_group(group_row: dict[str, Any]) -> dict[str, Any]:
        if "display_name" not in group_row and "displayName" in group_row:
            group_row["display_name"] = group_row.get("displayName")
        return group_row

    @classmethod
    def normalize_identity_domain_row(cls, domain_row: dict[str, Any], *, scope_compartment_id: str) -> dict[str, Any]:
        """
        Your identity_domains table PK is (compartment_id, url).
        Ensure we ALSO persist the domain OCID (d["id"]) so later joins work.
        """
        out = dict(domain_row or {})

        if "display_name" not in out and "displayName" in out:
            out["display_name"] = out.get("displayName")

        # Keep PK context
        out["compartment_id"] = scope_compartment_id
        out["scope_compartment_id"] = scope_compartment_id

        # list_domains returns domain OCID in "id"
        domain_ocid = cls.safe_str(out.get("id"))
        if domain_ocid:
            # Additional explicit fields used by graph/join workflows.
            out["domain_ocid"] = domain_ocid
            out["identity_domain_id"] = domain_ocid

        out["url"] = cls.safe_str(out.get("url"))
        return out

    @staticmethod
    def idd_extract_list(data: Any) -> list[Any]:
        if data is None:
            return []
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            for key_name in ("Resources", "resources", "items", "value", "Value"):
                value = data.get(key_name)
                if isinstance(value, list):
                    return value
            return []

        for attr in ("resources", "Resources", "items", "value", "Value"):
            try:
                value = getattr(data, attr, None)
            except Exception:
                value = None
            if isinstance(value, list):
                return value

        return []

    @staticmethod
    def json_blob(x: Any) -> str:
        try:
            return json.dumps(x, sort_keys=False)
        except Exception:
            try:
                return json.dumps(str(x), sort_keys=False)
            except Exception:
                return "null"

    @classmethod
    def resolve_tenancy_region_from_session(cls, session) -> tuple[str, str]:
        tenancy = cls.safe_str(getattr(session, "tenant_id", None))
        region = cls.safe_str(getattr(session, "region", None))
        creds = getattr(session, "credentials", None)
        if isinstance(creds, dict):
            if not tenancy:
                tenancy = cls.safe_str(creds.get("tenancy") or (creds.get("config") or {}).get("tenancy"))
            if not region:
                region = cls.safe_str(creds.get("region") or (creds.get("config") or {}).get("region"))
        return tenancy, region

    @staticmethod
    def generate_rsa_keypair_with_fingerprint() -> tuple[str, str, str]:
        # Lazy import so modules can still run read/selection logic if cryptography is unavailable.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.md5(public_der).hexdigest()
        fingerprint = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
        return private_pem, public_pem, fingerprint

    @classmethod
    def default_generated_profile_credname(cls, *, prefix: str, user_label: str, stamp: str, user_len: int = 10) -> str:
        user_part = cls.safe_str(user_label).strip().lower()
        if user_part:
            user_part = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in user_part).strip("._-")
        user_part = (user_part or "user")[: max(1, int(user_len))]
        compact_stamp = cls.safe_str(stamp).replace("T", "").replace("Z", "")[2:]  # yymmddHHMMSS
        return f"{cls.safe_str(prefix) or 'cred'}_{user_part}_{compact_stamp}"

    @staticmethod
    def register_generated_profile_credential(
        session,
        *,
        credname: str,
        user_ocid: str,
        fingerprint: str,
        tenancy: str,
        region: str,
        private_key_pem: str,
        source: str,
        no_prompt: bool,
        extra_payload: Optional[dict[str, Any]] = None,
    ) -> tuple[bool, str]:
        if not tenancy or not region or not user_ocid or not fingerprint or not private_key_pem:
            return False, "missing tenancy/region/user/fingerprint/private key for profile registration"

        existing = session.data_master.fetch_cred(session.workspace_id, credname)
        if existing:
            if no_prompt:
                return False, f"credname '{credname}' already exists"
            answer = input(f"Credential '{credname}' already exists. Overwrite? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                return False, "user declined overwrite"

        payload: dict[str, Any] = {
            "user": user_ocid,
            "fingerprint": fingerprint,
            "tenancy": tenancy,
            "region": region,
            "key_content": private_key_pem,
            "source": source,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        if isinstance(extra_payload, dict):
            for key_name, value in extra_payload.items():
                payload[key_name] = value

        try:
            session.data_master.insert_creds(
                session.workspace_id,
                credname,
                "Profile - API Key - GENERATED",
                json.dumps(payload),
            )
            return True, ""
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"





# =============================================================================
# Identity Domain enumeration + posture + creds
# =============================================================================

class IdentityDomainResourceClient:
    """
    Identity Domains (SCIM) wrapper via oci.identity_domains.IdentityDomainsClient.

    Pattern:
      - list_* returns list[dict]
      - save_* writes rows to the service DB (session.save_resource)
      - apply_domain_context stamps (domain_ocid/name/url + compartment) onto rows for joins

    REQUIREMENTS in helpers.py:
      - TABLE_IDD_PASSWORD_POLICIES, TABLE_IDD_MFA_SETTINGS, TABLE_IDD_USERS, TABLE_IDD_GROUPS,
        TABLE_IDD_DYNAMIC_GROUPS, TABLE_IDD_APP_ROLES, TABLE_IDD_GRANTS, TABLE_IDD_APPS constants exist
      - _init_client and IdentityHelperUtils (safe_str/json_blob helpers) are defined above
    """

    def __init__(
        self,
        *,
        session,
        service_endpoint,
        connect_timeout: int = 5,
        read_timeout: int = 60,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
        debug: bool = False,
    ):
        self.session = session
        self.debug = bool(
            getattr(session, "individual_run_debug", False)
            or getattr(session, "debug", False)
            or debug
        )

        # Track current domain context (helpful for stamping / debugging)
        self.domain_ocid = ""
        self.domain_name = ""
        self.domain_url = self._norm_url(service_endpoint)

        self.identity_domain_client = _init_client(
            oci.identity_domains.IdentityDomainsClient,
            session=session,
            service_name="identity_domains",
            service_endpoint=service_endpoint,
        )

        # ✅ FIX: set timeouts/retry on identity_domain_client (not identity_client)
        try:
            self.identity_domain_client.base_client.timeout = (connect_timeout, read_timeout)
        except Exception:
            pass
        try:
            self.identity_domain_client.retry_strategy = retry_strategy
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Small helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _norm_url(url: str) -> str:
        u = IdentityHelperUtils.safe_str(url).strip().lower()
        return u[:-1] if u.endswith("/") else u

    # -------------------------------------------------------------------------
    # Context stamping
    # -------------------------------------------------------------------------
    def apply_domain_context(
        self,
        row: dict[str, Any],
        *,
        domain_id: str = "",
        domain_name: str = "",
        domain_url: str = "",
        compartment_id: str = "",
        debug: bool | None = None,
    ) -> dict[str, Any]:
        if debug is None:
            debug = self.debug

        if domain_id:
            row["domain_ocid"] = IdentityHelperUtils.safe_str(domain_id)
            row["identity_domain_id"] = IdentityHelperUtils.safe_str(domain_id)
        if domain_name:
            row["identity_domain_name"] = IdentityHelperUtils.safe_str(domain_name)
        if domain_url:
            row["identity_domain_url"] = IdentityHelperUtils.safe_str(domain_url)

        if compartment_id:
            row.setdefault("compartment_ocid", IdentityHelperUtils.safe_str(compartment_id))
            row.setdefault("compartment_id", IdentityHelperUtils.safe_str(compartment_id))

        # store current context on object
        self.domain_ocid = IdentityHelperUtils.safe_str(domain_id) or self.domain_ocid
        self.domain_name = IdentityHelperUtils.safe_str(domain_name) or self.domain_name
        if domain_url:
            self.domain_url = self._norm_url(domain_url) or self.domain_url

        return row


    # ✅ Make this accept a list (your enum module passes a list)
    def save_password_policies(self, password_policies: list[dict[str, Any]]) -> None:
        self.session.save_resources(password_policies or [], TABLE_IDD_PASSWORD_POLICIES)

    # -------------------------------------------------------------------------
    # MFA / Authentication Factor Settings
    # -------------------------------------------------------------------------
    def list_authentication_factor_settings(self) -> list[dict[str, Any]]:
        rows = self.identity_domain_client.list_authentication_factor_settings()
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    # Canonical name
    def save_authentication_factor_settings(self, mfa_rows: list[dict[str, Any]]) -> None:
        self.session.save_resources(mfa_rows or [], TABLE_IDD_MFA_SETTINGS)

    # -------------------------------------------------------------------------
    # Users / Groups / Dynamic Groups
    # -------------------------------------------------------------------------
    def list_identity_domain_users(self) -> list[dict[str, Any]]:
        attrs = (
            "displayName,userName,emails,id,ocid,schemas,meta,"
            "domainOcid,compartmentOcid,tenancyOcid,matchingRule,groups"
        )
        rows = self.identity_domain_client.list_users(attributes=attrs)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_users(self, idd_users: list[dict[str, Any]]) -> None:
        self.session.save_resources(idd_users or [], TABLE_IDD_USERS)

    def list_identity_domain_groups(self) -> list[dict[str, Any]]:
        attrs = (
            "displayName,description,id,ocid,schemas,meta,"
            "domainOcid,compartmentOcid,tenancyOcid,matchingRule,users"
        )
        rows = self.identity_domain_client.list_groups(attributes=attrs)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_groups(self, groups: list[dict[str, Any]]) -> None:
        self.session.save_resources(groups or [], TABLE_IDD_GROUPS)

    def list_identity_domain_dynamic_groups(self) -> list[dict[str, Any]]:
        attrs = (
            "displayName,description,id,ocid,schemas,meta,"
            "domainOcid,compartmentOcid,tenancyOcid,matchingRule"
        )
        rows = self.identity_domain_client.list_dynamic_resource_groups(attributes=attrs)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_dynamic_groups(self, dynamic_groups: list[dict[str, Any]]) -> None:
        self.session.save_resources(dynamic_groups or [], TABLE_IDD_DYNAMIC_GROUPS)

    def save_idd_memberships(self, memberships: list[dict[str, Any]]) -> int:
        """
        Save Identity Domain user-group memberships into the dedicated IDD table
        when present in the local service schema.
        """
        dm = getattr(self.session, "data_master", None)
        cols = []
        try:
            if dm is not None:
                cols = dm._table_columns("service", TABLE_IDD_USER_GROUP_MEMBERSHIPS) or []
        except Exception:
            cols = []
        if not cols:
            return 0
        return int(self.session.save_resources(memberships or [], TABLE_IDD_USER_GROUP_MEMBERSHIPS) or 0)

    # -------------------------------------------------------------------------
    # Apps (SCIM Apps)
    # -------------------------------------------------------------------------
    def list_apps(self, attributes: str | None = None) -> list[dict[str, Any]]:
        kwargs = {}
        attrs = (attributes or "").strip()
        if attrs:
            kwargs["attributes"] = attrs
        rows = self.identity_domain_client.list_apps(**kwargs)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_apps(self, *, apps: list[dict[str, Any]], compartment_id: str) -> dict[str, Any]:
        self.session.save_resources(apps or [], TABLE_IDD_APPS)

    # -------------------------------------------------------------------------
    # App Roles / Grants (SCIM)
    # -------------------------------------------------------------------------
    def list_app_roles(self, *, attributes: str) -> list[dict[str, Any]]:
        rows = self.identity_domain_client.list_app_roles(attributes=attributes)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def list_grants(self, *, attributes: str) -> list[dict[str, Any]]:
        rows = self.identity_domain_client.list_grants(attributes=attributes)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    # -------------------------------------------------------------------------
    # Password Policies (SCIM)
    # -------------------------------------------------------------------------
    def list_password_policies(self, *, attributes: str | None = None) -> list[dict[str, Any]]:
        """
        Returns SCIM PasswordPolicy resources.
        We use list_call_get_all_results for safety; if attributes is unsupported by SDK, caller can retry with None.
        """
        rows = self.identity_domain_client.list_password_policies(attributes=attributes)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_password_policies(self, *, password_policies: list[dict[str, Any]], compartment_id: str) -> dict[str, Any]:
        """
        Save raw SCIM password policy resources to service DB.
        Caller should have already applied domain context (domain_ocid/url/name + compartment_id).
        """
        saved = self.session.save_resources(password_policies or [], TABLE_IDD_PASSWORD_POLICIES)
        return {"saved": saved, "table": TABLE_IDD_PASSWORD_POLICIES}


    # -------------------------------------------------------------------------
    # Helpers used by enum_iam + postproc (keep)
    # -------------------------------------------------------------------------
    @staticmethod
    def approle_display_name(r: dict[str, Any]) -> str:
        return IdentityHelperUtils.safe_str(r.get("display_name") or "")

    @staticmethod
    def grant_grantee_id(g: dict[str, Any]) -> str:
        grantee = g.get("grantee")
        if isinstance(grantee, dict):
            return IdentityHelperUtils.safe_str(grantee.get("value") or "")
        return IdentityHelperUtils.safe_str(g.get("grantee_id") or "")

    @staticmethod
    def grant_approle_id(g: dict[str, Any]) -> str:
        app_role = g.get("app_role")
        if isinstance(app_role, dict):
            return IdentityHelperUtils.safe_str(app_role.get("value") or "")
        return IdentityHelperUtils.safe_str(g.get("app_role_id") or "")

    @staticmethod
    def grant_entitlement_id(g: dict[str, Any]) -> str:
        aeid = g.get("app_entitlement_id")
        if isinstance(aeid, str) and aeid:
            return aeid
        ent = g.get("entitlement")
        if isinstance(ent, dict):
            return IdentityHelperUtils.safe_str(ent.get("value") or "")
        return IdentityHelperUtils.safe_str(g.get("entitlement_id") or "")

    # -------------------------------------------------------------------------
    # DB-save helpers (normalized rows) used by enum_iam / enum_idd_grants
    # -------------------------------------------------------------------------
    def save_idd_app_roles(self, *, app_roles: list[dict[str, Any]], compartment_id: str) -> dict[str, Any]:
        self.session.save_resources(app_roles or [], TABLE_IDD_APP_ROLES)

    def save_idd_grants(self, *, grants: list[dict[str, Any]], compartment_id: str) -> dict[str, Any]:
        self.session.save_resources(grants or [], TABLE_IDD_GRANTS)

    # -------------------------------------------------------------------------
    # API Keys (SCIM ApiKeys)
    # -------------------------------------------------------------------------
    def list_api_keys(self, *, user_id: str | None = None, user_ocid: str | None = None, attributes: str | None = None):
        kwargs = {}

        attrs = (attributes or "").strip()
        if attrs:
            kwargs["attributes"] = attrs

        if user_ocid:
            kwargs["filter"] = f'user.ocid eq "{user_ocid}"'
        elif user_id:
            kwargs["filter"] = f'user.value eq "{user_id}"'
        else:
            raise ValueError('list_api_keys requires user_id or user_ocid (SCIM filter: user.value/user.ocid).')
        
        rows = self.identity_domain_client.list_api_keys(**kwargs)

        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_api_keys(self, *, api_keys: list[dict[str, Any]]) -> None:
        self.session.save_resources(api_keys or [], TABLE_IDD_USER_API_KEYS)

    # -------------------------------------------------------------------------
    # Auth Tokens (SCIM AuthToken)
    # -------------------------------------------------------------------------
    def list_auth_tokens(
        self,
        *,
        user_id: str | None = None,
        user_ocid: str | None = None,
        attributes: str | None = None,
        attribute_sets: list[str] | None = None,
    ):
        kwargs = {}

        attrs = (attributes or "").strip()
        if attrs:
            kwargs["attributes"] = attrs
        if attribute_sets:
            kwargs["attribute_sets"] = [str(x).strip() for x in attribute_sets if str(x).strip()]

        if user_ocid:
            kwargs["filter"] = f'user.ocid eq "{user_ocid}"'
        elif user_id:
            kwargs["filter"] = f'user.value eq "{user_id}"'
        else:
            raise ValueError('list_auth_tokens requires user_id or user_ocid (SCIM filter: user.value/user.ocid).')

        rows = self.identity_domain_client.list_auth_tokens(**kwargs)
        data = oci.util.to_dict(rows.data)
        return data.get("resources", []) or []

    def save_idd_auth_tokens(self, *, auth_tokens: list[dict[str, Any]]) -> None:
        self.session.save_resources(auth_tokens or [], TABLE_IDD_USER_AUTH_TOKENS)


# =============================================================================
# IdentityResourceClient: COMPARTMENTS ONLY
# =============================================================================

class IdentityResourceClient:
    def __init__(
        self,
        *,
        session,
        connect_timeout: int = 5,
        read_timeout: int = 60,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
    ):

        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

        self.client = _init_client(
            oci.identity.IdentityClient,
            session=session,
            service_name="identity",
        )

        try:
            self.client.base_client.timeout = (connect_timeout, read_timeout)
        except Exception:
            pass
        try:
            self.client.retry_strategy = retry_strategy
        except Exception:
            pass



    def is_tenancy_root(self, root: str) -> list[Any]:
        return root.startswith("ocid1.tenancy")

    # compartment_id_in_subtree (bool) – (optional) Default is false. Can only be set to true when performing ListCompartments 
    # on the tenancy (root compartment). When set to true, the hierarchy of compartments is traversed and all compartments 
    # and subcompartments in the tenancy are returned depending on the the setting of accessLevel.
    def list_compartments(self, *, compartment_id: str, lifecycle_state: str, subtree: bool, ) -> list[dict[str, Any]]:
  
        rows = self.client.list_compartments(
            compartment_id=compartment_id,
            compartment_id_in_subtree=subtree,
            sort_by="NAME",
            sort_order="ASC",
            lifecycle_state=lifecycle_state
        )
        output = oci.util.to_dict(rows.data)
        
        return output

    def get_compartment(self, *, compartment_id: str) -> list[dict[str, Any]]:
  
        row = self.client.get_compartment(
            compartment_id=compartment_id
        )
        output = oci.util.to_dict(row.data)
        
        return output

    def save_compartment(self, comp_dict: dict[str, Any]) -> None:

        comp_dict["parent_compartment_id"] = comp_dict.pop("compartment_id", None)
        comp_dict["compartment_id"] = comp_dict.pop("id", None)
        self.session.save_resources([comp_dict], TABLE_COMPARTMENTS)

    def list_identity_domains(self, *, compartment_id: str) -> list[dict[str, Any]]:
        kwargs = {"compartment_id": compartment_id}

        # Prefer paginated helper first, but keep a direct-call fallback
        # because list_domains behavior can vary across SDK/service versions.
        try:
            rows = oci.pagination.list_call_get_all_results(
                self.client.list_domains,
                **kwargs,
            )
            output = oci.util.to_dict(rows.data)
            if isinstance(output, list):
                return output
            if isinstance(output, dict):
                return output.get("items") or output.get("resources") or []
            return []
        except Exception:
            pass

        rows = self.client.list_domains(**kwargs)
        output = oci.util.to_dict(rows.data)
        if isinstance(output, list):
            return output
        if isinstance(output, dict):
            return output.get("items") or output.get("resources") or []
        return []

    def save_domains(self, *, domains: list[dict[str, Any]]) -> int:
        prepared = []
        for d in domains or []:
            if not d.get("compartment_id"):
                d["compartment_id"] = d.get("compartmentId") or getattr(self.session, "compartment_id", None)
            if not d.get("url"):
                d["url"] = d.get("home_region_url")
            if not d.get("id"):
                d["id"] = d.get("ocid")
            if not d.get("compartment_id") or not d.get("url") or not d.get("id"):
                UtilityTools.dlog(bool(self.debug), "skipping domain save; missing PK cols", keys=sorted(d.keys()))
                continue
            prepared.append(d)
        return self.session.save_resources(prepared, TABLE_IDENTITY_DOMAINS)

    def list_users(self, *, compartment_id: str) -> list[dict[str, Any]]:
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_users,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(rows.data)

    def list_groups(self, *, compartment_id: str) -> list[dict[str, Any]]:
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_groups,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(rows.data)

    def list_dynamic_groups(self, *, compartment_id: str) -> list[dict[str, Any]]:
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_dynamic_groups,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(rows.data)

    def list_memberships(self, *, compartment_id: str, user_id: str) -> list[dict[str, Any]]:
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_user_group_memberships,
            compartment_id=compartment_id,
            user_id=user_id,
        )
        return oci.util.to_dict(rows.data)

    def list_policies(self, *, compartment_id: str) -> list[dict[str, Any]]:
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_policies,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(rows.data)

    def save_users(self, users) -> None:
        self.session.save_resources(users or [], TABLE_USERS)

    def save_groups(self, groups) -> None:
        self.session.save_resources(groups or [], TABLE_GROUPS)

    def save_dynamic_groups(self, dynamic_groups) -> None:
        self.session.save_resources(dynamic_groups or [], TABLE_DYNAMIC_GROUPS)

    def save_memberships(self, memberships) -> None:
        self.session.save_resources(memberships or [], TABLE_USER_GROUP_MEMBERSHIPS)

    def save_policies(self, policies) -> None:
        self.session.save_resources(policies or [], TABLE_POLICIES)

    def walk_compartments_bfs(self, *, root_compartment_id: str) -> list[dict[str, Any]]:
        q: deque[str] = deque([root_compartment_id])
        visited: set[str] = set()
        out: list[dict[str, Any]] = []

        while q:
            current = q.popleft()
            if current in visited:
                continue
            visited.add(current)

            try:
                children = self.list_compartments(compartment_id=current, lifecycle_state="ACTIVE", subtree=False)
            except Exception as e:
                print(f"[X] list_compartments failed for {current}: {type(e).__name__}: {e}")
                continue

            out.extend(children)
            for c in children:
                child_id = c.get("id")
                if child_id and child_id not in visited:
                    q.append(str(child_id))

            if self.debug:
                print(f"[*] BFS: visited={len(visited)} queued={len(q)} discovered={len(out)}")

        return out

class IdentityResourceSuite:
    """
    Consolidated Identity wrapper methods used by Enumeration/enum_identity.py.
    All Identity component orchestration lives here (no enum_* utility modules).
    """

    def __init__(self, session):
        self.session = session
        self.debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))
        self._domains_refreshed_this_run = False
        self._runtime_domains: list[dict[str, Any]] = []
        self._domains_refresh_failed = False
        self._domains_refresh_error = ""
        self._domains_refresh_warned = False

    # -------------------------------------------------------------------------
    # Shared small helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _parse_known(parser: argparse.ArgumentParser, user_args) -> argparse.Namespace:
        args, _unknown = parser.parse_known_args(list(user_args))
        return args

    @staticmethod
    def _s(value: Any) -> str:
        if value is None:
            return ""
        return value.strip() if isinstance(value, str) else str(value)

    @staticmethod
    def _print_section(title: str, rows: list[dict[str, Any]], columns: list[str]) -> None:
        print(f"\n[*] {title}")
        if not rows:
            print("[*] None.")
            return
        UtilityTools.print_limited_table(rows, columns, sort_key=None)

    @staticmethod
    def _load_identity_domains_from_db(
        session,
        *,
        compartment_id: str | None = None,
        fallback_to_all: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Load cached identity domains.

        Important:
        - When `compartment_id` is set, default behavior is compartment-strict.
          We do NOT automatically fall back to all cached domains, because that
          causes cross-compartment bleed/overwrites during per-target (A) runs.
        - `fallback_to_all=True` is only for legacy compatibility call sites that
          explicitly want global fallback.
        """
        if not compartment_id:
            return session.get_resource_fields(TABLE_IDENTITY_DOMAINS) or []

        rows = session.get_resource_fields(
            TABLE_IDENTITY_DOMAINS,
            where_conditions={"compartment_id": compartment_id},
        ) or []
        if rows:
            return rows

        if fallback_to_all:
            return session.get_resource_fields(TABLE_IDENTITY_DOMAINS) or []
        return []

    def _print_idd_grouped_by_domain(
        self,
        *,
        title: str,
        rows: list[dict[str, Any]],
        columns: list[str],
        domains: list[dict[str, Any]],
    ) -> None:
        print(f"\n[*] {title}")
        if not rows:
            print("[*] None.")
            return

        domain_label_by_id: dict[str, str] = {}
        ordered_domain_ids: list[str] = []
        for dom in domains or []:
            if not isinstance(dom, dict):
                continue
            dom_id = self._s(dom.get("id"))
            if not dom_id:
                continue
            domain_label_by_id[dom_id] = self._s(dom.get("display_name") or dom.get("name") or dom_id)
            ordered_domain_ids.append(dom_id)

        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            dom_id = self._s(row.get("domain_ocid"))
            grouped.setdefault(dom_id, []).append(row)

        seen: set[str] = set()
        for dom_id in ordered_domain_ids:
            dom_rows = grouped.get(dom_id) or []
            if not dom_rows:
                continue
            seen.add(dom_id)
            dom_name = domain_label_by_id.get(dom_id) or self._s(dom_rows[0].get("identity_domain_name")) or dom_id
            print(f"\n[*] Identity Domain: {dom_name} ({dom_id})")
            UtilityTools.print_limited_table(dom_rows, columns, sort_key=None)

        for dom_id, dom_rows in grouped.items():
            if dom_id in seen:
                continue
            dom_name = self._s(dom_rows[0].get("identity_domain_name")) or dom_id or "<unknown>"
            suffix = f" ({dom_id})" if dom_id else ""
            print(f"\n[*] Identity Domain: {dom_name}{suffix}")
            UtilityTools.print_limited_table(dom_rows, columns, sort_key=None)

    def _load_domains_from_cache(
        self,
        *,
        all_saved_domains: bool = False,
        domain_filter: str = "",
    ) -> tuple[str, list[dict[str, Any]], str]:
        compartment_id = getattr(self.session, "compartment_id", None)
        if not all_saved_domains and not isinstance(compartment_id, str):
            compartment_id = ""

        source = "db"
        if all_saved_domains:
            domains = self._load_identity_domains_from_db(self.session, compartment_id=None)
        elif self._domains_refreshed_this_run:
            source = "current_run"
            domains = list(self._runtime_domains or [])
            if compartment_id:
                domains = [d for d in domains if self._s(d.get("compartment_id")) == compartment_id]
        else:
            domains = self._load_identity_domains_from_db(self.session, compartment_id=compartment_id or None)
            if self._domains_refresh_failed and not self._domains_refresh_warned:
                err = self._domains_refresh_error or "unknown error"
                print(
                    f"{UtilityTools.YELLOW}[!] Live identity-domain refresh failed earlier; "
                    f"using DB cache for remaining IDD components. Error: {err}{UtilityTools.RESET}"
                )
                self._domains_refresh_warned = True
        domains = [d for d in (domains or []) if isinstance(d, dict)]
        if domain_filter:
            domains = [d for d in domains if domain_matches(d, domain_filter)]
        return (compartment_id or "", domains, source)

    def _active_user_ocid(self) -> str:
        creds = getattr(self.session, "credentials", None)
        if isinstance(creds, dict):
            direct = self._s(creds.get("user") or creds.get("user_ocid"))
            if direct:
                return direct
            cfg = creds.get("config") if isinstance(creds.get("config"), dict) else {}
            return self._s(cfg.get("user"))
        return ""

    def _persist_active_cred_identity_domain(self, idd_users: list[dict[str, Any]]) -> None:
        """
        If the active credential's user OCID matches an IDD user discovered this run,
        persist identity-domain context onto the stored credential profile.
        """
        try:
            user_ocid = self._active_user_ocid()
            if not user_ocid:
                return
            row = next(
                (
                    r for r in (idd_users or [])
                    if isinstance(r, dict) and self._s(r.get("ocid")) == user_ocid
                ),
                None,
            )
            if not isinstance(row, dict):
                return

            credname = self._s(getattr(self.session, "credname", ""))
            if not credname:
                return

            self.session.update_cred_session_metadata(
                credname,
                {
                    "identity_domain_ocid": self._s(row.get("domain_ocid")),
                    "identity_domain_name": self._s(row.get("identity_domain_name")),
                },
            )
        except Exception:
            return

    @staticmethod
    def _extract_link(obj: Any) -> dict[str, str]:
        if not isinstance(obj, dict):
            text = IdentityResourceSuite._s(obj)
            return {"id": text, "name": text, "ref": "", "type": ""}
        return {
            "id": IdentityResourceSuite._s(obj.get("value") or obj.get("id") or obj.get("ocid")),
            "name": IdentityResourceSuite._s(obj.get("display") or obj.get("display_name") or obj.get("name")),
            "ref": IdentityResourceSuite._s(obj.get("ref") or obj.get("$ref")),
            "type": IdentityResourceSuite._s(obj.get("type")),
        }

    @staticmethod
    def _extract_entitlement(obj: Any) -> dict[str, str]:
        if not isinstance(obj, dict):
            text = IdentityResourceSuite._s(obj)
            return {"id": text, "name": text, "ref": "", "attribute_name": "", "attribute_value": ""}
        attr_name = IdentityResourceSuite._s(obj.get("attribute_name") or obj.get("attributeName"))
        attr_value = IdentityResourceSuite._s(obj.get("attribute_value") or obj.get("attributeValue"))
        ent_id = IdentityResourceSuite._s(obj.get("value") or obj.get("id") or attr_value)
        ent_name = IdentityResourceSuite._s(obj.get("display") or obj.get("display_name") or obj.get("name") or ent_id)
        return {
            "id": ent_id,
            "name": ent_name,
            "ref": IdentityResourceSuite._s(obj.get("ref") or obj.get("$ref")),
            "attribute_name": attr_name,
            "attribute_value": attr_value,
        }

    @staticmethod
    def _summary_name_id(name: str, ident: str) -> str:
        n = IdentityResourceSuite._s(name)
        i = IdentityResourceSuite._s(ident)
        if n and i and n != i:
            return f"{n} ({i})"
        return n or i

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
            except Exception:
                return []
            return parsed if isinstance(parsed, list) else []
        return []

    def _extract_idd_memberships_from_users(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for user in users or []:
            if not isinstance(user, dict):
                continue
            user_ocid = self._s(user.get("ocid"))
            if not user_ocid:
                continue
            user_scim_id = self._s(user.get("id"))
            user_name = self._s(user.get("user_name") or user.get("userName"))

            for gref in self._as_list(user.get("groups")):
                if not isinstance(gref, dict):
                    continue
                group_ocid = self._s(gref.get("ocid"))
                if not group_ocid:
                    continue
                membership_ocid = self._s(gref.get("membership_ocid") or gref.get("membershipOcid") or gref.get("id"))
                row_id = membership_ocid or f"{user_ocid}::{group_ocid}"
                group_scim_id = self._s(gref.get("value") or gref.get("id"))
                group_name = self._s(
                    gref.get("display")
                    or gref.get("display_name")
                    or gref.get("name")
                    or gref.get("non_unique_display")
                )

                rows.append(
                    {
                        "id": row_id,
                        "membership_ocid": membership_ocid or row_id,
                        "user_id": user_ocid,  # keep OCID in user_id for graph compatibility
                        "group_id": group_ocid,  # keep OCID in group_id for graph compatibility
                        "user_ocid": user_ocid,
                        "group_ocid": group_ocid,
                        "user_scim_id": user_scim_id,
                        "group_scim_id": group_scim_id,
                        "user_name": user_name,
                        "group_name": group_name,
                        "domain_ocid": self._s(user.get("domain_ocid")),
                        "identity_domain_name": self._s(user.get("identity_domain_name")),
                        "identity_domain_url": self._s(user.get("identity_domain_url")),
                        "compartment_ocid": self._s(user.get("compartment_ocid")),
                        "compartment_id": self._s(user.get("compartment_id") or user.get("compartment_ocid")),
                        "tenancy_ocid": self._s(user.get("tenancy_ocid")),
                        "inactive_status": self._s(gref.get("inactive_status")),
                        "source": "idd_user_groups",
                    }
                )
        return IdentityHelperUtils.dedupe_by_key(rows, "id")

    def _build_principal_name_lookup(self, *, domain_ocid: str) -> dict[str, str]:
        lookup: dict[str, str] = {}
        tables = (
            ("identity_domain_users", ("display_name", "user_name")),
            ("identity_domain_groups", ("display_name", "name")),
            ("identity_domain_dynamic_groups", ("display_name", "name")),
        )
        for table_name, name_keys in tables:
            rows = self.session.get_resource_fields(table_name, where_conditions={"domain_ocid": domain_ocid}) or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                label = ""
                for key in name_keys:
                    label = self._s(row.get(key))
                    if label:
                        break
                if not label:
                    continue
                rid = self._s(row.get("id"))
                rocid = self._s(row.get("ocid"))
                if rid:
                    lookup[rid] = label
                if rocid:
                    lookup[rocid] = label
        return lookup

    def _normalize_grant_row(self, grant: dict[str, Any], *, principal_lookup: dict[str, str]) -> dict[str, Any]:
        row = dict(grant or {})

        grant_mechanism = self._s(row.get("grant_mechanism") or row.get("grantMechanism"))
        app_entitlement_id = self._s(row.get("app_entitlement_id") or row.get("appEntitlementId"))

        grantee_obj = row.get("grantee")
        grantor_obj = row.get("grantor")
        app_obj = row.get("app")
        app_role_obj = row.get("app_role") or row.get("appRole")
        entitlement_obj = row.get("entitlement")

        grantee = self._extract_link(grantee_obj)
        grantor = self._extract_link(grantor_obj)
        app = self._extract_link(app_obj)
        app_role = self._extract_link(app_role_obj)
        entitlement = self._extract_entitlement(entitlement_obj)

        if not grantee["name"] and grantee["id"]:
            grantee["name"] = principal_lookup.get(grantee["id"], "")
        if not app_entitlement_id:
            app_entitlement_id = entitlement["attribute_value"]

        row["grant_mechanism"] = grant_mechanism
        row["active"] = row.get("active")
        row["app_entitlement_id"] = app_entitlement_id

        row["grantee_id"] = grantee["id"]
        row["grantee_name"] = grantee["name"] or grantee["id"]
        row["grantee_ref"] = grantee["ref"]
        row["grantee_type"] = grantee["type"]

        row["grantor_id"] = grantor["id"]
        row["grantor_name"] = grantor["name"] or grantor["id"]
        row["grantor_ref"] = grantor["ref"]
        row["grantor_type"] = grantor["type"]

        row["app_id"] = app["id"]
        row["app_name"] = app["name"] or app["id"]
        row["app_ref"] = app["ref"]

        row["app_role_id"] = app_role["id"]
        row["app_role_name"] = app_role["name"] or app_role["id"]
        row["app_role_ref"] = app_role["ref"]

        row["entitlement_id"] = entitlement["id"]
        row["entitlement_name"] = entitlement["name"] or entitlement["id"]
        row["entitlement_ref"] = entitlement["ref"]
        row["entitlement_attribute_name"] = entitlement["attribute_name"]
        row["entitlement_attribute_value"] = entitlement["attribute_value"]

        row["grantee"] = row["grantee_name"]
        row["grantor"] = row["grantor_name"]
        row["app"] = row["app_name"]
        row["app_role"] = row["app_role_name"]
        row["entitlement"] = row["entitlement_name"]

        row["grantor_summary"] = self._summary_name_id(row["grantor_name"], row["grantor_id"])
        row["grantee_summary"] = self._summary_name_id(row["grantee_name"], row["grantee_id"])
        app_summary = self._summary_name_id(row["app_name"], row["app_id"]) or "app:<unknown>"
        role_summary = self._summary_name_id(row["app_role_name"], row["app_role_id"])
        ent_summary = self._summary_name_id(row["entitlement_name"], row["entitlement_id"])
        if not ent_summary:
            ent_summary = self._s(row.get("app_entitlement_id"))
        if role_summary:
            row["granted_summary"] = f"{app_summary} | role={role_summary} | ent={ent_summary or '<none>'}"
        else:
            row["granted_summary"] = f"{app_summary} | ent={ent_summary or '<none>'}"

        row["grantee_raw_json"] = IdentityHelperUtils.json_blob(grantee_obj)
        row["grantor_raw_json"] = IdentityHelperUtils.json_blob(grantor_obj)
        row["app_raw_json"] = IdentityHelperUtils.json_blob(app_obj)
        row["app_role_raw_json"] = IdentityHelperUtils.json_blob(app_role_obj)
        row["entitlement_raw_json"] = IdentityHelperUtils.json_blob(entitlement_obj)

        if not self._s(row.get("composite_key")):
            row["composite_key"] = "|".join(
                [
                    self._s(row.get("domain_ocid")),
                    row["grantee_id"],
                    row["app_id"],
                    row["app_role_id"],
                    row["entitlement_id"],
                    row["app_entitlement_id"],
                ]
            ).strip("|")
        return row

    @staticmethod
    def _token_preview(token_value: str) -> str:
        tok = str(token_value or "")
        if not tok:
            return ""
        if len(tok) <= 8:
            return "*" * len(tok)
        return f"{tok[:4]}...{tok[-4:]}"

    @staticmethod
    def _token_id(user_ocid: str, token_name: str, token_hint: str, fallback_id: str) -> str:
        fid = str(fallback_id or "").strip()
        if fid:
            return fid
        material = f"{user_ocid}|{token_name}|{token_hint}".encode("utf-8", errors="ignore")
        return hashlib.sha256(material).hexdigest()[:40]

    def _normalize_auth_token_row(
        self,
        token_row: dict[str, Any],
        user_row: dict[str, Any],
        dom: dict[str, Any],
        source: str,
    ) -> dict[str, Any]:
        out = dict(token_row or {})
        user_obj = out.get("user") if isinstance(out.get("user"), dict) else {}
        user_ocid = self._s(user_obj.get("ocid") or user_row.get("ocid") or out.get("user_ocid"))
        username = self._s(
            out.get("username")
            or user_obj.get("display")
            or user_row.get("user_name")
            or user_row.get("display_name")
        )
        token_name = self._s(out.get("token_name") or out.get("description") or out.get("name")) or "auth-token"
        token_hint = self._s(out.get("token"))

        out["token_id"] = self._token_id(user_ocid, token_name, token_hint, self._s(out.get("id")))
        out["token_name"] = token_name
        out["username"] = username
        out["token_preview"] = self._token_preview(token_hint)
        out["token_value"] = self._s(out.get("token_value"))
        out["source"] = self._s(out.get("source")) or source
        out["region"] = self._s(out.get("region") or getattr(self.session, "region", ""))
        out["tenancy_namespace"] = self._s(out.get("tenancy_namespace"))
        out["domain_ocid"] = self._s(out.get("domain_ocid") or dom.get("id"))
        out["user_ocid"] = user_ocid
        out["compartment_id"] = self._s(
            out.get("compartment_id")
            or dom.get("compartment_id")
            or dom.get("compartmentId")
            or getattr(self.session, "compartment_id", "")
        )
        if not self._s(out.get("created_at_utc")):
            out["created_at_utc"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        out["updated_at_utc"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        return out

    # -------------------------------------------------------------------------
    # Domains
    # -------------------------------------------------------------------------
    def _run_domains(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domains from current compartment (IdentityClient.list_domains).",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save domains to local DB")
        parser.add_argument("--domain", required=False, help="Filter by substring in id/display_name/url")
        args = self._parse_known(parser, user_args)
        save = bool(args.save)
        self._domains_refresh_failed = False
        self._domains_refresh_error = ""
        self._domains_refresh_warned = False

        compartment_id = getattr(self.session, "compartment_id", None)
        if not isinstance(compartment_id, str) or not compartment_id:
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate domains.{UtilityTools.RESET}")
            return {"ok": False, "domains": 0}

        ops = IdentityResourceClient(session=self.session)
        try:
            domains = ops.list_identity_domains(compartment_id=compartment_id) or []
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            self._domains_refresh_failed = True
            self._domains_refresh_error = err
            print(
                f"{UtilityTools.RED}[X] enum_domains live call failed: {err}{UtilityTools.RESET}\n"
                f"{UtilityTools.YELLOW}[*] Continuing with DB cache for downstream IDD components.{UtilityTools.RESET}"
            )
            UtilityTools.dlog(self.debug, "enum_domains: list_identity_domains failed", err=err)
            return {"ok": False, "domains": 0}

        if args.domain:
            token = str(args.domain).lower()
            domains = [
                d for d in domains
                if token in str(d.get("id", "")).lower()
                or token in str(d.get("display_name", "")).lower()
                or token in str(d.get("url", "")).lower()
            ]

        normalized_domains: list[dict[str, Any]] = []
        for d in domains:
            if not isinstance(d, dict):
                continue
            row = dict(d)
            row["compartment_id"] = self._s(
                row.get("compartment_id") or row.get("compartmentId") or compartment_id
            )
            normalized_domains.append(row)

        self._domains_refreshed_this_run = True
        self._runtime_domains = normalized_domains

        if not normalized_domains:
            print("[*] No identity domains found.")
            return {"ok": True, "domains": 0, "saved": False}

        UtilityTools.print_limited_table(normalized_domains, ["id", "display_name", "url", "home_region"])

        if save:
            try:
                saved = ops.save_domains(domains=normalized_domains)
                UtilityTools.dlog(self.debug, "enum_domains: saved domains", saved=saved, table=TABLE_IDENTITY_DOMAINS)
            except Exception as e:
                UtilityTools.dlog(self.debug, "enum_domains: save_domains failed", err=f"{type(e).__name__}: {e}")

        print(f"\n[*] enum_domains complete. Domains: {len(normalized_domains)}")
        return {"ok": True, "domains": len(normalized_domains), "saved": bool(save)}

    # -------------------------------------------------------------------------
    # IAM policies
    # -------------------------------------------------------------------------
    def _run_iam(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate OCI IAM: classic IAM policies.",
            allow_abbrev=False,
        )
        parser.add_argument("--proxy", required=False, help="Proxy address (e.g., http://127.0.0.1:8080)")
        parser.add_argument("-v", "--debug", action="store_true", help="Verbose debug output")
        parser.add_argument("--save", action="store_true", help="Save results into DB (service tables)")
        parser.add_argument("--iam-policies", action="store_true", help="Enumerate classic IAM policies")
        args = self._parse_known(parser, user_args)

        debug = bool(self.debug or getattr(args, "debug", False))
        save = bool(getattr(args, "save", False))

        if getattr(args, "proxy", None):
            try:
                self.session.individual_run_proxy = args.proxy
            except Exception:
                pass

        compartment_id = getattr(self.session, "compartment_id", None)
        if not isinstance(compartment_id, str) or not compartment_id:
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate IAM.{UtilityTools.RESET}")
            return {"ok": False, "iam": 0}

        ops = IdentityResourceClient(session=self.session)
        try:
            policies = ops.list_policies(compartment_id=compartment_id) or []
        except Exception as e:
            UtilityTools.dlog(debug, "enum_iam: list_policies failed", err=f"{type(e).__name__}: {e}")
            return {"ok": False, "iam": 0}

        UtilityTools.print_limited_table(policies, ["id", "name", "lifecycle_state"], sort_key=None)
        if save:
            try:
                ops.save_policies(policies)
            except Exception as e:
                UtilityTools.dlog(debug, "enum_iam: save_policies failed", err=f"{type(e).__name__}: {e}")
                return {"ok": False, "iam": 0}
        return {"ok": True, "iam": len(policies), "saved": bool(save)}

    # -------------------------------------------------------------------------
    # Principals
    # -------------------------------------------------------------------------
    def _run_principals(self, user_args):
        parser = argparse.ArgumentParser(
            description=(
                "Enumerate OCI principals.\n"
                "Default (no lane flags): enumerate Identity Domain (IDD) principals first, "
                "then classic principals; do NOT save classic duplicates if already seen in IDD."
            ),
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save results into DB (service tables).")
        lane = parser.add_mutually_exclusive_group()
        lane.add_argument("--idd", "--idd-only", dest="idd_only", action="store_true", help="Enumerate Identity Domain principals only.")
        lane.add_argument("--classic", "--classic-only", dest="classic_only", action="store_true", help="Enumerate classic principals only.")
        parser.add_argument("--domain-filter", help="Filter identity domains by substring (id/display_name/url).")
        parser.add_argument(
            "--domains",
            action="extend",
            nargs="+",
            type=lambda s: [x.strip() for x in str(s).split(",") if x.strip()],
            help="Comma-separated list of Identity Domain service endpoints.",
        )
        parser.add_argument("--users", action="store_true", help="Enumerate users (default if no selectors).")
        parser.add_argument("--groups", action="store_true", help="Enumerate groups (default if no selectors).")
        parser.add_argument("--dynamic-groups", action="store_true", help="Enumerate dynamic groups (default if no selectors).")
        parser.add_argument("--memberships", action="store_true", help="Enumerate user-group memberships.")
        args = self._parse_known(parser, user_args)

        save = bool(args.save)
        compartment_id = getattr(self.session, "compartment_id", None)
        if not isinstance(compartment_id, str) or not compartment_id:
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate principals.{UtilityTools.RESET}")
            return {"ok": False, "principals": 0}

        want_any_selector = bool(args.users or args.groups or args.dynamic_groups or args.memberships)
        want_users = bool(args.users) or not want_any_selector
        want_groups = bool(args.groups) or not want_any_selector
        want_dgs = bool(args.dynamic_groups) or not want_any_selector
        # Memberships are always attempted for principals enumeration to maximize graph fidelity.
        want_memberships = True

        no_lane_flags = not (args.idd_only or args.classic_only)
        do_idd = bool(args.idd_only or no_lane_flags)
        do_classic = bool(args.classic_only or no_lane_flags)

        classic_ops = IdentityResourceClient(session=self.session)
        idd_seen: set[str] = set()

        # Resolve identity domain endpoints from args or DB.
        domain_endpoints: list[str] = args.domains or []
        domains: list[dict[str, Any]] = []
        if do_idd and not domain_endpoints:
            _comp, domains, domain_source = self._load_domains_from_cache(
                all_saved_domains=False,
                domain_filter=args.domain_filter or "",
            )
            domain_endpoints = [self._s(d.get("url")) for d in domains if self._s(d.get("url"))]
            if domains:
                source_label = "current run" if domain_source == "current_run" else "DB cache"
                self._print_section(f"Identity Domains ({source_label})", domains, ["id", "display_name", "url", "home_region"])

        idd_users: list[dict[str, Any]] = []
        idd_groups: list[dict[str, Any]] = []
        idd_dynamic_groups: list[dict[str, Any]] = []
        idd_memberships: list[dict[str, Any]] = []

        if do_idd and not domain_endpoints:
            print("[*] No identity domains available skipping...")

        if do_idd:
            for domain_url in domain_endpoints:
                idd_ops = IdentityDomainResourceClient(session=self.session, service_endpoint=domain_url)
                dom_match = next((d for d in domains if self._s(d.get("url")) == self._s(domain_url)), {})
                dom_id = self._s(dom_match.get("id"))
                dom_name = self._s(dom_match.get("display_name") or dom_match.get("name"))
                dom_compartment_id = self._s(
                    dom_match.get("compartment_id") or dom_match.get("compartmentId") or compartment_id
                )

                if want_users or want_memberships:
                    try:
                        rows = [IdentityHelperUtils.normalize_idd_user(u) for u in (idd_ops.list_identity_domain_users() or []) if isinstance(u, dict)]
                        for r in rows:
                            idd_ops.apply_domain_context(
                                r,
                                domain_id=dom_id,
                                domain_name=dom_name,
                                domain_url=domain_url,
                                compartment_id=dom_compartment_id,
                            )
                        if want_users:
                            idd_users.extend(rows)
                            if save and rows:
                                idd_ops.save_idd_users(rows)
                        if want_memberships:
                            mrows = self._extract_idd_memberships_from_users(rows)
                            if mrows:
                                idd_memberships.extend(mrows)
                                if save:
                                    # Dedicated IDD table (if present in local schema).
                                    idd_ops.save_idd_memberships(mrows)
                                    # Compatibility table used by OpenGraph Phase B.
                                    classic_ops.save_memberships(memberships=mrows)
                    except Exception as e:
                        UtilityTools.dlog(
                            self.debug,
                            "enum_principals: IDD users/memberships failed",
                            domain_url=domain_url,
                            err=f"{type(e).__name__}: {e}",
                        )

                if want_groups:
                    try:
                        rows = [IdentityHelperUtils.normalize_idd_group(g) for g in (idd_ops.list_identity_domain_groups() or []) if isinstance(g, dict)]
                        for r in rows:
                            idd_ops.apply_domain_context(
                                r,
                                domain_id=dom_id,
                                domain_name=dom_name,
                                domain_url=domain_url,
                                compartment_id=dom_compartment_id,
                            )
                        idd_groups.extend(rows)
                        if save and rows:
                            idd_ops.save_idd_groups(rows)
                    except Exception as e:
                        UtilityTools.dlog(self.debug, "enum_principals: IDD groups failed", domain_url=domain_url, err=f"{type(e).__name__}: {e}")

                if want_dgs:
                    try:
                        rows = [g for g in (idd_ops.list_identity_domain_dynamic_groups() or []) if isinstance(g, dict)]
                        for r in rows:
                            idd_ops.apply_domain_context(
                                r,
                                domain_id=dom_id,
                                domain_name=dom_name,
                                domain_url=domain_url,
                                compartment_id=dom_compartment_id,
                            )
                        idd_dynamic_groups.extend(rows)
                        if save and rows:
                            idd_ops.save_idd_dynamic_groups(rows)
                    except Exception as e:
                        UtilityTools.dlog(self.debug, "enum_principals: IDD dynamic groups failed", domain_url=domain_url, err=f"{type(e).__name__}: {e}")

        for r in (idd_users + idd_groups + idd_dynamic_groups):
            rid = self._s(r.get("id"))
            rocid = self._s(r.get("ocid"))
            if rid:
                idd_seen.add(rid)
            if rocid:
                idd_seen.add(rocid)

        if do_idd:
            if want_users:
                self._print_idd_grouped_by_domain(
                    title="IDD Users",
                    rows=IdentityHelperUtils.dedupe_by_key(idd_users, "id"),
                    columns=["id", "ocid", "user_name", "display_name", "domain_ocid", "identity_domain_name"],
                    domains=domains,
                )
                self._persist_active_cred_identity_domain(IdentityHelperUtils.dedupe_by_key(idd_users, "id"))
            if want_groups:
                self._print_section(
                    "IDD Groups",
                    IdentityHelperUtils.dedupe_by_key(idd_groups, "id"),
                    ["id", "ocid", "name", "display_name", "domain_ocid", "identity_domain_name"],
                )
            if want_dgs:
                self._print_section(
                    "IDD Dynamic Groups",
                    IdentityHelperUtils.dedupe_by_key(idd_dynamic_groups, "id"),
                    ["id", "ocid", "name", "display_name", "domain_ocid", "identity_domain_name", "matching_rule"],
                )
            if want_memberships:
                self._print_idd_grouped_by_domain(
                    title="IDD User-Group Memberships",
                    rows=IdentityHelperUtils.dedupe_by_key(idd_memberships, "id"),
                    columns=[
                        "id",
                        "user_id",
                        "group_id",
                        "domain_ocid",
                        "identity_domain_name",
                    ],
                    domains=domains,
                )

        classic_users: list[dict[str, Any]] = []
        classic_groups: list[dict[str, Any]] = []
        classic_dynamic_groups: list[dict[str, Any]] = []
        classic_memberships: list[dict[str, Any]] = []

        if do_classic:
            if want_users:
                try:
                    classic_users = classic_ops.list_users(compartment_id=compartment_id) or []
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_principals: classic users failed", err=f"{type(e).__name__}: {e}")
            if want_groups:
                try:
                    classic_groups = classic_ops.list_groups(compartment_id=compartment_id) or []
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_principals: classic groups failed", err=f"{type(e).__name__}: {e}")
            if want_dgs:
                try:
                    classic_dynamic_groups = classic_ops.list_dynamic_groups(compartment_id=compartment_id) or []
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_principals: classic dynamic groups failed", err=f"{type(e).__name__}: {e}")
            if want_memberships:
                try:
                    users_for_memberships = classic_users
                    if not users_for_memberships:
                        users_for_memberships = classic_ops.list_users(compartment_id=compartment_id) or []
                    for user in users_for_memberships:
                        user_id = self._s(user.get("id"))
                        if not user_id:
                            continue
                        rows = classic_ops.list_memberships(compartment_id=compartment_id, user_id=user_id) or []
                        for row in rows:
                            if not isinstance(row, dict):
                                continue
                            norm = dict(row)
                            norm["membership_id"] = self._s(norm.get("membership_id") or norm.get("id"))
                            norm.pop("membership_ocid", None)
                            norm.setdefault("user_name", self._s(user.get("name")))
                            norm.setdefault("tenancy_ocid", self._s(getattr(self.session, "tenant_id", None)))
                            classic_memberships.append(norm)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_principals: classic memberships failed", err=f"{type(e).__name__}: {e}")

            # Save classic with dedupe if IDD also enumerated.
            if save:
                dedupe_active = bool(idd_seen) and not args.classic_only

                def _filter_dupes(rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
                    if not dedupe_active:
                        return rows
                    out: list[dict[str, Any]] = []
                    for row in rows or []:
                        matched = False
                        for key in keys:
                            value = self._s(row.get(key))
                            if value and value in idd_seen:
                                matched = True
                                break
                        if not matched:
                            out.append(row)
                    return out

                filtered_users = _filter_dupes(classic_users, ["id", "ocid"])
                filtered_groups = _filter_dupes(classic_groups, ["id", "ocid"])
                filtered_dgs = _filter_dupes(classic_dynamic_groups, ["id", "ocid"])

                if filtered_users:
                    classic_ops.save_users(users=filtered_users)
                if filtered_groups:
                    classic_ops.save_groups(groups=filtered_groups)
                if filtered_dgs:
                    classic_ops.save_dynamic_groups(dynamic_groups=filtered_dgs)
                if classic_memberships:
                    classic_ops.save_memberships(memberships=classic_memberships)

                classic_users = filtered_users
                classic_groups = filtered_groups
                classic_dynamic_groups = filtered_dgs

        if do_classic:
            if want_users:
                self._print_section("Classic Users", classic_users, ["id", "name", "email", "lifecycle_state"])
            if want_groups:
                self._print_section("Classic Groups", classic_groups, ["id", "name", "lifecycle_state"])
            if want_dgs:
                self._print_section("Classic Dynamic Groups", classic_dynamic_groups, ["id", "name", "lifecycle_state", "matching_rule"])
            if want_memberships:
                self._print_section("Classic User-Group Memberships", classic_memberships, ["user_id", "group_id", "lifecycle_state"])

        print(
            f"\n[*] enum_principals complete."
            f" IDD: users={len(idd_users)} groups={len(idd_groups)} dgs={len(idd_dynamic_groups)} memberships={len(idd_memberships)}"
            f" | Classic: users={len(classic_users)} groups={len(classic_groups)} dgs={len(classic_dynamic_groups)} memberships={len(classic_memberships)}"
        )

        return {
            "ok": True,
            "idd_users": len(idd_users),
            "idd_groups": len(idd_groups),
            "idd_dynamic_groups": len(idd_dynamic_groups),
            "idd_memberships": len(idd_memberships),
            "classic_users": len(classic_users),
            "classic_groups": len(classic_groups),
            "classic_dynamic_groups": len(classic_dynamic_groups),
            "classic_memberships": len(classic_memberships),
            "saved": bool(save),
        }

    # -------------------------------------------------------------------------
    # Identity Domain apps
    # -------------------------------------------------------------------------
    def _run_idd_apps(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain Applications (SCIM Apps) for each saved Identity Domain.",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save apps to DB")
        parser.add_argument("--domain", required=False, help="Filter domains by substring (id/name/url/display_name).")
        parser.add_argument("--get", action="store_true", help="Reserved.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not isinstance(compartment_id, str) or not compartment_id:
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate apps.{UtilityTools.RESET}")
            return {"ok": False, "apps": 0}

        _comp_id, domains, domain_source = self._load_domains_from_cache(all_saved_domains=False, domain_filter=args.domain or "")
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in table '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then re-run: modules run enum_identity --idd-apps --save (optional)"
            )
            return {"ok": False, "apps": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB cache'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"])

        total_apps = 0
        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            try:
                apps = [a for a in (ops.list_apps() or []) if isinstance(a, dict)]
            except Exception as e:
                UtilityTools.dlog(self.debug, "enum_idd_apps: list_apps failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                continue

            total_apps += len(apps)
            for app in apps:
                ops.apply_domain_context(
                    app,
                    domain_id=dom_id,
                    domain_name=dom_name,
                    domain_url=dom_url,
                    compartment_id=dom_compartment_id,
                )

            if args.save and apps:
                try:
                    ops.save_idd_apps(apps=apps, compartment_id=dom_compartment_id)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_apps: save_idd_apps failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

            print(f"\n[*] Apps for Domain: {dom_name or dom_id}")
            UtilityTools.print_limited_table(apps, ["domain_ocid", "id", "display_name", "active"], sort_key="display_name")

        print(f"\n[*] enum_idd_apps complete. Domains: {len(domains)} | Apps: {total_apps}")
        return {"ok": True, "apps": int(total_apps), "saved": bool(args.save)}

    # -------------------------------------------------------------------------
    # Identity Domain app roles
    # -------------------------------------------------------------------------
    def _run_idd_app_roles(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain App Roles (SCIM) using Identity Domains cached in DB.",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save app roles to DB.")
        parser.add_argument("--domain", required=False, help="Filter domains by id/name/url substring.")
        parser.add_argument("--attributes", required=False, help="Override SCIM attributes list for list_app_roles().")
        parser.add_argument("--limit", type=int, default=200, help="Max rows to print per domain.")
        parser.add_argument("--sort", default="displayName", help="Sort key.")
        parser.add_argument("--reverse", action="store_true", help="Reverse sort order.")
        parser.add_argument("--all-compartments", action="store_true", help="Do not scope domains by session.compartment_id.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not isinstance(compartment_id, str) or not compartment_id:
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set{UtilityTools.RESET}")
            return {"ok": False, "app_roles": 0}

        scope_all = bool(args.all_compartments)
        _comp, domains, domain_source = self._load_domains_from_cache(
            all_saved_domains=scope_all,
            domain_filter=args.domain or "",
        )
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then rerun this module."
            )
            return {"ok": False, "app_roles": 0}

        if not scope_all:
            domains = [d for d in domains if self._s(d.get("compartment_id")) == compartment_id]
        if not domains:
            print("[*] No identity domains matched scope/filter.")
            return {"ok": True, "app_roles": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"], max_rows=200, truncate=140)

        attrs = args.attributes or "id,ocid,name,displayName,description,active,app,adminRole,members,schemas,meta"
        total_roles = 0
        domains_touched = 0

        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            domains_touched += 1
            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            try:
                app_roles = [r for r in (ops.list_app_roles(attributes=attrs) or []) if isinstance(r, dict)]
            except Exception as e:
                UtilityTools.dlog(self.debug, "enum_idd_app_roles: list_app_roles failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                continue

            total_roles += len(app_roles)
            for row in app_roles:
                ops.apply_domain_context(
                    row,
                    domain_id=dom_id,
                    domain_name=dom_name,
                    domain_url=dom_url,
                    compartment_id=dom_compartment_id,
                )
                app_val = row.get("app")
                if isinstance(app_val, dict):
                    row["app"] = app_val.get("display") or app_val.get("value") or app_val.get("id") or ""
                elif app_val is None:
                    row["app"] = ""
                else:
                    row["app"] = str(app_val)

            print(f"\n[*] App Roles — {dom_name or dom_id} ({len(app_roles)})")
            UtilityTools.print_limited_table(
                app_roles,
                ["domain_ocid", "ocid", "display_name", "app", "admin_role"],
                sort_key=args.sort,
                reverse=bool(args.reverse),
                max_rows=max(1, int(args.limit)),
                truncate=140,
            )

            if args.save and app_roles:
                try:
                    ops.save_idd_app_roles(app_roles=app_roles, compartment_id=dom_compartment_id)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_app_roles: save_idd_app_roles failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

        print(f"\n[*] enum_idd_app_roles complete. Domains: {domains_touched} | AppRoles: {total_roles}")
        return {"ok": True, "app_roles": int(total_roles), "saved": bool(args.save)}

    # -------------------------------------------------------------------------
    # Identity Domain API keys
    # -------------------------------------------------------------------------
    def _run_idd_api_keys(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain API Keys (SCIM ApiKeys) for saved Identity Domains.",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save API keys to DB.")
        parser.add_argument("--domain", required=False, help="Filter domains by substring.")
        parser.add_argument("--attributes", required=False, help="Override SCIM attributes list for list_api_keys().")
        parser.add_argument("--all-saved-domains", action="store_true", help="Use all saved domains.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not args.all_saved_domains and (not isinstance(compartment_id, str) or not compartment_id):
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate IDD API keys.{UtilityTools.RESET}")
            return {"ok": False, "api_keys": 0}

        _comp, domains, domain_source = self._load_domains_from_cache(
            all_saved_domains=bool(args.all_saved_domains),
            domain_filter=args.domain or "",
        )
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in table '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then re-run: modules run enum_identity --idd-api-keys --save (optional)"
            )
            return {"ok": False, "api_keys": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB cache'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"])

        attrs = args.attributes or None
        total = 0
        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            users = self.session.get_resource_fields(TABLE_IDD_USERS, where_conditions={"domain_ocid": dom_id}) or []
            users = [u for u in users if isinstance(u, dict)]
            if not users:
                continue

            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            keys: list[dict[str, Any]] = []
            for user in users:
                try:
                    rows = [r for r in (ops.list_api_keys(user_ocid=user.get("ocid"), attributes=attrs) or []) if isinstance(r, dict)]
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_api_keys: list_api_keys failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                    continue
                for row in rows:
                    ops.apply_domain_context(
                        row,
                        domain_id=dom_id,
                        domain_name=dom_name,
                        domain_url=dom_url,
                        compartment_id=dom_compartment_id,
                    )
                keys.extend(rows)
                total += len(rows)
                if args.save and rows:
                    try:
                        ops.save_idd_api_keys(api_keys=rows)
                    except Exception as e:
                        UtilityTools.dlog(self.debug, "enum_idd_api_keys: save_idd_api_keys failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

            for key in keys:
                meta = key.get("meta") if isinstance(key.get("meta"), dict) else {}
                user_obj = key.get("user") if isinstance(key.get("user"), dict) else {}
                key["owner"] = user_obj.get("display")
                key["created"] = meta.get("created")
                key["last_modified"] = meta.get("last_modified")
                key["version"] = meta.get("version")

            print(f"\n[*] API Keys for Domain: {dom_name or dom_id}")
            UtilityTools.print_limited_table(
                keys,
                ["owner", "domain_ocid", "id", "created", "last_modified", "version"],
                sort_key="owner",
            )

        print(f"\n[*] enum_idd_api_keys complete. Domains: {len(domains)} | ApiKeys: {total}")
        return {"ok": True, "api_keys": int(total), "saved": bool(args.save)}

    # -------------------------------------------------------------------------
    # Identity Domain auth tokens
    # -------------------------------------------------------------------------
    def _run_idd_auth_tokens(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain Auth Tokens (SCIM AuthToken) for saved Identity Domains.",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save auth token metadata to DB.")
        parser.add_argument("--domain", required=False, help="Filter domains by substring.")
        parser.add_argument("--attributes", required=False, help="Override SCIM attributes list for list_auth_tokens().")
        parser.add_argument("--attribute-sets", action="append", default=[], help="SCIM attribute_sets (repeatable/comma-separated).")
        parser.add_argument("--all-saved-domains", action="store_true", help="Use all saved domains.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not args.all_saved_domains and (not isinstance(compartment_id, str) or not compartment_id):
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate IDD auth tokens.{UtilityTools.RESET}")
            return {"ok": False, "auth_tokens": 0}

        _comp, domains, domain_source = self._load_domains_from_cache(
            all_saved_domains=bool(args.all_saved_domains),
            domain_filter=args.domain or "",
        )
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in table '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then re-run: modules run enum_identity --idd-auth-tokens --save (optional)"
            )
            return {"ok": False, "auth_tokens": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB cache'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"])

        attrs = args.attributes or None
        attribute_sets = parse_csv_args(args.attribute_sets)
        if not attribute_sets:
            attribute_sets = None

        total = 0
        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            users = self.session.get_resource_fields(TABLE_IDD_USERS, where_conditions={"domain_ocid": dom_id}) or []
            users = [u for u in users if isinstance(u, dict)]
            if not users:
                UtilityTools.dlog(self.debug, "enum_idd_auth_tokens: no cached users for domain", domain_id=dom_id)
                continue

            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            tokens: list[dict[str, Any]] = []
            for user in users:
                try:
                    rows = [
                        r for r in (
                            ops.list_auth_tokens(
                                user_ocid=user.get("ocid"),
                                attributes=attrs,
                                attribute_sets=attribute_sets,
                            ) or []
                        ) if isinstance(r, dict)
                    ]
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_auth_tokens: list_auth_tokens failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                    continue

                for row in rows:
                    tokens.append(
                        self._normalize_auth_token_row(
                            row,
                            user_row=user,
                            dom=dom,
                            source="identity_domains:list_auth_tokens",
                        )
                    )
                total += len(rows)

            # Dedupe on stable token_id.
            deduped: list[dict[str, Any]] = []
            seen: set[str] = set()
            for token in tokens:
                tid = self._s(token.get("token_id"))
                if not tid or tid in seen:
                    continue
                seen.add(tid)
                deduped.append(token)
            tokens = deduped

            if args.save and tokens:
                try:
                    ops.save_idd_auth_tokens(auth_tokens=tokens)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_auth_tokens: save_idd_auth_tokens failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

            for token in tokens:
                meta = token.get("meta") if isinstance(token.get("meta"), dict) else {}
                user_obj = token.get("user") if isinstance(token.get("user"), dict) else {}
                token["owner"] = user_obj.get("display") or token.get("username")
                token["created"] = meta.get("created")
                token["last_modified"] = meta.get("last_modified")
                token["version"] = meta.get("version")

            print(f"\n[*] Auth Tokens for Domain: {dom_name or dom_id}")
            display_fields = ["owner", "domain_ocid", "token_name", "id", "status", "expires_on", "token_preview", "source"]
            optional_fields = {"status", "expires_on", "token_preview"}

            def _has_value(v: Any) -> bool:
                if v is None:
                    return False
                if isinstance(v, str):
                    return bool(v.strip())
                return True

            filtered_fields = [
                f for f in display_fields
                if f not in optional_fields or any(_has_value(t.get(f)) for t in tokens)
            ]

            UtilityTools.print_limited_table(
                tokens,
                filtered_fields,
                sort_key="owner",
            )

        print(f"\n[*] enum_idd_auth_tokens complete. Domains: {len(domains)} | AuthTokens: {total}")
        return {"ok": True, "auth_tokens": int(total), "saved": bool(args.save)}

    # -------------------------------------------------------------------------
    # Identity Domain grants
    # -------------------------------------------------------------------------
    def _run_idd_grants(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain Grants (SCIM Grants) for saved Identity Domains.",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save grants to DB.")
        parser.add_argument("--domain", required=False, help="Filter domains by substring.")
        parser.add_argument("--attributes", required=False, help="Override SCIM attributes list for list_grants().")
        parser.add_argument("--all-saved-domains", action="store_true", help="Use all saved domains.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not args.all_saved_domains and (not isinstance(compartment_id, str) or not compartment_id):
            print(f"{UtilityTools.RED}[X] session.compartment_id is not set; cannot enumerate grants.{UtilityTools.RESET}")
            return {"ok": False, "grants": 0}

        _comp, domains, domain_source = self._load_domains_from_cache(
            all_saved_domains=bool(args.all_saved_domains),
            domain_filter=args.domain or "",
        )
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in table '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then re-run: modules run enum_identity --idd-grants --save (optional)"
            )
            return {"ok": False, "grants": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB cache'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"])

        attrs = args.attributes or (
            "id,ocid,schemas,meta,domainOcid,compartmentOcid,tenancyOcid,active,"
            "grantMechanism,grantee,grantor,app,appRole,entitlement,appEntitlementId"
        )

        total = 0
        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            try:
                grants = [g for g in (ops.list_grants(attributes=attrs) or []) if isinstance(g, dict)]
            except Exception as e:
                UtilityTools.dlog(self.debug, "enum_idd_grants: list_grants failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                continue
            if not grants:
                continue

            total += len(grants)
            for grant in grants:
                ops.apply_domain_context(
                    grant,
                    domain_id=dom_id,
                    domain_name=dom_name,
                    domain_url=dom_url,
                    compartment_id=dom_compartment_id,
                )
            principal_lookup = self._build_principal_name_lookup(domain_ocid=dom_id)
            normalized = [self._normalize_grant_row(g, principal_lookup=principal_lookup) for g in grants]

            if args.save:
                try:
                    ops.save_idd_grants(grants=normalized, compartment_id=dom_compartment_id)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_grants: save_idd_grants failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

            print(f"\n[*] Grants for Domain: {dom_name or dom_id}")
            UtilityTools.print_limited_table(
                normalized,
                ["id", "grant_mechanism", "grantor_summary", "grantee_summary", "granted_summary"],
                sort_key="grantee_name",
            )

        print(f"\n[*] enum_idd_grants complete. Domains: {len(domains)} | Grants: {total}")
        return {"ok": True, "grants": int(total), "saved": bool(args.save)}

    # -------------------------------------------------------------------------
    # Identity Domain password policies
    # -------------------------------------------------------------------------
    def _run_idd_password_policies(self, user_args):
        parser = argparse.ArgumentParser(
            description="Enumerate Identity Domain Password Policies (SCIM PasswordPolicies).",
            allow_abbrev=False,
        )
        parser.add_argument("--save", action="store_true", help="Save password policies to DB.")
        parser.add_argument("--domain", required=False, help="Filter domains by substring.")
        parser.add_argument("--attributes", required=False, help="Override SCIM attributes list for list_password_policies().")
        parser.add_argument("--all-saved-domains", action="store_true", help="Use all saved domains.")
        args = self._parse_known(parser, user_args)

        compartment_id = getattr(self.session, "compartment_id", None)
        if not args.all_saved_domains and (not isinstance(compartment_id, str) or not compartment_id):
            print(
                f"{UtilityTools.RED}[X] session.compartment_id is not set; "
                f"use --all-saved-domains or select a compartment.{UtilityTools.RESET}"
            )
            return {"ok": False, "password_policies": 0}

        _comp, domains, domain_source = self._load_domains_from_cache(
            all_saved_domains=bool(args.all_saved_domains),
            domain_filter=args.domain or "",
        )
        if not domains:
            print(
                f"{UtilityTools.RED}[X] No saved identity domains found in table '{TABLE_IDENTITY_DOMAINS}'.{UtilityTools.RESET}\n"
                "Run: modules run enum_identity --domains --save\n"
                "Then re-run: modules run enum_identity --idd-password-policies --save (optional)"
            )
            return {"ok": False, "password_policies": 0}

        print(f"\n[*] Identity Domains ({'from current run' if domain_source == 'current_run' else 'from DB cache'})")
        UtilityTools.print_limited_table(domains, ["id", "display_name", "url", "home_region"])

        attrs = args.attributes or (
            "id,ocid,name,description,schemas,meta,"
            "domainOcid,compartmentOcid,tenancyOcid,"
            "minLength,maxLength,passwordStrength,"
            "minNumerals,minAlphas,minLowerCase,minUpperCase,"
            "numPasswordsInHistory,passwordExpiresAfter,"
            "maxIncorrectAttempts,lockoutDuration,"
            "firstNameDisallowed,lastNameDisallowed,userNameDisallowed,"
            "disallowedChars,idcsCreatedBy,idcsLastModifiedBy,"
            "priority,groups"
        )

        total = 0
        for dom in domains:
            dom_id = self._s(dom.get("id"))
            dom_name = self._s(dom.get("display_name"))
            dom_url = self._s(dom.get("url"))
            dom_compartment_id = self._s(
                dom.get("compartment_id") or dom.get("compartmentId") or compartment_id
            )
            if not dom_url:
                continue

            ops = IdentityDomainResourceClient(session=self.session, service_endpoint=dom_url)
            try:
                rows = [r for r in (ops.list_password_policies(attributes=attrs) or []) if isinstance(r, dict)]
            except Exception:
                try:
                    rows = [r for r in (ops.list_password_policies(attributes=None) or []) if isinstance(r, dict)]
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_password_policies: list failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")
                    continue

            if not rows:
                continue

            total += len(rows)
            for row in rows:
                ops.apply_domain_context(
                    row,
                    domain_id=dom_id,
                    domain_name=dom_name,
                    domain_url=dom_url,
                    compartment_id=dom_compartment_id,
                )
                groups = row.get("groups")
                row["assigned_to_groups"] = "yes" if isinstance(groups, list) and len(groups) > 0 else "no"

            if args.save:
                try:
                    ops.save_idd_password_policies(password_policies=rows, compartment_id=dom_compartment_id)
                except Exception as e:
                    UtilityTools.dlog(self.debug, "enum_idd_password_policies: save failed", domain_id=dom_id, err=f"{type(e).__name__}: {e}")

            print(f"\n[*] Password Policies for Domain: {dom_name or dom_id}")
            UtilityTools.print_limited_table(
                rows,
                ["id", "name", "priority", "assigned_to_groups", "min_length", "max_length"],
                sort_key="name",
            )

        print(f"\n[*] enum_idd_password_policies complete. Domains: {len(domains)} | PasswordPolicies: {total}")
        return {"ok": True, "password_policies": int(total), "saved": bool(args.save)}


class IdentityDomainsResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_domains(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIamResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_iam(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityPrincipalsResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_principals(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddAppsResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_apps(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddAppRolesResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_app_roles(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddApiKeysResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_api_keys(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddAuthTokensResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_auth_tokens(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddGrantsResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_grants(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class IdentityIddPasswordPoliciesResource(IdentityResourceSuite):
    def list(self, *, user_args):
        return self._run_idd_password_policies(user_args)

    def get(self, *, resource_id: str):
        _ = resource_id
        return {}

    def save(self, rows):
        _ = rows
        return None

    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
