#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client

# PEM fields (in emit order) on the data-plane certificate-bundle model.
_BUNDLE_PEM_FIELDS = ("certificate_pem", "cert_chain_pem", "private_key_pem")


class CertificatesResource(OciListResource):
    CLIENT_CLS = oci.certificates_management.CertificatesManagementClient
    SERVICE_NAME = "Certificates"
    TABLE_NAME = "certificates"
    LIST_METHOD = "list_certificates"
    GET_METHOD = "get_certificate"
    GET_ID_PARAM = "certificate_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "config_type",
        "subject",
        "issuer_certificate_authority_id",
        "key_algorithm",
        "signature_algorithm",
        "current_version_number",
    ]

    def download_bundle(self, *, resource_id: str, out_path) -> bool:
        """Export a certificate's PEM bundle via the DATA-plane client.

        The management client (``CLIENT_CLS``) lists/gets certificate *metadata*; the
        exportable material (leaf PEM, chain PEM, and — when the certificate config
        permits — the private key PEM) comes from
        ``oci.certificates.CertificatesClient.get_certificate_bundle``. Concatenates the
        non-empty PEM fields to ``out_path``. Returns ``True`` only when at least one
        PEM field was written (never leaves a partial/empty file behind).
        """
        client = _init_client(
            oci.certificates.CertificatesClient,
            session=self.session,
            service_name="certificates",
        )
        # Prefer the with-private-key bundle (only returns key material when the cert's
        # config allows export); fall back to the public-only default if that's rejected.
        try:
            data = client.get_certificate_bundle(
                certificate_id=resource_id,
                certificate_bundle_type="CERTIFICATE_CONTENT_WITH_PRIVATE_KEY",
            ).data
        except Exception:
            data = client.get_certificate_bundle(certificate_id=resource_id).data

        parts = []
        for field in _BUNDLE_PEM_FIELDS:
            value = getattr(data, field, None)
            if value:
                parts.append(value if value.endswith("\n") else value + "\n")
        if not parts:
            return False
        with open(out_path, "w") as fh:
            fh.write("".join(parts))
        return True


class CertificateAuthoritiesResource(OciListResource):
    CLIENT_CLS = oci.certificates_management.CertificatesManagementClient
    SERVICE_NAME = "Certificates"
    TABLE_NAME = "certificate_authorities"
    LIST_METHOD = "list_certificate_authorities"
    GET_METHOD = "get_certificate_authority"
    GET_ID_PARAM = "certificate_authority_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "config_type",
        "subject",
        "issuer_certificate_authority_id",
        "kms_key_id",
    ]


class CaBundlesResource(OciListResource):
    CLIENT_CLS = oci.certificates_management.CertificatesManagementClient
    SERVICE_NAME = "Certificates"
    TABLE_NAME = "certificate_ca_bundles"
    LIST_METHOD = "list_ca_bundles"
    GET_METHOD = "get_ca_bundle"
    GET_ID_PARAM = "ca_bundle_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
    ]
