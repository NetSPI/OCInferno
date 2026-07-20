#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.certificates.utilities.helpers import (
    CaBundlesResource,
    CertificateAuthoritiesResource,
    CertificatesResource,
)

def _certificate_bundles_download(session, args, resource):
    """Factory: export each certificate's PEM bundle (leaf + chain + private key when
    exportable) via the data-plane client. Written under
    ``certificates/certificate-bundles/<id>/bundle.pem``."""
    def _download(rows):
        from ocinferno.core.utils.download_budget import DownloadBudget
        budget = DownloadBudget(session, label="certificates certificate_bundles")
        written = 0
        for row in rows:
            if budget.exceeded():
                break
            rid = row.get("id")
            if not rid:
                continue
            comp = row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown"
            path = session.get_download_save_path(
                service_name="certificates", filename="bundle.pem",
                compartment_id=comp, subdirs=["certificate-bundles", str(rid)],
            )
            try:
                if resource.download_bundle(resource_id=rid, out_path=path):
                    written += 1
            except Exception:
                continue
        return written
    return _download


COMPONENTS = [
    Component("certificates", CertificatesResource, help_text="Enumerate certificates", cache_table="certificates", download_fn=_certificate_bundles_download),
    Component("certificate_authorities", CertificateAuthoritiesResource, help_text="Enumerate certificate-authorities", cache_table="certificate_authorities"),
    Component("ca_bundles", CaBundlesResource, help_text="Enumerate ca-bundles", cache_table="certificate_ca_bundles"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_certificates",
        description="Enumerate Certificates resources",
    )
