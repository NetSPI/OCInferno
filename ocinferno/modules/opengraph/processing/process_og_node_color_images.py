#!/usr/bin/env python3
"""Push OCI OpenGraph custom node color/image styling to BloodHound.

Standalone styling module (separate from graph generation): re-style an existing
BloodHound instance WITHOUT regenerating the whole graph. The style payload lives
in ``opengraph/utilities/helpers/custom_node_sync.py``.
"""
from __future__ import annotations

import argparse
import os

from ocinferno.modules.opengraph.utilities.helpers.custom_node_sync import push_custom_node_attributes


def _parse_args(user_args):
    p = argparse.ArgumentParser(
        description="Push OCI OpenGraph custom node color/image styling to BloodHound.",
        allow_abbrev=False,
    )
    p.add_argument(
        "--custom-nodes-url",
        default=os.getenv("OCINFERNO_CUSTOM_NODES_URL", "http://127.0.0.1:8080/api/v2/custom-nodes"),
        help="BloodHound custom-nodes API endpoint.",
    )
    p.add_argument(
        "--custom-nodes-token",
        default=os.getenv("OCINFERNO_CUSTOM_NODES_TOKEN", ""),
        help="Bearer JWT token for the custom-nodes API (or set OCINFERNO_CUSTOM_NODES_TOKEN).",
    )
    p.add_argument(
        "--auth-mode", choices=("bearer", "signature"), default="bearer",
        help="BloodHound auth: 'bearer' JWT, or 'signature' API key (id+key HMAC).",
    )
    p.add_argument(
        "--custom-nodes-token-id", default=os.getenv("OCINFERNO_CUSTOM_NODES_TOKEN_ID", ""),
        help="BloodHound API token ID for signature auth (or OCINFERNO_CUSTOM_NODES_TOKEN_ID).",
    )
    p.add_argument(
        "--custom-nodes-token-key", default=os.getenv("OCINFERNO_CUSTOM_NODES_TOKEN_KEY", ""),
        help="BloodHound API token KEY/secret for signature auth (or OCINFERNO_CUSTOM_NODES_TOKEN_KEY).",
    )
    p.add_argument(
        "--prompt-token", action="store_true",
        help="Prompt for the bearer token / signature id+key if not supplied via flag/env.",
    )
    p.add_argument(
        "--insecure", action="store_true",
        help="Disable TLS verification (only for a local self-signed BloodHound).",
    )
    p.add_argument(
        "--reset", action="store_true",
        help="Delete all currently-registered custom node kinds first, then re-push everything.",
    )
    p.add_argument(
        "--clear", action="store_true",
        help="Delete all currently-registered custom node kinds and exit (no re-push).",
    )
    return p.parse_args(list(user_args or []))


def _prompt(session, prompt_text: str) -> str:
    for attr in ("prompt_text", "get_input", "prompt", "input_text"):
        fn = getattr(session, attr, None)
        if callable(fn):
            try:
                return str(fn(prompt_text) or "").strip()
            except Exception:
                return ""
    try:
        return str(input(prompt_text) or "").strip()
    except Exception:
        print("[X] --prompt-token requested but this session cannot prompt interactively.")
        return ""


def run_module(user_args, session):
    args = _parse_args(user_args)
    mode = str(args.auth_mode or "bearer")
    token = str(args.custom_nodes_token or "").strip()
    token_id = str(args.custom_nodes_token_id or "").strip()
    token_key = str(args.custom_nodes_token_key or "").strip()

    # Auto-infer signature mode when id+key are supplied but no bearer token and
    # --auth-mode wasn't explicitly set to bearer. Avoids requiring the user to
    # always add --auth-mode signature when they already passed the key pair.
    if mode == "bearer" and not token and token_id and token_key:
        mode = "signature"

    if bool(args.prompt_token):
        if mode == "bearer" and not token:
            token = _prompt(session, "BloodHound bearer token: ")
        elif mode == "signature" and (not token_id or not token_key):
            print("[*] API key: BloodHound -> My Profile -> API Key Management -> Create Token.")
            token_id = token_id or _prompt(session, "BloodHound API token ID: ")
            token_key = token_key or _prompt(session, "BloodHound API token KEY/secret: ")

    result = push_custom_node_attributes(
        custom_nodes_url=str(args.custom_nodes_url or ""),
        custom_nodes_token=token,
        auth_mode=mode,
        custom_nodes_token_id=token_id,
        custom_nodes_token_key=token_key,
        verify=not bool(args.insecure),
        reset=bool(args.reset),
        clear=bool(args.clear),
    )
    return 1 if bool(result.get("ok")) else -1
