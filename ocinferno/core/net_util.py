"""Network/DNS helpers applied at process startup via main.py."""
from __future__ import annotations

import concurrent.futures
import socket
import threading

_DNS_TIMEOUT = 10.0
_dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="oci_dns")
_real_getaddrinfo = socket.getaddrinfo

# Hostnames confirmed unresolvable this process lifetime. After the first timeout
# for a host, subsequent lookups return DnsTimeoutError instantly — no new thread
# submitted, no 10 s wait. This matters in enum_all when N compartments in a
# region all trigger the same unresolvable endpoint in parallel.
_dns_failed: set[str] = set()
_dns_failed_lock = threading.Lock()


class DnsTimeoutError(Exception):
    """Raised when DNS resolution exceeds _DNS_TIMEOUT seconds.

    Intentionally NOT a socket.gaierror / OSError subclass so urllib3 does NOT
    wrap it in NameResolutionError/ConnectionError.  This prevents the OCI
    pagination DEFAULT_RETRY_STRATEGY from retrying DNS failures (which would
    otherwise loop up to 8 times × 10 s each for a non-existent endpoint).
    The exception IS caught and reported as a soft-skip in service_runtime.
    """


def _getaddrinfo_bounded(*args, **kwargs):
    host = args[0] if args else "?"

    # Fast path: hostname already known to fail — return immediately.
    with _dns_failed_lock:
        if host in _dns_failed:
            raise DnsTimeoutError(
                f"DNS previously timed out for {host!r} — "
                "the OCI endpoint may not exist in this region."
            )

    future = _dns_pool.submit(_real_getaddrinfo, *args, **kwargs)
    try:
        return future.result(timeout=_DNS_TIMEOUT)
    except concurrent.futures.TimeoutError:
        with _dns_failed_lock:
            _dns_failed.add(host)
        raise DnsTimeoutError(
            f"DNS timed out after {_DNS_TIMEOUT:.0f}s for {host!r} — "
            "the OCI endpoint may not exist in this region."
        )


def install_dns_timeout() -> None:
    """Monkey-patch socket.getaddrinfo with a hard timeout.

    Call once at process startup (main.py) before any OCI SDK imports make
    network calls.  Safe to call multiple times (idempotent).
    """
    if socket.getaddrinfo is not _getaddrinfo_bounded:
        socket.getaddrinfo = _getaddrinfo_bounded
