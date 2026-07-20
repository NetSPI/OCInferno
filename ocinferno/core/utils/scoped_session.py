"""Per-task compartment-scoped view over a shared session.

Parallel cross-compartment enumeration needs each worker to act on its own
compartment while sharing one session (credentials + the lock-serialized
DataController). A single mutable ``session.compartment_id`` cannot express
"compartment A and compartment B at the same time", so each task wraps the base
session in a ``CompartmentScopedSession`` whose ``compartment_id`` is isolated;
every other attribute/method delegates to the shared base. The base
DataController is safe to call from workers -- it serializes every method on one
process-wide RLock (check_same_thread=False).
"""

from __future__ import annotations

from typing import Any


class CompartmentScopedSession:
    _OWN_ATTRS = {"_base", "_overrides"}

    def __init__(self, base: Any, compartment_id: str | None, region: str | None = None) -> None:
        object.__setattr__(self, "_base", base)
        overrides: dict[str, Any] = {"compartment_id": compartment_id}
        # Optionally pin this view to a REGION too. ``_init_client`` derives a
        # client's endpoint from ``config_current_default_region`` (then ``region``)
        # off the session (see service_runtime._init_client), so overriding both here
        # retargets every client built under this view -- no per-call region= threading.
        # Writes stay local to the view, so concurrent region workers never corrupt
        # the shared base session's region (same isolation compartments rely on).
        if region:
            overrides["region"] = region
            overrides["config_current_default_region"] = region
        object.__setattr__(self, "_overrides", overrides)

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_base"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._OWN_ATTRS:
            object.__setattr__(self, name, value)
            return
        # Keep writes local to this view so concurrent tasks never corrupt the
        # shared base session (compartment_id especially).
        object.__getattribute__(self, "_overrides")[name] = value

    # Output-path helpers take compartment_id explicitly; inject this task's
    # compartment when the caller doesn't override it, so downloads/exports land
    # under the right compartment.
    def get_download_save_path(self, *, compartment_id: str | None = None, **kwargs: Any) -> Any:
        base = object.__getattribute__(self, "_base")
        return base.get_download_save_path(compartment_id=compartment_id or self.compartment_id, **kwargs)

    def resolve_output_path(self, *, compartment_id: str | None = None, **kwargs: Any) -> Any:
        base = object.__getattribute__(self, "_base")
        return base.resolve_output_path(compartment_id=compartment_id or self.compartment_id, **kwargs)
