"""The action space contract — shared by corpus, trainer, export, and C++ serving.

Phase 3 makes the policy's action the full Mahoraga vector instead of a scalar
setpoint. ``ActionSpec`` is just the *ordered* list of controlled dimension names;
dim 0 is always ``rps`` (the primary setpoint the shield governs). Per-dim bounds
are data-derived by the dataset builder and travel with the exported policy, so
Python training and C++ serving de-normalize each dimension identically.

The dimension order is the wire contract between ``export.py`` and ``rl_policy.cpp``
(the C++ side applies outputs positionally), so it must not be reordered casually.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Corpus field each action dimension reads from ``schemas.Action``. Add here to
# grow the action space; keep the C++ apply-order (master_main) in lockstep.
ACTION_FIELDS: dict[str, str] = {
    "rps": "rps",
    "concurrency": "concurrency",
    "connections": "connections",
    "request_mix": "request_mix",
    "source_rotation": "source_rotation",
    "pacing_mode": "pacing_mode",
}


@dataclass(frozen=True)
class ActionSpec:
    names: tuple[str, ...] = ("rps",)

    def __post_init__(self) -> None:
        if not self.names or self.names[0] != "rps":
            raise ValueError("ActionSpec dim 0 must be 'rps' (the primary setpoint)")
        for n in self.names:
            if n not in ACTION_FIELDS:
                raise ValueError(f"unknown action dim {n!r}; add it to ACTION_FIELDS")

    @property
    def dim(self) -> int:
        return len(self.names)

    def field_of(self, name: str) -> str:
        return ACTION_FIELDS[name]


# The full Mahoraga action: setpoint plus the levers that change *how* load is
# shaped, which is what a defended target reacts to differently.
MAHORAGA = ActionSpec(("rps", "concurrency", "request_mix", "source_rotation", "pacing_mode"))

# Back-compat default: scalar setpoint only.
RPS_ONLY = ActionSpec(("rps",))
