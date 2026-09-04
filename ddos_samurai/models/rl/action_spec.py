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
    """Ordered action dimensions plus which of them are *categorical*.

    A continuous dim (rps, concurrency, source_rotation) is a scalar the policy
    regresses in a normalized [0,1] space. A categorical dim (request_mix,
    pacing_mode) is an unordered *choice*: its "good" values do not average to a
    good value, so a continuous head collapses to the mean of the categories. Such
    dims get a softmax head — one logit per observed category, argmax at serving —
    trained by advantage-weighted cross-entropy. The category values themselves are
    data-derived by the dataset builder and travel with the exported policy.
    """

    names: tuple[str, ...] = ("rps",)
    categorical_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.names or self.names[0] != "rps":
            raise ValueError("ActionSpec dim 0 must be 'rps' (the primary setpoint)")
        for n in self.names:
            if n not in ACTION_FIELDS:
                raise ValueError(f"unknown action dim {n!r}; add it to ACTION_FIELDS")
        for n in self.categorical_names:
            if n not in self.names:
                raise ValueError(f"categorical dim {n!r} is not in names {self.names}")
            if n == "rps":
                raise ValueError("rps is the continuous setpoint; it cannot be categorical")

    @property
    def dim(self) -> int:
        return len(self.names)

    def is_categorical(self, name: str) -> bool:
        return name in self.categorical_names

    def field_of(self, name: str) -> str:
        return ACTION_FIELDS[name]


# The full Mahoraga action: setpoint plus the levers that change *how* load is
# shaped, which is what a defended target reacts to differently. request_mix (which
# request variant) and pacing_mode (constant/burst/poisson) are unordered choices —
# categorical heads — so the policy can learn to *avoid* a WAF-blocked variant
# instead of regressing to the mean of the good ones.
MAHORAGA = ActionSpec(
    ("rps", "concurrency", "request_mix", "source_rotation", "pacing_mode"),
    categorical_names=("request_mix", "pacing_mode"),
)

# Back-compat default: scalar setpoint only.
RPS_ONLY = ActionSpec(("rps",))
