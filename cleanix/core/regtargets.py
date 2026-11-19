"""Types for deciding whether a registry entry's target is provably missing.

Only the types live here for now; the evidence logic arrives with the
detectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol


class Existence(Enum):
    PRESENT = "present"
    MISSING = "missing"
    UNKNOWN = "unknown"


class Prober(Protocol):
    def probe(self, path: str) -> Existence: ...


@dataclass(frozen=True)
class DetectorContext:
    env: Mapping[str, str]
    prober: Prober
    profiles_root: str
    system_root: str


def default_context() -> DetectorContext:
    raise NotImplementedError("filled in by the detector task")
