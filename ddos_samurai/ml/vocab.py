from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List


@dataclass
class Vocab:
    token_to_id: Dict[str, int]

    @classmethod
    def build(cls, values: Iterable[str]) -> "Vocab":
        uniq = sorted({str(v) for v in values})
        token_to_id = {tok: i for i, tok in enumerate(uniq)}
        return cls(token_to_id=token_to_id)

    def encode(self, value: str, default: int = -1) -> int:
        return int(self.token_to_id.get(str(value), default))

    def decode(self, idx: int, default: str = "unknown") -> str:
        for token, token_id in self.token_to_id.items():
            if int(token_id) == int(idx):
                return token
        return default

    @property
    def tokens(self) -> List[str]:
        return list(self.token_to_id.keys())

