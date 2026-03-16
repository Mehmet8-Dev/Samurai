from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Sequence, Tuple, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class SplitResult:
    train: List[T]
    val: List[T]
    test: List[T]


def split_dataset(
    items: Sequence[T],
    *,
    seed: int = 1337,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
) -> SplitResult:
    arr = list(items)
    rng = random.Random(int(seed))
    rng.shuffle(arr)
    n = len(arr)
    n_train = int(n * float(train_ratio))
    n_val = int(n * float(val_ratio))
    train = arr[:n_train]
    val = arr[n_train : n_train + n_val]
    test = arr[n_train + n_val :]
    return SplitResult(train=train, val=val, test=test)

