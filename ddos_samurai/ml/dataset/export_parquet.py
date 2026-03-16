from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, Iterable, List


def export_jsonl(rows: Iterable[Dict[str, Any]], out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
    return out_path


def export_parquet(rows: List[Dict[str, Any]], out_path: str) -> str:
    try:
        import pandas as pd  # type: ignore
    except Exception as exc:
        raise RuntimeError("export_parquet requires pandas+pyarrow to be installed") from exc
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    df = pd.DataFrame(list(rows))
    df.to_parquet(out_path, index=False)
    return out_path

