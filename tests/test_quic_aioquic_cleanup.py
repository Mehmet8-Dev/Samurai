from __future__ import annotations

from pathlib import Path
import unittest


class TestAioquicHardRemove(unittest.TestCase):
    def test_repo_has_no_aioquic_references_in_text_sources(self):
        root = Path(__file__).resolve().parents[1]
        allow_suffixes = {
            ".py", ".md", ".txt", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".json", "",
        }
        offenders: list[str] = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in {".git", ".venv", "venv", "ven", "ven311", "build", "dist", "__pycache__", ".pytest_cache"} for part in p.parts):
                continue
            if p.resolve() == Path(__file__).resolve():
                continue
            if p.suffix.lower() not in allow_suffixes and p.name != "setup.py":
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if "aioquic" in txt.lower():
                offenders.append(str(p.relative_to(root)))

        self.assertEqual(offenders, [], f"Found aioquic references: {offenders}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
