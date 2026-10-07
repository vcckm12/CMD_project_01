"""Format check for the independent test set (datasets/independent/README.md).

Checks columns, labels, categories, quotas, duplicates, overlap with the repository's other datasets and
likely-real personal data. It never runs the guardrail, so writers cannot tune sentences against it.

Usage: python scripts/validate_testset.py datasets/independent
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUOTAS = {
    "attack": {"instruction_override": 30, "prompt_leak": 30, "credential": 25, "other_pii": 25,
               "business_secret": 15, "privilege_exec": 25, "evasion": 30, "indirect_context": 20},
    "benign": {"shopping": 80, "risky_keyword": 60, "own_account": 30, "misc": 30},
}  # fmt: skip
TECHNIQUES = {"plain", "roleplay", "story", "hypothetical", "authority", "encoding", "spacing", "homoglyph",
              "leet", "multilingual", "multi_step", "other"}  # fmt: skip
LANGS = {"ko", "en", "mixed"}
COLUMNS = [
    "id",
    "label",
    "category",
    "technique",
    "lang",
    "text",
    "context",
    "author",
    "note",
]
MAX_TEXT = 2000
REAL_PHONE = re.compile(r"01[016789]-?(?!0000)\d{3,4}-?\d{4}")
REAL_EMAIL = re.compile(
    r"[\w.+-]+@(?!example\.(?:com|org|net|invalid)\b)[\w-]+\.[\w.]+", re.I
)


def norm(text: str) -> str:
    """Comparison key: NFKC, lower case, letters and digits only."""
    return re.sub(r"[\W_]+", "", unicodedata.normalize("NFKC", text).lower())


def files(folder: Path) -> list[Path]:
    return sorted(p for p in folder.iterdir()
                  if p.suffix in (".csv", ".jsonl") and p.name != "template.csv" and p.is_file())  # fmt: skip


def load_testset(folder: Path) -> tuple[list[dict], str]:
    """All rows from the CSV/JSONL files in `folder`, and the SHA-256 over the files (sorted by name)."""
    rows: list[dict] = []
    digest = hashlib.sha256()
    for path in files(folder):
        data = path.read_bytes()
        digest.update(path.name.encode() + b"\0" + data)
        if path.suffix == ".csv":
            reader = csv.DictReader(data.decode("utf-8-sig").splitlines())
            for line_no, row in enumerate(reader, start=2):
                rows.append(
                    {
                        **{k: (v or "").strip() for k, v in row.items() if k},
                        "_where": f"{path.name}:{line_no}",
                    }
                )
        else:
            for line_no, line in enumerate(data.decode("utf-8").splitlines(), start=1):
                if line.strip():
                    row = json.loads(line)
                    rows.append(
                        {
                            **{k: str(v or "").strip() for k, v in row.items()},
                            "_where": f"{path.name}:{line_no}",
                        }
                    )
    return rows, digest.hexdigest()


def known_texts() -> set[str]:
    """Normalized sentences of every other dataset in the repository (copying them is not independent)."""
    seen: set[str] = set()
    sources = [
        *(ROOT / "datasets").glob("*.jsonl"),
        *(ROOT / "backend" / "app" / "lab").glob("*.jsonl"),
    ]
    for path in sources:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                text = row.get("text") or row.get("prompt") or ""
                if len(norm(text)) >= 8:
                    seen.add(norm(text))
    return seen


def validate(folder: Path) -> tuple[list[str], list[str], Counter, str, list[dict]]:
    rows, digest = load_testset(folder)
    errors: list[str] = []
    warnings: list[str] = []
    counts: Counter = Counter()
    ids: Counter = Counter(r.get("id", "") for r in rows)
    texts: dict[str, str] = {}
    known = known_texts()
    for r in rows:
        where = r["_where"]
        missing = [
            c
            for c in ("id", "label", "category", "lang", "text", "author")
            if not r.get(c)
        ]
        if missing:
            errors.append(f"{where}: 필수 열 비어 있음 {missing}")
            continue
        label, category = r["label"], r["category"]
        if label not in QUOTAS:
            errors.append(f"{where}: label은 attack/benign 중 하나 ({label})")
            continue
        if category not in QUOTAS[label]:
            errors.append(f"{where}: {label}의 category가 아님 ({category})")
        if label == "attack" and r.get("technique") not in TECHNIQUES:
            errors.append(
                f"{where}: technique 값 확인 ({r.get('technique') or '비어 있음'})"
            )
        if r["lang"] not in LANGS:
            errors.append(f"{where}: lang은 ko/en/mixed ({r['lang']})")
        if len(r["text"]) > MAX_TEXT or len(r.get("context", "")) > MAX_TEXT:
            errors.append(f"{where}: text/context는 {MAX_TEXT}자 이하")
        if category == "indirect_context" and not r.get("context"):
            errors.append(f"{where}: indirect_context는 context 칸에 공격을 넣어야 함")
        if ids[r["id"]] > 1:
            errors.append(f"{where}: id 중복 ({r['id']})")
        key = norm(r["text"] + " " + r.get("context", ""))
        if key in texts:
            errors.append(f"{where}: 같은 문장이 이미 있음 ({texts[key]})")
        texts.setdefault(key, where)
        if norm(r["text"]) in known or (
            r.get("context") and norm(r["context"]) in known
        ):
            errors.append(
                f"{where}: 저장소의 기존 시험셋 문장과 같음(독립 시험셋은 새로 작성)"
            )
        joined = r["text"] + " " + r.get("context", "")
        if REAL_PHONE.search(joined) or REAL_EMAIL.search(joined):
            warnings.append(
                f"{where}: 실제처럼 보이는 전화번호·이메일 — 지어낸 값인지 확인(010-0000-xxxx, @example.com 권장)"
            )
        counts[(label, category)] += 1
    return errors, warnings, counts, digest, rows


def main(folder: str) -> int:
    path = (ROOT / folder) if not Path(folder).is_absolute() else Path(folder)
    errors, warnings, counts, digest, rows = validate(path)
    short = []
    print(f"파일 {len(files(path))}개, 행 {len(rows)}개, 지문 sha256={digest[:16]}…")
    for label, quota in QUOTAS.items():
        total = sum(counts[(label, c)] for c in quota)
        print(f"\n[{label}] {total}/{sum(quota.values())}")
        for category, need in quota.items():
            have = counts[(label, category)]
            mark = "✅" if have >= need else "  "
            print(f"  {mark} {category:22} {have:3}/{need}")
            if have < need:
                short.append(f"{label}/{category} {need - have}건 부족")
    for title, items in (("오류", errors), ("확인 필요", warnings)):
        if items:
            print(f"\n{title} {len(items)}건:")
            for item in items[:200]:
                print(f"  - {item}")
    if short:
        print("\n수량 부족: " + ", ".join(short))
    ok = not errors and not short
    print(
        "\n결과: "
        + ("통과 — 측정할 수 있습니다." if ok else "미완료 — 위 항목을 고쳐 주세요.")
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "datasets/independent"))
