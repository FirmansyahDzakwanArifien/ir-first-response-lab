"""Konfigurasi mata kuliah, kunci, bank skenario, dan identitas kasus."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml
from cryptography.fernet import Fernet, InvalidToken

ROOT = Path(__file__).resolve().parent.parent
WIB = timezone(timedelta(hours=7), "WIB")
SCENARIOS = ("ransomware-fileserver", "webshell-compromise", "insider-threat-exfil")
LETTERS = "ABCD"


class DeskError(Exception):
    """Kesalahan yang pesannya aman ditampilkan ke mahasiswa."""


def load_course() -> dict:
    return yaml.safe_load((ROOT / "course.yml").read_text(encoding="utf-8"))


def load_key() -> bytes:
    key = os.environ.get("IRSIM_KEY", "").strip()
    if not key:
        local = ROOT / ".irsim.key"
        if local.exists():
            key = local.read_text(encoding="utf-8").strip()
    if not key:
        raise SystemExit("IRSIM_KEY tidak ditemukan (secret repo atau file .irsim.key).")
    return key.encode()


# ── Bank skenario ────────────────────────────────────────────────────────────
# Isi skenario (kunci jawaban, pembahasan, pool nilai) disimpan terenkripsi di
# bank.sealed. Salinan plaintext di folder bank/ hanya ada di mesin dosen.

def seal_bank(key: bytes) -> Path:
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted((ROOT / "bank").glob("*.yml"))}
    if not files:
        raise SystemExit("Folder bank/ kosong.")
    for name, text in files.items():
        doc = yaml.safe_load(text)
        if doc.get("id") not in SCENARIOS:
            raise SystemExit(f"{name}: id skenario tidak dikenal")
    out = ROOT / "bank.sealed"
    out.write_bytes(Fernet(key).encrypt(json.dumps(files, ensure_ascii=False).encode()))
    return out


def unseal_bank(key: bytes) -> list[Path]:
    files = _read_sealed(key)
    target = ROOT / "bank"
    target.mkdir(exist_ok=True)
    written = []
    for name, text in files.items():
        p = target / name
        p.write_text(text, encoding="utf-8")
        written.append(p)
    return written


def _read_sealed(key: bytes) -> dict[str, str]:
    try:
        return json.loads(Fernet(key).decrypt((ROOT / "bank.sealed").read_bytes()))
    except InvalidToken:
        raise SystemExit("bank.sealed tidak dapat dibuka dengan kunci ini.")


def load_bank(key: bytes) -> dict[str, dict]:
    plain = ROOT / "bank"
    if plain.is_dir() and any(plain.glob("*.yml")) and not os.environ.get("IRSIM_SEALED_ONLY"):
        texts = [p.read_text(encoding="utf-8") for p in sorted(plain.glob("*.yml"))]
    else:
        texts = list(_read_sealed(key).values())
    docs = [yaml.safe_load(t) for t in texts]
    return {d["id"]: d for d in docs}


# ── Identitas kasus ──────────────────────────────────────────────────────────

def _mac(key: bytes, label: str) -> bytes:
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


@dataclass(frozen=True)
class Case:
    key: bytes
    nim: str
    scenario: str
    year: int

    @property
    def case_id(self) -> str:
        code = base64.b32encode(_mac(self.key, f"case|{self.nim}")).decode()
        code = code.replace("O", "Q").replace("I", "J")[:5]
        return f"IR-{self.year % 100:02d}-{code}"

    def rng(self, purpose: str) -> random.Random:
        seed = int.from_bytes(_mac(self.key, f"{purpose}|{self.nim}|{self.scenario}"), "big")
        return random.Random(seed)

    def option_order(self, decision: dict) -> list[dict]:
        """Urutan opsi A–D untuk satu keputusan, diacak per mahasiswa."""
        options = list(decision["options"])
        self.rng(f"order|{decision['id']}").shuffle(options)
        return options

    def option_for(self, decision: dict, letter: str) -> dict:
        return self.option_order(decision)[LETTERS.index(letter)]

    def letter_for(self, decision: dict, key: str) -> str:
        keys = [o["key"] for o in self.option_order(decision)]
        return LETTERS[keys.index(key)]


def assign_scenario(key: bytes, nim: str, course: dict) -> str:
    mode = course.get("scenario_assignment", "auto")
    if mode in SCENARIOS:
        return mode
    pool = [s for s in course.get("scenario_pool", SCENARIOS) if s in SCENARIOS]
    return pool[int.from_bytes(_mac(key, f"scenario|{nim}"), "big") % len(pool)]


def incident_day(case: Case, course: dict) -> date:
    start, end = (date.fromisoformat(str(d)) for d in course["incident_window"])
    span = (end - start).days
    return start + timedelta(days=case.rng("day").randint(0, span))


def now_wib() -> datetime:
    return datetime.now(WIB)


def grade_for(pct: float, course: dict) -> dict:
    for band in course["grading"]:
        if pct >= band["min"]:
            return band
    return course["grading"][-1]
