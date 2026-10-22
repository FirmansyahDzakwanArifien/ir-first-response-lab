"""Perakitan kasus: keputusan → efek → bukti → manifest akuisisi."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..core import WIB, Case, incident_day
from . import insider, ransomware, webshell
from .base import Build, Context, fill, sha256, tamper

GENERATORS = {
    "ransomware-fileserver": ransomware.build,
    "webshell-compromise": webshell.build,
    "insider-threat-exfil": insider.build,
}


@dataclass
class Assembled:
    build: Build
    chosen: dict[str, dict]          # id keputusan -> opsi yang dipilih
    effects: set[str]
    drift: timedelta
    tampered_id: str
    files: dict[str, bytes]          # nama file bukti -> isi yang diterima mahasiswa
    manifest: list[dict]


def _outcome(decision: dict, option: dict, effects: set[str]) -> str:
    if decision.get("requires_live") and "live_lost" in effects:
        return (f"Rencana: {option['text']} Tidak dapat dijalankan — sistem sudah mati/di-reboot "
                "pada langkah sebelumnya.")
    return " ".join(option["outcome"].split())


def assemble(case: Case, scenario: dict, letters: dict[str, str], course: dict) -> Assembled:
    chosen = {d["id"]: case.option_for(d, letters[d["id"]]) for d in scenario["decisions"]}
    effects = {fx for opt in chosen.values() for fx in opt.get("effects", [])}
    rng = case.rng("evidence")
    drift = timedelta(seconds=rng.randint(70, 540) * rng.choice([1, -1]))
    day = incident_day(case, course)
    ctx = Context(
        rng=rng, bank=scenario, effects=effects,
        outcomes={d["id"]: _outcome(d, chosen[d["id"]], effects) for d in scenario["decisions"]},
        day=datetime(day.year, day.month, day.day, tzinfo=WIB), drift=drift, case_id=case.case_id,
    )
    build = GENERATORS[scenario["id"]](ctx)

    # Satu bukti "rusak" dalam perjalanan (dibuka & disimpan ulang). Dipilih
    # dengan RNG terpisah agar tidak bergantung pada keputusan mahasiswa.
    present = [e for e in build.evidence if e.available]
    pick = case.rng("tamper").choice([e.id for e in build.evidence])
    if pick not in {e.id for e in present}:
        pick = present[case.rng("tamper2").randrange(len(present))].id
    files, manifest = {}, []
    for e in build.evidence:
        if not e.available:
            manifest.append({"evidence_id": e.id, "filename": None, "description": e.title, "source": e.source,
                             "status": "TIDAK TERSEDIA", "reason": e.reason})
            continue
        original = e.content.encode("utf-8")
        received = tamper(original) if e.id == pick else original
        files[e.filename] = received
        manifest.append({
            "evidence_id": e.id, "filename": e.filename, "description": e.title, "source": e.source,
            "volatile": e.volatile, "tool": e.tool,
            "acquired_at": e.acquired_at.strftime("%Y-%m-%d %H:%M:%S WIB") if e.acquired_at else None,
            "size_bytes": len(original), "sha256": sha256(original), "note": e.note or None,
        })
    build.truth["INT_ID"] = pick
    build.truth["INT_HASH"] = sha256(files[next(e.filename for e in build.evidence if e.id == pick)])
    return Assembled(build=build, chosen=chosen, effects=effects, drift=drift, tampered_id=pick,
                     files=files, manifest=manifest)


__all__ = ["assemble", "Assembled", "GENERATORS", "fill"]
