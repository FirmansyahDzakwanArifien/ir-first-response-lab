"""Penilaian keputusan, temuan analisis, dan verifikasi integritas."""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from .scenarios import Assembled


def _strip(v) -> str:
    s = "" if v is None else str(v)
    return s.strip().strip("`'\"").strip()


def _ip(v):
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", v)
    return m.group(1) if m else None


def _ip_port(v):
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s*[:\s]\s*(\d{1,5})\b", v)
    return f"{m.group(1)}:{int(m.group(2))}" if m else None


def _secs(v):
    m = re.search(r"\b(\d{1,2})[:.](\d{2})[:.](\d{2})\b", v)
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3)) if m else None


def _proc_pid(v):
    m = re.search(r"([\w.\-]+\.exe)\D*?(\d{1,6})\b", v, re.I)
    return (m.group(1).lower(), int(m.group(2))) if m else None


def _account(v):
    return v.lower().replace("/", "\\").split("\\")[-1]


def _path(v):
    v = re.sub(r"^https?://[^/]+", "", v.strip())
    return v.split("?")[0].rstrip("/")


def matches(kind: str, answer, truth: str) -> bool:
    a = _strip(answer)
    if not a:
        return False
    if kind == "ip":
        return _ip(a) == truth
    if kind == "ip_port":
        return _ip_port(a) == truth
    if kind == "time":
        s, t = _secs(a), _secs(truth)
        return s is not None and abs(s - t) <= 1
    if kind == "int":
        digits = re.sub(r"[^\d]", "", a)
        return digits != "" and int(digits) == int(truth)
    if kind == "proc_pid":
        got, want = _proc_pid(a), _proc_pid(truth)
        return got is not None and got == want
    if kind == "account":
        return _account(a) == _account(truth)
    if kind == "urlpath":
        got = _path(a)
        return got == truth or (got.endswith(truth) and got.startswith("/var/www/"))
    if kind == "url":
        return a.lower().rstrip("/") == truth.lower().rstrip("/")
    if kind == "command":
        norm = lambda s: " ".join(unquote_plus(s).split())  # noqa: E731
        return norm(a) == norm(truth)
    if kind == "domain":
        host = re.sub(r"^https?://", "", a.lower()).split("/")[0].strip(".")
        return host == truth or (host.count(".") >= 1 and truth.endswith("." + host))
    if kind == "serial":
        return re.sub(r"[^0-9A-Za-z]", "", a).upper() == truth.upper()
    if kind == "filename":
        return a.replace("/", "\\").split("\\")[-1].lower() == truth.lower()
    if kind == "evidence_id":
        m = re.search(r"EV-?0*(\d+)", a, re.I)
        return m is not None and f"EV-{int(m.group(1)):03d}" == truth
    if kind == "sha256":
        return a.lower() == truth.lower()
    return a.lower() == truth.lower()


def grade(scenario: dict, asm: Assembled, answers: dict) -> dict:
    sc = scenario["scoring"]
    truth = asm.build.truth
    missing = {e.key: e for e in asm.build.evidence if not e.available}
    decisions = []
    for d in scenario["decisions"]:
        opt = asm.chosen[d["id"]]
        correct = next(o for o in d["options"] if o.get("correct"))
        ok = bool(opt.get("correct"))
        decisions.append({
            "id": d["id"], "topic": d["topic"], "refs": d.get("refs", ""), "chosen": opt["key"],
            "chosen_text": opt["text"], "verdict": opt["verdict"], "explain": opt["explain"].strip(),
            "correct_text": correct["text"], "correct_explain": correct["explain"].strip(),
            "ok": ok, "weight": sc["decision"], "earned": sc["decision"] if ok else 0,
        })
    findings = []
    for f in scenario["findings"]:
        given = answers.get("temuan", {}).get(f["id"])
        ok = matches(f["type"], given, truth[f["id"]])
        blocked = [missing[k] for k in f.get("needs", []) if k in missing]
        if "clock" in f.get("needs", []) and not asm.build.clock_recorded:
            blocked.append(None)
        findings.append({
            "id": f["id"], "topic": f["topic"], "prompt": f["prompt"], "type": f["type"],
            "answer": _strip(given), "truth": truth[f["id"]], "ok": ok, "weight": f["weight"],
            "earned": f["weight"] if ok else 0, "explain": f["explain"],
            "blocked": [b.id if b else "clock" for b in blocked],
        })
    integ = answers.get("integritas", {}) or {}
    int_id_ok = matches("evidence_id", integ.get("bukti_bermasalah"), truth["INT_ID"])
    int_hash_ok = matches("sha256", integ.get("sha256_aktual"), truth["INT_HASH"])
    integrity = {
        "id_answer": _strip(integ.get("bukti_bermasalah")), "hash_answer": _strip(integ.get("sha256_aktual")),
        "id_truth": truth["INT_ID"], "hash_truth": truth["INT_HASH"],
        "id_ok": int_id_ok, "hash_ok": int_hash_ok,
        "earned": (sc["integrity_id"] if int_id_ok else 0) + (sc["integrity_hash"] if int_hash_ok else 0),
        "weight": sc["integrity_id"] + sc["integrity_hash"],
    }
    parts = {
        "keputusan": (sum(d["earned"] for d in decisions), sum(d["weight"] for d in decisions)),
        "analisis": (sum(f["earned"] for f in findings), sum(f["weight"] for f in findings)),
        "integritas": (integrity["earned"], integrity["weight"]),
    }
    score = sum(p[0] for p in parts.values())
    max_score = sum(p[1] for p in parts.values())
    return {"decisions": decisions, "findings": findings, "integrity": integrity, "parts": parts,
            "score": score, "max_score": max_score, "pct": round(score / max_score * 100, 1)}
