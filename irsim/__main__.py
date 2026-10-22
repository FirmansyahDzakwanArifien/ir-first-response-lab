"""Perkakas dosen.

    python -m irsim keygen                 buat kunci baru (.irsim.key)
    python -m irsim seal | unseal          enkripsi / buka bank skenario
    python -m irsim preview --nim 2024001  pratinjau kasus + kunci jawaban
    python -m irsim selftest               uji menyeluruh seluruh skenario
    python -m irsim setup --repo OWNER/REPO   buat label issue
    python -m irsim rekap --repo OWNER/REPO   rekap nilai ke CSV
    python -m irsim laporan --repo OWNER/REPO laporan lengkap seluruh mahasiswa + indeks HTML
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from cryptography.fernet import Fernet

from . import render, report
from .core import (LETTERS, ROOT, SCENARIOS, Case, assign_scenario, grade_for, load_bank, load_course, load_key,
                   now_wib, seal_bank, unseal_bank)
from .desk import (BOT, LABEL_CASE, LABEL_DONE, LABEL_F1, LABEL_F2, LABEL_LATE, LABEL_REJECT, MARK,
                   correct_letters, facts_for, parse_submission)
from .gh import GitHub
from .grading import grade
from .scenarios import assemble
from .scenarios.base import sha256

LABELS = {
    LABEL_CASE: ("9b1c1c", "Kasus simulasi First Response"),
    LABEL_F1: ("d97706", "Menunggu keputusan di TKP"),
    LABEL_F2: ("2563eb", "Analisis paket bukti"),
    LABEL_DONE: ("15803d", "Laporan dinilai, kasus ditutup"),
    LABEL_REJECT: ("6b7280", "Penugasan ditolak"),
    LABEL_LATE: ("7c3aed", "Laporan melewati tenggat"),
}


def letters_for(case: Case, scenario: dict, mode: str) -> dict[str, str]:
    if mode == "benar":
        return correct_letters(case, scenario)
    if mode == "salah":
        return {d["id"]: next(case.letter_for(d, o["key"]) for o in case.option_order(d) if not o.get("correct"))
                for d in scenario["decisions"]}
    picks = [x.strip().upper() for x in mode.split(",")]
    return {d["id"]: p for d, p in zip(scenario["decisions"], picks)}


def key_answers(asm) -> dict:
    t = asm.build.truth
    return {"temuan": {k: v for k, v in t.items() if k.startswith("F")},
            "integritas": {"bukti_bermasalah": t["INT_ID"], "sha256_aktual": t["INT_HASH"]},
            "catatan": "Jawaban kunci (pratinjau dosen)."}


def cmd_preview(args):
    course, key = load_course(), load_key()
    bank = load_bank(key)
    sid = args.skenario or assign_scenario(key, args.nim, course)
    case = Case(key, args.nim, sid, course["year"])
    scenario = bank[sid]
    letters = letters_for(case, scenario, args.keputusan)
    asm = assemble(case, scenario, letters, course)
    facts = facts_for(case, scenario, course)
    out = Path(args.out) / case.case_id
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    student = {"nim": args.nim, "name": args.nama}
    (out / "01_briefing.md").write_text(render.briefing_comment(case, scenario, facts, "mahasiswa", course), encoding="utf-8")
    render.write_pack(out / "paket", case, scenario, asm, facts, student)
    (out / "02_paket.md").write_text(render.pack_comment(case, scenario, asm, course), encoding="utf-8")
    answers = key_answers(asm)
    (out / "KUNCI.json").write_text(json.dumps({"keputusan": letters, "benar": correct_letters(case, scenario),
                                                **answers}, indent=2, ensure_ascii=False), encoding="utf-8")
    result = grade(scenario, asm, answers)
    band = grade_for(result["pct"], course)
    report.write_debrief(out / "debrief", case, scenario, asm, result, band, student, answers["catatan"], course,
                         now_wib(), False, "mahasiswa")
    (out / "03_skor.md").write_text(render.score_comment(case, result, band, False), encoding="utf-8")
    print(f"{case.case_id} · {sid} · keputusan {letters} → skor kunci {result['score']}/{result['max_score']}")
    print(f"Ditulis ke {out}")


def _derivable(kind: str, truth: str, text: str) -> bool:
    if kind == "proc_pid":
        name, pid = truth.split()
        return name in text and pid in text
    if kind == "ip_port":
        ip, port = truth.split(":")
        return ip in text and port in text
    if kind == "account":
        return truth.split("\\")[-1] in text
    if kind == "command":
        from urllib.parse import quote_plus
        return quote_plus(truth) in text
    if kind in ("time", "int"):
        return True
    return truth in text


def cmd_selftest(args):
    course, key = load_course(), load_key()
    bank = load_bank(key)
    nims = [f"2024{n:03d}" for n in range(1, args.n + 1)]
    failures = 0
    for sid in SCENARIOS:
        scenario = bank[sid]
        for nim in nims:
            case = Case(key, nim, sid, course["year"])
            good = correct_letters(case, scenario)
            a1 = assemble(case, scenario, good, course)
            a2 = assemble(case, scenario, good, course)
            checks = {
                "deterministik": a1.files == a2.files and a1.build.truth == a2.build.truth,
                "skor penuh": grade(scenario, a1, key_answers(a1))["score"] == 100,
                "hash rusak": sha256(a1.files[next(e.filename for e in a1.build.evidence
                                                   if e.id == a1.tampered_id)]) == a1.build.truth["INT_HASH"],
                "manifest beda": next(m for m in a1.manifest if m["evidence_id"] == a1.tampered_id)["sha256"]
                                 != a1.build.truth["INT_HASH"],
            }
            for f in scenario["findings"]:
                sources = "\n".join(a1.build.by_key(k).content for k in f["needs"] if k != "clock")
                checks[f"{f['id']} dapat ditemukan"] = _derivable(f["type"], a1.build.truth[f["id"]], sources)
            notes = "\n".join(m for _, m in a1.build.scene_log)
            checks["drift tercatat"] = "Selisih" in notes
            for d in scenario["decisions"]:
                for letter in LETTERS:
                    trial = dict(good, **{d["id"]: letter})
                    a3 = assemble(case, scenario, trial, course)
                    res = grade(scenario, a3, key_answers(a3))
                    if res["score"] > 100 or not a3.files:
                        checks[f"{d['id']}{letter}"] = False
            bad = letters_for(case, scenario, "salah")
            a4 = assemble(case, scenario, bad, course)
            r4 = grade(scenario, a4, {"temuan": {}, "integritas": {}})
            checks["skor nol"] = r4["score"] == 0
            render.pack_comment(case, scenario, a4, course)
            render.briefing_comment(case, scenario, facts_for(case, scenario, course), "x", course)
            failed = [k for k, v in checks.items() if not v]
            failures += bool(failed)
            status = "OK " if not failed else "GAGAL"
            print(f"[{status}] {sid:<24} {nim} {case.case_id}" + (f"  → {', '.join(failed)}" if failed else ""))
    dist = {}
    for n in range(1, 61):
        s = assign_scenario(key, f"2024{n:03d}", course)
        dist[s] = dist.get(s, 0) + 1
    print("Distribusi skenario untuk 60 NIM contoh:", dist)
    sys.exit(1 if failures else 0)


def _token() -> str:
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def cmd_setup(args):
    gh = GitHub(args.repo, _token())
    existing = {lb["name"] for lb in gh.req("GET", f"/repos/{args.repo}/labels", params={"per_page": 100})}
    for name, (color, desc) in LABELS.items():
        if name in existing:
            gh.req("PATCH", f"/repos/{args.repo}/labels/{quote(name)}",
                   {"color": color, "description": desc})
        else:
            gh.req("POST", f"/repos/{args.repo}/labels", {"name": name, "color": color, "description": desc})
        print(f"label: {name}")


def cmd_rekap(args):
    gh = GitHub(args.repo, _token())
    rows = []
    for issue in gh.issues(LABEL_CASE):
        result = None
        for c in gh.comments(issue["number"]):
            if c["user"]["login"] == BOT:
                m = MARK.search(c["body"] or "")
                if m:
                    st = json.loads(m.group(1))
                    result = st.get("result") or result
                    stage = st.get("stage")
        if result:
            rows.append({**{k: v for k, v in result.items() if k not in ("komponen", "butir")},
                         **{f"k_{k}": v for k, v in result["komponen"].items()},
                         **{k: int(v) for k, v in result["butir"].items()}, "issue": issue["number"]})
    rows.sort(key=lambda r: r["nim"])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not rows:
        print("Belum ada laporan yang dinilai.")
        return
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with open(out / "rekap_nilai.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    lines = ["# Rekap kelas", "", f"Jumlah laporan: **{len(rows)}**  ",
             f"Rata-rata skor: **{sum(r['skor'] for r in rows) / len(rows):.1f}**", "",
             "| Skenario | n | Rata-rata |", "|---|:-:|:-:|"]
    for sid in SCENARIOS:
        sub = [r["skor"] for r in rows if r["skenario"] == sid]
        if sub:
            lines.append(f"| {sid} | {len(sub)} | {sum(sub) / len(sub):.1f} |")
    lines += ["", "| Butir | % benar |", "|---|:-:|"]
    items = [k for k in fields if k[:1] in "DF" and k[1:].isdigit() or k.startswith("INT_")]
    for k in items:
        vals = [r[k] for r in rows if k in r]
        lines.append(f"| {k} | {100 * sum(vals) / len(vals):.0f}% |")
    (out / "ringkasan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(rows)} laporan → {out / 'rekap_nilai.csv'} dan {out / 'ringkasan.md'}")


def cmd_laporan(args):
    """Bangun ulang debrief setiap mahasiswa dari jawaban /submit di issue (tidak bergantung artifact)."""
    course, key = load_course(), load_key()
    bank = load_bank(key)
    gh = GitHub(args.repo, _token())
    out = Path(args.out)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    rows = []
    for issue in gh.issues(LABEL_CASE):
        final, final_submit, submit = None, None, None
        for c in gh.comments(issue["number"]):
            body = c["body"] or ""
            if c["user"]["login"] == BOT:
                m = MARK.search(body)
                if m and json.loads(m.group(1)).get("result"):
                    final, final_submit = json.loads(m.group(1)), submit
            elif c["user"]["login"] == issue["user"]["login"] and body.strip().lower().startswith("/submit"):
                submit = c
        if not final or not final_submit:
            continue
        rec = final["result"]
        case = Case(key, final["nim"], final["scenario"], course["year"])
        scenario = bank[final["scenario"]]
        answers = parse_submission(final_submit["body"])
        asm = assemble(case, scenario, final["decisions"], course)
        result = grade(scenario, asm, answers)
        band = grade_for(result["pct"], course)
        student = {"nim": final["nim"], "name": final["name"]}
        slug = re.sub(r"[^A-Za-z0-9]+", "_", final["name"]).strip("_")
        folder = out / f"{final['nim']}_{slug}"
        report.write_debrief(folder, case, scenario, asm, result, band, student, answers["catatan"], course,
                             datetime.fromisoformat(rec["dikirim"]), rec["terlambat"], final["login"])
        page = next(folder.glob("*-debrief/DEBRIEF.html")).relative_to(out).as_posix()
        rows.append({**rec, "page": page, "issue": issue["html_url"], "cocok": result["score"] == rec["skor"]})
    rows.sort(key=lambda r: r["nim"])
    write_index(out, rows, course)
    mismatch = [r["nim"] for r in rows if not r["cocok"]]
    print(f"{len(rows)} laporan → {out / 'index.html'}" + (f"  (skor berbeda: {mismatch})" if mismatch else ""))


def write_index(out: Path, rows: list[dict], course: dict):
    e = html.escape
    avg = sum(r["skor"] for r in rows) / len(rows) if rows else 0
    body = "".join(
        f"<tr><td>{e(r['nim'])}</td><td>{e(r['nama'])}</td><td>{e(r['skenario'])}</td>"
        f"<td class=n>{r['skor']}</td><td class=n><b>{e(r['grade'])}</b></td>"
        f"<td>{'Terlambat' if r['terlambat'] else 'Tepat waktu'}</td><td>{e(r['dikirim'][:16].replace('T', ' '))}</td>"
        f"<td><a href=\"{e(r['page'])}\">Debrief</a> · <a href=\"{e(r['issue'])}\">Issue</a></td></tr>"
        for r in rows)
    (out / "index.html").write_text(f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Laporan Kelas</title><style>{report.CSS}
td.n{{text-align:center}}</style></head><body><main>
<header class="cover"><div class="tag">{e(course['course'])} · {e(course['module'])}</div>
<h1>Laporan Kelas</h1><p>{e(course['institution'])} · {e(course['semester'])}</p>
<div class="kpis"><div class="kpi"><span>Laporan masuk</span><b>{len(rows)}</b></div>
<div class="kpi"><span>Rata-rata skor</span><b>{avg:.1f}</b></div>
<div class="kpi"><span>Terlambat</span><b>{sum(1 for r in rows if r['terlambat'])}</b></div></div></header>
<table><thead><tr><th>NIM</th><th>Nama</th><th>Skenario</th><th>Skor</th><th>Grade</th><th>Status</th>
<th>Dikirim (WIB)</th><th>Dokumen</th></tr></thead><tbody>{body}</tbody></table>
</main></body></html>""", encoding="utf-8")


def main():
    p = argparse.ArgumentParser(prog="python -m irsim")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("seal")
    sub.add_parser("unseal")
    pv = sub.add_parser("preview")
    pv.add_argument("--nim", required=True)
    pv.add_argument("--nama", default="Mahasiswa Uji")
    pv.add_argument("--skenario", choices=SCENARIOS)
    pv.add_argument("--keputusan", default="benar", help="benar | salah | A,B,C,D,A")
    pv.add_argument("--out", default="preview")
    st = sub.add_parser("selftest")
    st.add_argument("-n", type=int, default=6)
    for name in ("setup", "rekap", "laporan"):
        sp = sub.add_parser(name)
        sp.add_argument("--repo", required=True)
        if name != "setup":
            sp.add_argument("--out", default=name)
    args = p.parse_args()

    if args.cmd == "keygen":
        target = ROOT / ".irsim.key"
        if target.exists():
            sys.exit(".irsim.key sudah ada. Hapus manual bila memang ingin mengganti kunci.")
        target.write_text(Fernet.generate_key().decode() + "\n", encoding="utf-8")
        print(f"Kunci baru: {target}. Simpan cadangannya dan daftarkan sebagai secret IRSIM_KEY.")
    elif args.cmd == "seal":
        print(f"Tersegel: {seal_bank(load_key())}")
    elif args.cmd == "unseal":
        for path in unseal_bank(load_key()):
            print(f"Dibuka: {path}")
    elif args.cmd == "preview":
        cmd_preview(args)
    elif args.cmd == "selftest":
        cmd_selftest(args)
    elif args.cmd == "setup":
        cmd_setup(args)
    elif args.cmd == "rekap":
        cmd_rekap(args)
    elif args.cmd == "laporan":
        cmd_laporan(args)


if __name__ == "__main__":
    main()
