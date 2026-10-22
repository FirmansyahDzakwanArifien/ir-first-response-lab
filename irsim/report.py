"""Dokumen debrief: Laporan Insiden, Chain of Custody, Lesson Learned, skor."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

import markdown

from .core import Case
from .scenarios import Assembled
from .scenarios.base import drift_text, sha256

STANDARDS = [
    ("ISO/IEC 27037:2012", "Identifikasi, pengumpulan, akuisisi, dan preservasi bukti digital"),
    ("RFC 3227", "Guidelines for Evidence Collection and Archiving (order of volatility)"),
    ("NIST SP 800-61r3", "Incident Response Recommendations and Considerations"),
    ("NIST SP 800-86", "Guide to Integrating Forensic Techniques into Incident Response"),
    ("UU No. 11/2008 jo. UU No. 1/2024 (ITE)", "Keabsahan informasi & dokumen elektronik sebagai alat bukti"),
    ("UU No. 27/2022 (PDP)", "Pelindungan data pribadi dalam proses investigasi"),
]


def _c(text) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _ok(flag: bool) -> str:
    return "✅" if flag else "❌"


def incident_report(case, scenario, asm: Assembled, result, student, notes, issued: datetime) -> str:
    b = asm.build
    out = [f"# Laporan Insiden — {case.case_id}", f"## Operasi {scenario['codename']} · {scenario['title']}", "",
           "| | |", "|---|---|",
           f"| **Nomor kasus** | `{case.case_id}` |",
           f"| **Klasifikasi** | {scenario['severity']} |",
           f"| **Sistem terdampak** | {b.host} — {scenario['platform']} |",
           f"| **Tanggal insiden** | {b.scene_log[0][0].strftime('%d-%m-%Y')} |",
           f"| **Responder** | {student['name']} ({student['nim']}) |",
           f"| **Diterbitkan** | {issued.strftime('%d-%m-%Y %H:%M')} WIB |",
           "| **Sifat dokumen** | RAHASIA · Simulasi akademik |", "",
           "## 1. Ringkasan", scenario["summary"], ""]
    if notes:
        out += ["**Catatan analis:**", "", *[f"> {line}" for line in notes.strip().splitlines()], ""]
    out += ["## 2. Tindakan first response", "| Waktu (WIB) | Tindakan / kejadian |", "|---|---|"]
    out += [f"| {t.strftime('%H:%M')} | {_c(m)} |" for t, m in b.scene_log]
    out += ["", "## 3. Bukti yang diamankan", "| ID | Bukti | Sumber | Volatil | Status |", "|---|---|---|:-:|---|"]
    for e in b.evidence:
        status = "Diamankan" if e.available else f"Tidak tersedia — {_c(e.reason)}"
        out.append(f"| `{e.id}` | {_c(e.title)} | {_c(e.source)} | {'Ya' if e.volatile else '—'} | {status} |")
    out += ["", "## 4. Temuan analis", "| ID | Pertanyaan | Jawaban analis | Verifikasi |", "|---|---|---|:-:|"]
    for f in result["findings"]:
        out.append(f"| {f['id']} | {_c(f['prompt'])} | `{_c(f['answer']) or '—'}` | {_ok(f['ok'])} |")
    out += ["", "## 5. Rekonstruksi kronologi (WIB, terkoreksi)", "| Waktu | Kejadian |", "|---|---|"]
    out += [f"| {t.strftime('%d-%m %H:%M:%S')} | {_c(m)} |" for t, m in b.timeline]
    out += ["", "## 6. Indicators of Compromise", "| Jenis | Nilai |", "|---|---|"]
    out += [f"| {k} | `{_c(v)}` |" for k, v in b.iocs]
    out += ["", "## 7. Rekomendasi", *[f"{i}. {r}" for i, r in enumerate(scenario.get("recommendations", []), 1)], ""]
    return "\n".join(out)


def chain_of_custody(case, scenario, asm: Assembled, result, student, issued: datetime) -> str:
    b = asm.build
    integ = result["integrity"]
    out = [f"# Formulir Chain of Custody — {case.case_id}", "",
           "| | |", "|---|---|",
           f"| **Nomor kasus** | `{case.case_id}` |",
           f"| **Operasi** | {scenario['codename']} — {scenario['title']} |",
           f"| **Lokasi** | {b.host} |",
           f"| **Petugas akuisisi** | {student['name']} ({student['nim']}) |",
           f"| **Selisih jam host** | {drift_text(asm.drift) + ' (jam host − referensi)' if b.clock_recorded else 'TIDAK TERCATAT'} |",
           "", "## A. Daftar barang bukti", "",
           "| ID | Deskripsi | Waktu akuisisi | Alat | SHA-256 saat akuisisi | Status saat diterima analis |",
           "|---|---|---|---|---|---|"]
    by_id = {m["evidence_id"]: m for m in asm.manifest}
    for e in b.evidence:
        m = by_id[e.id]
        if not e.available:
            out.append(f"| `{e.id}` | {_c(e.title)} | — | — | — | Tidak diakuisisi: {_c(e.reason)} |")
            continue
        received = sha256(asm.files[e.filename])
        state = "Cocok" if received == m["sha256"] else f"**TIDAK COCOK** — diterima `{received}`"
        out.append(f"| `{e.id}` | {_c(e.title)} | {m['acquired_at']} | {_c(e.tool)} | `{m['sha256']}` | {state} |")
    out += ["", "## B. Riwayat serah terima", "",
            "| No | Waktu (WIB) | Diserahkan oleh | Diterima oleh | Keperluan | Paraf |", "|:-:|---|---|---|---|:-:|"]
    t_end = b.scene_log[-1][0]
    out.append(f"| 1 | {t_end.strftime('%d-%m-%Y %H:%M')} | {student['name']} (first responder) | Evidence custodian CSIRT "
               f"| Penyimpanan di evidence locker | ✓ / ✓ |")
    out.append(f"| 2 | {issued.strftime('%d-%m-%Y %H:%M')} | Evidence custodian CSIRT | {student['name']} (analis) "
               f"| Salinan kerja untuk analisis | ✓ / ✓ |")
    out.append(f"| 3 | {issued.strftime('%d-%m-%Y %H:%M')} | {student['name']} (analis) | Evidence custodian CSIRT "
               f"| Pengembalian & arsip | ✓ / ✓ |")
    out += ["", "## C. Catatan kondisi & integritas", ""]
    for e in b.evidence:
        if e.note:
            out.append(f"- `{e.id}` — {e.note}")
    for note in b.custody_notes:
        out.append(f"- **Perhatian:** {note}")
    if not b.clock_recorded:
        out.append("- **Perhatian:** selisih jam host tidak tercatat; timestamp dari host tidak dapat dikalibrasi.")
    out += [f"- Hasil verifikasi analis: bukti bermasalah `{integ['id_answer'] or '—'}` {_ok(integ['id_ok'])}, "
            f"hash aktual {_ok(integ['hash_ok'])}.",
            f"- Bukti `{integ['id_truth']}` berubah setelah akuisisi (file dibuka dan disimpan ulang: BOM + CRLF). "
            "Salinan kerja diganti dari image asli; perubahan dicatat sebagai insiden integritas.", "",
            "> Setiap perpindahan barang bukti wajib dicatat dan diparaf oleh **dua pihak**. Dalam praktik, "
            "formulir ini ditandatangani basah dan disimpan bersama barang bukti.", ""]
    return "\n".join(out)


def lesson_learned(case, scenario, asm: Assembled, result, band, student, late: bool) -> str:
    p = result["parts"]
    out = [f"# Lesson Learned — {case.case_id}", f"### {student['name']} ({student['nim']})", "",
           "| Skor | Grade | Predikat |", "|:-:|:-:|:-:|",
           f"| **{result['score']} / {result['max_score']}** | **{band['grade']}** | {band['badge']} |", "",
           f"> {band['message']}", "",
           "| Komponen | Skor |", "|---|:-:|",
           f"| Keputusan di TKP | {p['keputusan'][0]} / {p['keputusan'][1]} |",
           f"| Analisis bukti | {p['analisis'][0]} / {p['analisis'][1]} |",
           f"| Integritas bukti | {p['integritas'][0]} / {p['integritas'][1]} |", ""]
    if late:
        out += ["> Laporan dikirim setelah tenggat.", ""]
    out += ["## 1. Keputusan di TKP", ""]
    for d in result["decisions"]:
        out += [f"### {_ok(d['ok'])} {d['id']} · {d['topic']}",
                f"**Pilihan Anda:** {d['chosen_text']}  ", f"**Penilaian:** {d['verdict']} — {d['earned']}/{d['weight']} poin", "",
                d["explain"], ""]
        if not d["ok"]:
            out += [f"**Tindakan yang tepat:** {d['correct_text']}", "", d["correct_explain"], ""]
        out += [f"<small>Rujukan: {d['refs']}</small>", ""]
    out += ["## 2. Analisis bukti", "", "| ID | Topik | Jawaban Anda | Kunci | Poin |", "|---|---|---|---|:-:|"]
    for f in result["findings"]:
        out.append(f"| {f['id']} | {_c(f['topic'])} | `{_c(f['answer']) or '—'}` | `{_c(f['truth'])}` | "
                   f"{f['earned']}/{f['weight']} |")
    out.append("")
    for f in result["findings"]:
        line = f"- **{f['id']} · {f['topic']}** — {f['explain']}"
        if f["blocked"]:
            why = ", ".join("selisih jam tidak tercatat" if x == "clock" else f"{x} tidak tersedia" for x in f["blocked"])
            line += f" _Pada kasus Anda: {why} akibat keputusan di TKP._"
        out.append(line)
    i = result["integrity"]
    out += ["", "## 3. Integritas bukti", "",
            f"- Bukti bermasalah: jawaban `{i['id_answer'] or '—'}`, kunci `{i['id_truth']}` {_ok(i['id_ok'])}",
            f"- SHA-256 aktual: {_ok(i['hash_ok'])} `{i['hash_truth']}`",
            "- File tersebut dibuka dan disimpan ulang dengan editor teks (BOM UTF-8 + CRLF). Isinya tampak sama, "
            "tetapi hash berubah — alasan bukti hanya dianalisis dari salinan kerja dan setiap salinan diverifikasi "
            "ulang terhadap hash akuisisi.", ""]
    weak = [d["topic"] for d in result["decisions"] if not d["ok"]] + \
           [f["topic"] for f in result["findings"] if not f["ok"]]
    out += ["## 4. Fokus belajar", ""]
    out += [f"- {t}" for t in weak] if weak else ["- Seluruh butir tepat. Coba jelaskan alasan setiap keputusan kepada rekan Anda."]
    out += ["", "## 5. Standar rujukan", "", "| Standar | Cakupan |", "|---|---|"]
    out += [f"| {a} | {b} |" for a, b in STANDARDS]
    out.append("")
    return "\n".join(out)


CSS = """
:root{--ink:#14181f;--muted:#5b6474;--line:#dfe3ea;--bg:#ffffff;--soft:#f5f7fa;--accent:#9b1c1c;--ok:#1f7a4d}
@media (prefers-color-scheme:dark){:root{--ink:#e7eaf0;--muted:#9aa3b2;--line:#2b313c;--bg:#11141a;--soft:#181c24;--accent:#f07171;--ok:#5cc894}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 "Inter",-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:40px 24px 80px}
.cover{border-bottom:3px solid var(--accent);padding-bottom:28px;margin-bottom:12px}
.cover .tag{font:600 12px/1 ui-monospace,Consolas,monospace;letter-spacing:.14em;color:var(--accent);text-transform:uppercase}
.cover h1{font-size:34px;line-height:1.15;margin:12px 0 6px;border:0}
.cover p{color:var(--muted);margin:0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:24px 0 0}
.kpi{background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
nav{display:flex;gap:18px;flex-wrap:wrap;margin:18px 0 8px;font-size:14px}nav a{color:var(--accent);text-decoration:none}
section.doc{border-top:1px solid var(--line);margin-top:40px;padding-top:8px}
h1{font-size:26px;margin:28px 0 4px}h2{font-size:19px;margin:28px 0 8px}h3{font-size:16px;margin:22px 0 6px}
table{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}th{background:var(--soft)}
code{font:12.5px ui-monospace,Consolas,monospace;background:var(--soft);padding:1px 5px;border-radius:4px;word-break:break-all}
blockquote{margin:12px 0;padding:8px 16px;border-left:3px solid var(--accent);background:var(--soft);color:var(--ink)}
small{color:var(--muted)}footer{margin-top:56px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media print{body{font-size:11pt}main{max-width:none;padding:0}section.doc{page-break-before:always;border:0}nav{display:none}
table{display:table}:root{--bg:#fff;--ink:#000;--soft:#f3f3f3;--line:#ccc}}
"""


def to_html(docs: list[tuple[str, str, str]], case, scenario, result, band, student, course, issued) -> str:
    md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists"])
    sections = []
    for anchor, title, text in docs:
        md.reset()
        sections.append(f'<section class="doc" id="{anchor}">{md.convert(text)}</section>')
    nav = "".join(f'<a href="#{a}">{html.escape(t)}</a>' for a, t, _ in docs)
    e = html.escape
    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Debrief {e(case.case_id)}</title><style>{CSS}</style></head>
<body><main>
<header class="cover">
<div class="tag">{e(course['course'])} · {e(course['module'])}</div>
<h1>Operasi {e(scenario['codename'])}</h1>
<p>{e(scenario['title'])} — kasus <code>{e(case.case_id)}</code></p>
<p>{e(student['name'])} · {e(student['nim'])} · {e(issued.strftime('%d-%m-%Y %H:%M'))} WIB</p>
<div class="kpis">
<div class="kpi"><span>Skor</span><b>{result['score']} / {result['max_score']}</b></div>
<div class="kpi"><span>Grade</span><b>{e(band['grade'])}</b></div>
<div class="kpi"><span>Predikat</span><b style="font-size:17px">{e(band['badge'])}</b></div>
</div>
</header>
<nav>{nav}</nav>
{''.join(sections)}
<footer>{e(course['institution'])} · {e(course['course'])} · {e(course['semester'])}. Dokumen simulasi untuk keperluan pendidikan.</footer>
</main></body></html>
"""


def write_debrief(root: Path, case: Case, scenario, asm, result, band, student, notes, course, issued, late,
                  login: str) -> Path:
    out = root / f"{case.case_id}-debrief"
    out.mkdir(parents=True, exist_ok=True)
    docs = [
        ("laporan", "Laporan Insiden", incident_report(case, scenario, asm, result, student, notes, issued)),
        ("coc", "Chain of Custody", chain_of_custody(case, scenario, asm, result, student, issued)),
        ("lesson", "Lesson Learned", lesson_learned(case, scenario, asm, result, band, student, late)),
    ]
    for n, (_, title, text) in enumerate(docs, 1):
        (out / f"{n:02d}_{title.replace(' ', '_')}.md").write_text(text, encoding="utf-8")
    (out / "DEBRIEF.html").write_text(to_html(docs, case, scenario, result, band, student, course, issued),
                                       encoding="utf-8")
    (out / "skor.json").write_text(json.dumps(score_record(case, scenario, result, band, student, login, issued, late),
                                              indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def score_record(case, scenario, result, band, student, login, issued, late) -> dict:
    return {
        "nim": student["nim"], "nama": student["name"], "github": login, "case_id": case.case_id,
        "skenario": scenario["id"], "skor": result["score"], "maks": result["max_score"], "persen": result["pct"],
        "grade": band["grade"], "terlambat": late, "dikirim": issued.isoformat(timespec="seconds"),
        "komponen": {k: v[0] for k, v in result["parts"].items()},
        "butir": {**{d["id"]: d["ok"] for d in result["decisions"]}, **{f["id"]: f["ok"] for f in result["findings"]},
                  "INT_ID": result["integrity"]["id_ok"], "INT_HASH": result["integrity"]["hash_ok"]},
    }
