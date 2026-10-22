"""Teks briefing, paket bukti, dan balasan issue."""
from __future__ import annotations

import json
from pathlib import Path

from .core import LETTERS, Case
from .scenarios import Assembled
from .scenarios.base import drift_text, fill

TOOL_HINTS = (
    "Alat yang disarankan: `sha256sum` / `Get-FileHash`, `grep` / `Select-String`, `awk`, `sort`, `uniq -c`, "
    "Timeline Explorer, dan CyberChef. Semua jawaban dapat diturunkan dari isi paket bukti."
)


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def header(case: Case, scenario: dict, login: str) -> str:
    return (f"## {case.case_id} · Operasi {scenario['codename']}\n"
            f"**{scenario['title']}**  \n"
            f"`{scenario['severity']}` · {scenario['platform']} · Penanggung jawab: @{login}\n")


def briefing_comment(case: Case, scenario: dict, facts: dict, login: str, course: dict) -> str:
    out = [header(case, scenario, login), fill(scenario["briefing"].strip(), facts), "", "---", "",
           "### Fase 1 — Keputusan di TKP",
           "Ambil lima keputusan berikut. **Keputusan dikunci setelah dikirim**, dan konsekuensinya "
           "menentukan bukti apa saja yang berhasil diamankan untuk Anda analisis di fase berikutnya.", ""]
    for d in scenario["decisions"]:
        out.append(f"#### {d['id']} · {d['topic']}")
        out.append(fill(d["prompt"], facts))
        out.append("")
        out.append("| | Tindakan |")
        out.append("|:-:|---|")
        for letter, opt in zip(LETTERS, case.option_order(d)):
            out.append(f"| **{letter}** | {_cell(fill(opt['text'], facts))} |")
        out.append("")
    out += ["### Kirim keputusan", "Balas issue ini dengan satu komentar berformat seperti di bawah "
            "(ganti huruf sesuai pilihan Anda):", "", "```text", "/respond"]
    out += [f"{d['id']}: A" for d in scenario["decisions"]]
    out += ["```", "",
            "<sub>Urutan opsi diacak untuk setiap mahasiswa; huruf jawaban orang lain tidak berlaku untuk kasus "
            "Anda. Ketik <code>/bantuan</code> untuk melihat daftar perintah.</sub>"]
    return "\n".join(out)


def scene_rows(asm: Assembled) -> list[str]:
    rows = ["| Waktu (WIB) | Catatan |", "|---|---|"]
    for t, msg in asm.build.scene_log:
        rows.append(f"| {t.strftime('%H:%M')} | {_cell(msg)} |")
    return rows


def evidence_rows(asm: Assembled) -> list[str]:
    rows = ["| ID | Bukti | Sumber | Status |", "|---|---|---|---|"]
    for e in asm.build.evidence:
        if e.available:
            status = "Diamankan" + (f" — _{_cell(e.note)}_" if e.note else "")
        else:
            status = f"**Tidak tersedia** — {_cell(e.reason)}"
        rows.append(f"| `{e.id}` | {_cell(e.title)} | {_cell(e.source)} | {status} |")
    return rows


def submit_template(scenario: dict) -> list[str]:
    lines = ["/submit", "temuan:"]
    lines += [f"  {f['id']}: " for f in scenario["findings"]]
    lines += ["integritas:", "  bukti_bermasalah: EV-00?", "  sha256_aktual: ",
              "catatan: |", "  Ringkasan singkat analisis Anda (opsional, dicetak di laporan insiden)."]
    return lines


def questions(scenario: dict) -> list[str]:
    rows = ["| ID | Pertanyaan |", "|---|---|"]
    for f in scenario["findings"]:
        rows.append(f"| **{f['id']}** | {_cell(f['prompt'])} |")
    return rows


def pack_comment(case: Case, scenario: dict, asm: Assembled, course: dict) -> str:
    limit = course.get("max_submissions", 1)
    out = [f"## Paket bukti {case.case_id} siap", "",
           "Keputusan Anda sudah dikunci. Berikut jalannya penanganan di TKP berdasarkan keputusan tersebut.", "",
           "### Log tindakan di TKP", *scene_rows(asm), "",
           "### Bukti yang diamankan", *evidence_rows(asm), "",
           "**Unduh paket bukti:** [{{PACK_NAME}}.zip]({{PACK_URL}})  ",
           "<sub>Artifact tersedia selama 30 hari. Ketik <code>/paket</code> untuk menerbitkan ulang tautan.</sub>", "",
           "---", "",
           "### Fase 2 — Analisis forensik",
           "1. **Verifikasi integritas.** Hitung SHA-256 setiap file di folder `bukti/` dan bandingkan dengan "
           "`MANIFEST_AKUISISI.json`. Satu bukti tidak lagi cocok dengan hash saat akuisisi — identifikasi dan "
           "catat hash aktualnya.",
           "2. **Analisis bukti** dan jawab pertanyaan berikut. Pertanyaan yang buktinya tidak tersedia tetap boleh "
           "dijawab jika Anda menemukannya di sumber lain.", "",
           *questions(scenario), "",
           TOOL_HINTS, "",
           "### Kirim laporan", "Balas issue ini dengan satu komentar:", "", "```yaml",
           *submit_template(scenario), "```", "",
           f"<sub>Laporan hanya dapat dikirim {limit} kali. Waktu ditulis HH:MM:SS (WIB terkoreksi).</sub>"]
    return "\n".join(out)


def score_comment(case: Case, result: dict, band: dict, late: bool) -> str:
    p = result["parts"]
    mark = lambda ok: "✅" if ok else "❌"  # noqa: E731
    out = [f"## Hasil evaluasi · {case.case_id}", "",
           "| Skor | Grade | Predikat |", "|:-:|:-:|:-:|",
           f"| **{result['score']} / {result['max_score']}** | **{band['grade']}** | {band['badge']} |", "",
           "| Komponen | Skor |", "|---|:-:|",
           f"| Keputusan di TKP | {p['keputusan'][0]} / {p['keputusan'][1]} |",
           f"| Analisis bukti | {p['analisis'][0]} / {p['analisis'][1]} |",
           f"| Integritas bukti | {p['integritas'][0]} / {p['integritas'][1]} |", ""]
    if late:
        out += ["> Laporan dikirim setelah tenggat dan ditandai **terlambat**.", ""]
    out += ["<details><summary>Rincian per butir</summary>", "", "| Butir | Topik | Hasil |", "|---|---|:-:|"]
    for d in result["decisions"]:
        out.append(f"| {d['id']} | {_cell(d['topic'])} | {mark(d['ok'])} |")
    for f in result["findings"]:
        out.append(f"| {f['id']} | {_cell(f['topic'])} | {mark(f['ok'])} |")
    i = result["integrity"]
    out.append(f"| INT | Bukti bermasalah | {mark(i['id_ok'])} |")
    out.append(f"| INT | SHA-256 aktual | {mark(i['hash_ok'])} |")
    out += ["", "</details>", "",
            "**Debrief lengkap:** [{{DEBRIEF_NAME}}.zip]({{DEBRIEF_URL}}) — Laporan Insiden, Chain of Custody, "
            "Lesson Learned, dan skor (HTML siap cetak + Markdown).", "",
            "Kasus ditutup. Terima kasih, responder."]
    return "\n".join(out)


def help_comment(stage: str) -> str:
    return "\n".join([
        "### Perintah yang tersedia", "",
        "| Perintah | Fungsi |", "|---|---|",
        "| `/respond` | Mengirim keputusan D1–D5 (fase 1) |",
        "| `/paket` | Menerbitkan ulang tautan paket bukti (fase 2) |",
        "| `/submit` | Mengirim laporan analisis (fase 2) |",
        "| `/bantuan` | Menampilkan pesan ini |", "",
        f"Status kasus saat ini: **{stage}**.",
    ])


# ── Paket bukti ──────────────────────────────────────────────────────────────

def write_pack(root: Path, case: Case, scenario: dict, asm: Assembled, facts: dict, student: dict) -> Path:
    pack = root / case.case_id
    (pack / "bukti").mkdir(parents=True, exist_ok=True)
    for name, data in asm.files.items():
        (pack / "bukti" / name).write_bytes(data)
    (pack / "MANIFEST_AKUISISI.json").write_text(json.dumps({
        "case_id": case.case_id, "operation": scenario["codename"], "examiner": f"{student['name']} ({student['nim']})",
        "hash_algorithm": "SHA-256", "evidence": asm.manifest,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    notes = [f"LOG AKTIVITAS RESPONDER — {case.case_id}", f"Responder : {student['name']} ({student['nim']})",
             f"Tanggal   : {asm.build.scene_log[0][0].strftime('%d-%m-%Y')}", "Zona waktu: WIB (UTC+7), jam referensi tim",
             "-" * 72]
    for t, msg in asm.build.scene_log:
        notes.append(f"{t.strftime('%H:%M:%S')}  {' '.join(msg.split())}")
    (pack / "CATATAN_RESPONDER.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")

    md = [f"# {case.case_id} · Operasi {scenario['codename']}", f"**{scenario['title']}** — {scenario['severity']}",
          "", f"Responder: **{student['name']}** ({student['nim']})  ", f"Platform: {scenario['platform']}", "",
          "## Situasi", fill(scenario["briefing"].strip(), facts), "",
          "## Log tindakan di TKP", *scene_rows(asm), "",
          "## Bukti", *evidence_rows(asm), "",
          "Catatan format waktu: log yang berasal dari host memakai **jam host** (belum dikoreksi). "
          "Lihat `CATATAN_RESPONDER.txt` untuk selisih jam bila tercatat.", "",
          "## Pertanyaan analisis", *questions(scenario), "",
          "## Verifikasi integritas",
          "Hitung SHA-256 setiap file di `bukti/` dan bandingkan dengan `MANIFEST_AKUISISI.json`.", "",
          "```bash", "sha256sum bukti/*", "```", "", "```powershell",
          "Get-FileHash .\\bukti\\* -Algorithm SHA256 | Format-Table Hash, Path", "```", "",
          "## Format laporan", "Kirim sebagai komentar pada issue kasus Anda:", "", "```yaml",
          *submit_template(scenario), "```", ""]
    (pack / "BRIEFING.md").write_text("\n".join(md), encoding="utf-8")
    return pack


__all__ = ["briefing_comment", "pack_comment", "score_comment", "help_comment", "write_pack", "drift_text"]
