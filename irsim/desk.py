"""Meja kasus: memproses issue & komentar dari GitHub Actions.

    python -m irsim.desk handle   # dipanggil pertama; menyiapkan paket/debrief & balasan
    python -m irsim.desk reply    # setelah upload artifact; mengirim balasan
    python -m irsim.desk fail     # bila job gagal
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

import yaml

from . import render, report
from .core import (LETTERS, ROOT, Case, DeskError, assign_scenario, grade_for, load_bank, load_course,
                   load_key, now_wib, remedial_for)
from .gh import BOT, GitHub
from .grading import grade
from .scenarios import assemble

OUT = ROOT / "out"
MARK = re.compile(r"<!-- irsim:state (\{.*?\}) -->", re.S)
LABEL_CASE, LABEL_F1, LABEL_F2 = "ir-case", "fase-1: tkp", "fase-2: analisis"
LABEL_DONE, LABEL_REJECT, LABEL_LATE = "selesai", "ditolak", "terlambat"
NIM_RE = re.compile(r"^\d{6,15}$")
REMEDIAL_TAG = " · Remedial"


# ── Utilitas kasus (dipakai juga oleh CLI lokal) ─────────────────────────────

def correct_letters(case: Case, scenario: dict) -> dict[str, str]:
    return {d["id"]: case.letter_for(d, next(o["key"] for o in d["options"] if o.get("correct")))
            for d in scenario["decisions"]}


def facts_for(case: Case, scenario: dict, course: dict) -> dict:
    return assemble(case, scenario, correct_letters(case, scenario), course).build.facts


def parse_form(body: str) -> dict[str, str]:
    fields, current = {}, None
    for line in (body or "").splitlines():
        if line.startswith("### "):
            current = line[4:].strip().lower()
            fields[current] = ""
        elif current is not None:
            fields[current] = (fields[current] + "\n" + line).strip()
    return {k: ("" if v == "_No response_" else v) for k, v in fields.items()}


DECISION_LINE = re.compile(r"^\s*D\d\s*[:=;.]\s*[A-Da-d]\b", re.M)


def parse_decisions(body: str, scenario: dict) -> dict[str, str]:
    found = {m.group(1).upper(): m.group(2).upper()
             for m in re.finditer(r"^\s*(D\d)\s*[:=;.]\s*([A-Da-d])\b", body, re.M)}
    ids = [d["id"] for d in scenario["decisions"]]
    missing = [i for i in ids if i not in found]
    if missing:
        raise DeskError(f"Keputusan belum lengkap: {', '.join(missing)}. Kirim ulang semua keputusan "
                        f"({', '.join(ids)}) dalam satu komentar, masing-masing A–{LETTERS[-1]}.")
    return {i: found[i] for i in ids}


def parse_submission(body: str) -> dict:
    lines = [ln for ln in body.splitlines() if not ln.strip().startswith("```")]
    text = "\n".join(lines)
    text = re.sub(r"^\s*/submit\s*$", "", text, count=1, flags=re.M)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None)
        where = f" (baris {mark.line + 1})" if mark else ""
        raise DeskError(f"Format YAML tidak valid{where}. Pastikan indentasi dua spasi dan tanda titik dua "
                        "diikuti spasi.") from None
    if not isinstance(data, dict) or not isinstance(data.get("temuan"), dict):
        raise DeskError("Laporan harus memuat blok `temuan:` berisi jawaban F1, F2, dst.")
    data["temuan"] = {str(k).upper(): ("" if v is None else str(v)) for k, v in data["temuan"].items()}
    integ = data.get("integritas") or {}
    if not isinstance(integ, dict):
        raise DeskError("Blok `integritas:` harus memuat `bukti_bermasalah` dan `sha256_aktual`.")
    data["integritas"] = {k: ("" if v is None else str(v)) for k, v in integ.items()}
    data["catatan"] = str(data.get("catatan") or "")[:3000]
    return data


def clean_name(raw: str) -> str:
    name = re.sub(r"[^\w .,'\-]", "", raw, flags=re.U)
    return " ".join(name.split())[:80]


# ── Penanganan event ─────────────────────────────────────────────────────────

class Desk:
    def __init__(self):
        self.event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        self.kind = os.environ["GITHUB_EVENT_NAME"]
        self.gh = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
        self.issue = self.event["issue"]
        self.number = self.issue["number"]
        self.login = self.issue["user"]["login"]
        self.course = load_course()
        self.key = load_key()
        self.bank = load_bank(self.key)
        self.outputs: dict[str, str] = {}
        self.after: dict = {}

    # state tersimpan di komentar bot sebagai penanda HTML tersembunyi
    def state(self) -> dict | None:
        latest = None
        for c in self.gh.comments(self.number):
            if c["user"]["login"] == BOT:
                m = MARK.search(c["body"] or "")
                if m:
                    latest = json.loads(m.group(1))
        return latest

    def respond(self, body: str, state: dict | None = None):
        if state is not None:
            body += f"\n\n<!-- irsim:state {json.dumps(state, separators=(',', ':'))} -->"
        OUT.mkdir(exist_ok=True)
        (OUT / "reply.md").write_text(body, encoding="utf-8")
        self.outputs["reply"] = "out/reply.md"

    def case_of(self, st: dict) -> tuple[Case, dict]:
        case = Case(self.key, st["nim"], st["scenario"], self.course["year"], bool(st.get("remedial")))
        return case, self.bank[st["scenario"]]

    def deadline(self, rem: dict | None = None) -> datetime | None:
        d = (rem or {}).get("deadline") or self.course.get("deadline")
        return datetime.fromisoformat(str(d)) if d else None

    # ── issue dibuka ─────────────────────────────────────────────────────────
    def open_case(self):
        form = parse_form(self.issue.get("body") or "")
        nim = re.sub(r"\s", "", form.get("nim", ""))
        name = clean_name(form.get("nama lengkap", ""))
        reject = None
        rem = remedial_for(self.course, nim)
        dl = self.deadline(rem)
        roster = {re.split(r"[,;\s]+", ln.strip())[0] for ln in os.environ.get("IRSIM_ROSTER", "").splitlines()
                  if ln.strip()}
        if dl and now_wib() > dl:
            reject = "Periode penugasan sudah ditutup."
        elif not NIM_RE.match(nim):
            reject = "NIM tidak valid. Buka issue baru melalui template **Penugasan Kasus IR** dan isi NIM dengan angka saja."
        elif len(name) < 3:
            reject = "Nama lengkap wajib diisi."
        elif roster and nim not in roster:
            reject = "NIM tidak terdaftar pada daftar peserta mata kuliah. Hubungi dosen/asisten."
        else:
            for other in self.gh.issues(LABEL_CASE):
                if other["number"] == self.number or not other["title"].startswith("[IR-"):
                    continue
                if any(lb["name"] == LABEL_REJECT for lb in other["labels"]):
                    continue
                # mahasiswa remedial boleh memiliki satu kasus lagi di samping kasus pertamanya
                if rem and f"] {nim} ·" in other["title"] and not other["title"].endswith(REMEDIAL_TAG):
                    continue
                if f"] {nim} ·" in other["title"]:
                    reject = f"NIM {nim} sudah memiliki kasus di #{other['number']}. Lanjutkan di issue tersebut."
                    break
                if other["user"]["login"] == self.login:
                    reject = f"Akun Anda sudah memiliki kasus di #{other['number']}. Satu mahasiswa satu kasus."
                    break
        if reject:
            self.respond(f"### Penugasan tidak dapat diproses\n\n{reject}")
            self.after = {"labels_add": [LABEL_REJECT], "close": "not_planned"}
            return
        scenario_id = rem["scenario"] if rem else assign_scenario(self.key, nim, self.course)
        case = Case(self.key, nim, scenario_id, self.course["year"], bool(rem))
        scenario = self.bank[scenario_id]
        facts = facts_for(case, scenario, self.course)
        st = {"v": 1, "stage": "fase1", "nim": nim, "name": name, "login": self.login, "scenario": scenario_id,
              "case_id": case.case_id, "opened": now_wib().isoformat(timespec="seconds")}
        body = render.briefing_comment(case, scenario, facts, self.login, self.course)
        title = f"[{case.case_id}] {nim} · {name}"
        if rem:
            st.update(remedial=True, max_grade=rem.get("max_grade"))
            note = f"> **Kasus remedial.** Grade maksimal **{rem.get('max_grade')}**"
            note += f", tenggat {dl:%d-%m-%Y %H:%M} WIB." if dl else "."
            body, title = f"{note}\n\n{body}", title + REMEDIAL_TAG
        self.respond(body, st)
        self.after = {"title": title, "labels_add": [LABEL_CASE, LABEL_F1]}

    # ── komentar ─────────────────────────────────────────────────────────────
    def command(self):
        comment = self.event["comment"]
        if comment["user"]["login"] != self.login or comment["user"].get("type") == "Bot":
            return
        body = (comment.get("body") or "").strip()
        if len(body) > 20000:
            raise DeskError("Komentar terlalu panjang.")
        cmd = body.split(None, 1)[0].lower() if body else ""
        st = self.state()
        if st is None:
            return
        # keputusan tanpa baris /respond tetap diterima selama masih fase 1
        if not cmd.startswith("/") and st["stage"] == "fase1" and DECISION_LINE.search(body):
            cmd = "/respond"
        # komentar yang diedit hanya diproses bila masih menunggu keputusan
        if self.event.get("action") == "edited" and not (cmd == "/respond" and st["stage"] == "fase1"):
            return
        if not cmd.startswith("/"):
            return
        handlers = {"/respond": self.cmd_respond, "/submit": self.cmd_submit, "/paket": self.cmd_pack,
                    "/bantuan": self.cmd_help, "/help": self.cmd_help}
        handler = handlers.get(cmd)
        if handler is None:
            raise DeskError(f"Perintah `{cmd}` tidak dikenal. Ketik `/bantuan`.")
        handler(st, body)

    def cmd_help(self, st, body):
        stage = {"fase1": "Fase 1 — menunggu keputusan di TKP", "fase2": "Fase 2 — analisis bukti",
                 "selesai": "Selesai"}[st["stage"]]
        self.respond(render.help_comment(stage))

    def cmd_respond(self, st, body):
        if st["stage"] != "fase1":
            raise DeskError("Keputusan sudah dikunci sebelumnya dan tidak dapat diubah.")
        case, scenario = self.case_of(st)
        letters = parse_decisions(body, scenario)
        asm = self._pack(case, scenario, st, letters)
        st = {**st, "stage": "fase2", "decisions": letters, "responded": now_wib().isoformat(timespec="seconds"),
              "submissions": 0}
        self.respond(render.pack_comment(case, scenario, asm, self.course), st)
        self.after = {"labels_add": [LABEL_F2], "labels_remove": [LABEL_F1]}

    def cmd_pack(self, st, body):
        if st["stage"] != "fase2":
            raise DeskError("Paket bukti hanya tersedia pada fase analisis.")
        case, scenario = self.case_of(st)
        self._pack(case, scenario, st, st["decisions"])
        self.respond(f"Paket bukti **{case.case_id}** diterbitkan ulang: "
                     "[{{PACK_NAME}}.zip]({{PACK_URL}}). Isinya identik dengan paket sebelumnya.", st)

    def _pack(self, case, scenario, st, letters):
        asm = assemble(case, scenario, letters, self.course)
        facts = facts_for(case, scenario, self.course)
        target = OUT / "pack"
        shutil.rmtree(target, ignore_errors=True)
        render.write_pack(target, case, scenario, asm, facts, {"nim": st["nim"], "name": st["name"]})
        self.outputs.update(pack_dir="out/pack", pack_name=f"paket-bukti-{case.case_id}")
        return asm

    def cmd_submit(self, st, body):
        if st["stage"] != "fase2":
            raise DeskError("Laporan hanya dapat dikirim pada fase analisis (setelah `/respond`).")
        limit = int(self.course.get("max_submissions", 1))
        if st.get("submissions", 0) >= limit:
            raise DeskError("Batas pengiriman laporan sudah tercapai.")
        answers = parse_submission(body)
        case, scenario = self.case_of(st)
        asm = assemble(case, scenario, st["decisions"], self.course)
        result = grade(scenario, asm, answers)
        band = grade_for(result["pct"], self.course, st.get("max_grade"))
        issued = now_wib()
        dl = self.deadline(remedial_for(self.course, st["nim"]) if st.get("remedial") else None)
        late = bool(dl and issued > dl)
        student = {"nim": st["nim"], "name": st["name"]}
        target = OUT / "debrief"
        shutil.rmtree(target, ignore_errors=True)
        report.write_debrief(target, case, scenario, asm, result, band, student, answers["catatan"], self.course,
                             issued, late, self.login)
        self.outputs.update(debrief_dir="out/debrief", debrief_name=f"debrief-{case.case_id}")
        used = st.get("submissions", 0) + 1
        record = report.score_record(case, scenario, result, band, student, self.login, issued, late)
        if st.get("remedial"):
            record["remedial"] = True
        st = {**st, "stage": "selesai" if used >= limit else "fase2", "submissions": used, "result": record}
        body = render.score_comment(case, result, band, late)
        if st.get("remedial"):
            body += f"\n\n<sub>Kasus remedial: grade dibatasi maksimal {st.get('max_grade')}.</sub>"
        self.respond(body, st)
        self.after = {"labels_add": [LABEL_LATE] if late else []}
        if used >= limit:
            self.after["labels_add"].append(LABEL_DONE)
            self.after.update(labels_remove=[LABEL_F2], close=True, lock=True)

    # ── entry ───────────────────────────────────────────────────────────────
    def handle(self):
        try:
            if self.kind == "issues":
                self.open_case()
            elif self.kind == "issue_comment":
                self.command()
        except DeskError as err:
            self.outputs.pop("pack_dir", None)
            self.outputs.pop("debrief_dir", None)
            self.after = {}
            self.respond(f"**Tidak dapat diproses.** {err}")
        OUT.mkdir(exist_ok=True)
        (OUT / "after.json").write_text(json.dumps(self.after), encoding="utf-8")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            for k, v in self.outputs.items():
                fh.write(f"{k}={v}\n")


def reply():
    gh = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    number = event["issue"]["number"]
    body = (OUT / "reply.md").read_text(encoding="utf-8")
    for key in ("PACK_URL", "PACK_NAME", "DEBRIEF_URL", "DEBRIEF_NAME"):
        body = body.replace("{{" + key + "}}", os.environ.get(key, ""))
    gh.comment(number, body)
    after = json.loads((OUT / "after.json").read_text(encoding="utf-8"))
    if after.get("title"):
        gh.edit_issue(number, title=after["title"])
    if after.get("labels_add"):
        gh.add_labels(number, after["labels_add"])
    for label in after.get("labels_remove", []):
        gh.remove_label(number, label)
    if after.get("close"):
        reason = after["close"] if isinstance(after["close"], str) else "completed"
        gh.edit_issue(number, state="closed", state_reason=reason)
    if after.get("lock"):
        gh.lock(number)


def fail():
    gh = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    run = f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"
    gh.comment(event["issue"]["number"],
               "**Terjadi kendala sistem saat memproses permintaan Anda.** Status kasus tidak berubah; silakan "
               f"kirim ulang perintah beberapa saat lagi. Bila berulang, laporkan ke asisten ([log run]({run})).")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "handle"
    {"handle": lambda: Desk().handle(), "reply": reply, "fail": fail}[action]()
