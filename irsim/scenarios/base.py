"""Struktur bersama untuk generator bukti forensik."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from string import Template


@dataclass
class Evidence:
    key: str
    id: str
    filename: str
    title: str
    source: str
    volatile: bool
    tool: str
    content: str = ""
    available: bool = True
    reason: str = ""
    note: str = ""
    acquired_at: datetime | None = None


@dataclass
class Context:
    rng: random.Random
    bank: dict
    effects: set[str]
    outcomes: dict[str, str]        # id keputusan -> narasi hasil di TKP
    day: datetime                    # tengah malam WIB tanggal insiden
    drift: timedelta                 # jam host = jam benar + drift
    case_id: str


@dataclass
class Build:
    host: str
    evidence: list[Evidence]
    truth: dict[str, str]
    scene_log: list[tuple[datetime, str]]
    timeline: list[tuple[datetime, str]]
    facts: dict[str, str]
    iocs: list[tuple[str, str]]
    clock_recorded: bool
    custody_notes: list[str] = field(default_factory=list)

    def by_key(self, key: str) -> Evidence:
        return next(e for e in self.evidence if e.key == key)


def fill(text: str, values: dict) -> str:
    return Template(text).safe_substitute(values)


def drift_text(drift: timedelta) -> str:
    secs = int(drift.total_seconds())
    sign = "+" if secs >= 0 else "-"
    secs = abs(secs)
    return f"{sign}{secs // 3600:02d}:{secs % 3600 // 60:02d}:{secs % 60:02d}"


def hms(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")


def clock_values(ctx: Context, values: dict, at: datetime) -> dict:
    """Nilai untuk narasi pencatatan jam: jam host vs jam referensi pada saat `at`."""
    return dict(values, ref_clock=hms(at), host_clock=hms(at + ctx.drift), drift=drift_text(ctx.drift))


def stamp(rng: random.Random, dt: datetime) -> datetime:
    """Waktu kasar (hari/menit) diberi detik & mikrodetik acak."""
    return dt.replace(second=rng.randint(0, 59), microsecond=rng.randint(0, 999_999))


def jitter(rng: random.Random, dt: datetime) -> datetime:
    return dt.replace(microsecond=rng.randint(0, 999_999))


def testnet_ip(rng: random.Random) -> str:
    # Rentang dokumentasi RFC 5737 — tidak pernah dirutekan di internet.
    return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(5, 250)}"


def public_ip(rng: random.Random) -> str:
    first = rng.choice([36, 39, 103, 110, 112, 114, 116, 118, 120, 125, 140, 180, 182, 202])
    return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(2, 254)}"


def hexstr(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789ABCDEF") for _ in range(n))


def noise_strings(rng: random.Random, count: int, extra: list[str]) -> list[str]:
    """Baris mirip keluaran `strings` dari image memori."""
    vocab = [
        "kernel32.dll", "ntdll.dll", "KERNELBASE.dll", "advapi32.dll", "bcrypt.dll", "crypt32.dll",
        "ws2_32.dll", "msvcrt.dll", "user32.dll", "combase.dll", "rpcrt4.dll", "sechost.dll",
        "GetProcAddress", "LoadLibraryExW", "VirtualAlloc", "CreateFileW", "ReadFile", "WriteFile",
        "RegOpenKeyExW", "CryptAcquireContextW", "WSAStartup", "InternetOpenUrlA", "NtQuerySystemInformation",
        "\\Device\\HarddiskVolume2\\Windows\\System32", "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services",
        "Content-Type: application/octet-stream", "Accept-Language: en-US", "HTTP/1.1 200 OK",
        "Microsoft Enhanced RSA and AES Cryptographic Provider", "MZ", "This program cannot be run in DOS mode.",
        "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libpthread.so.0", "GLIBC_2.34",
        "LANG=C.UTF-8", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin", "TERM=xterm-256color",
    ] + extra
    lines = []
    for _ in range(count):
        roll = rng.random()
        if roll < 0.55:
            lines.append(rng.choice(vocab))
        elif roll < 0.75:
            lines.append("{" + "-".join(hexstr(rng, n) for n in (8, 4, 4, 4, 12)) + "}")
        elif roll < 0.9:
            lines.append("".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+")
                                 for _ in range(rng.randint(8, 40))))
        else:
            lines.append(f"0x{hexstr(rng, 16)}")
    return lines


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tamper(data: bytes) -> bytes:
    """Simulasi file yang dibuka lalu disimpan ulang di Notepad: BOM + CRLF."""
    return b"\xef\xbb\xbf" + data.replace(b"\n", b"\r\n")


def csv_cell(value) -> str:
    s = str(value)
    if any(c in s for c in ',"\n'):
        return '"' + s.replace('"', '""') + '"'
    return s
