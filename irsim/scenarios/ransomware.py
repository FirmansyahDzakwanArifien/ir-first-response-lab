"""Skenario: ransomware pada file server keuangan (Windows Server)."""
from __future__ import annotations

import json
from datetime import timedelta
from string import ascii_lowercase, digits

from .base import (Build, Context, Evidence, clock_values, csv_cell, fill, hexstr, hms,
                   jitter, noise_strings, stamp, testnet_ip)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]


def build(ctx: Context) -> Build:
    r, P, fx = ctx.rng, ctx.bank["pools"], ctx.effects

    # ── Nilai unik per mahasiswa (diambil dulu agar tidak bergantung keputusan)
    org = r.choice(P["organizations"])
    dom = org["netbios"]
    net = r.randint(16, 60)
    server = "SRV-FIN-01"
    srv_ip = f"10.{net}.10.{r.randint(11, 60)}"
    dc_ip = f"10.{net}.10.{r.randint(2, 9)}"
    staff = r.sample(P["finance_users"], 7)
    laptop_user = staff[0]
    laptop = f"LT-FIN-{r.randint(1, 30):02d}"
    lt_ip = f"10.{net}.30.{r.randint(20, 230)}"
    admin = r.choice(P["admin_users"])
    malproc = r.choice(P["malicious_process"])
    malpid = r.randrange(3000, 9800, 4)
    cmdpid = malpid + r.randrange(8, 120, 4)
    svc = r.choice(P["service_names"])
    drop = fill(r.choice(P["drop_dirs"]), {"rand": hexstr(r, 6).lower()})
    c2_ip, c2_port = testnet_ip(r), r.choice([443, 8443, 4443, 8080, 9001, 2053])
    ext = "." + "".join(r.choice(ascii_lowercase + digits) for _ in range(5))
    note = r.choice(P["ransom_notes"])
    campaign = f"{r.choice(P['campaign_prefix'])}-{hexstr(r, 6)}"
    attachment = fill(r.choice(P["attachment_templates"]),
                      {"n": str(r.randint(1000, 9899)), "bulan": r.choice(MONTHS[6:])})
    attempts = r.randint(14, 46)
    task = r.choice(P["task_names"])

    day = ctx.day
    t0 = jitter(r, day + timedelta(hours=1, minutes=r.randint(18, 48), seconds=r.randint(0, 59)))
    t_phish = stamp(r, day - timedelta(days=1) + timedelta(hours=r.randint(14, 16), minutes=r.randint(0, 59)))
    tries, t = [], t0
    for _ in range(attempts):
        tries.append(t)
        t = jitter(r, t + timedelta(seconds=r.randint(1, 4)))
    t_logon = jitter(r, t + timedelta(seconds=r.randint(3, 20)))
    t_svc = jitter(r, t_logon + timedelta(minutes=r.randint(3, 8), seconds=r.randint(0, 59)))
    t_task = jitter(r, t_svc + timedelta(seconds=r.randint(10, 40)))
    t_proc = jitter(r, t_task + timedelta(seconds=r.randint(5, 30)))
    t_clear = jitter(r, t_proc + timedelta(minutes=r.randint(1, 3)))
    t_enc = jitter(r, t_proc + timedelta(minutes=r.randint(2, 4)))
    t_alert = (t_enc + timedelta(minutes=r.randint(9, 15))).replace(microsecond=0)
    t_contain = t_alert + timedelta(minutes=r.randint(5, 9))
    t_arrive = t_alert + timedelta(minutes=r.randint(25, 40), seconds=r.randint(0, 59))

    # Daftar file di share D:\Finance
    folders = r.sample(P["finance_folders"], 5)
    files = []
    for i in range(r.randint(260, 520)):
        name = fill(r.choice(P["file_templates"]), {
            "n": str(r.randint(100, 9999)), "bulan": r.choice(MONTHS), "tahun": str(r.choice([2024, 2025, 2026])),
            "vendor": r.choice(P["vendors"]),
        })
        folder = r.choice(folders)
        created = stamp(r, day - timedelta(days=r.randint(5, 700), minutes=r.randint(0, 900)))
        modified = stamp(r, created + timedelta(days=r.randint(0, 4), minutes=r.randint(0, 500)))
        accessed = max(modified, stamp(r, day - timedelta(days=r.randint(0, 30), minutes=r.randint(0, 900))))
        files.append({"path": f"D:\\Finance\\{folder}\\{name}", "folder": folder,
                      "size": r.randint(18_000, 9_800_000), "c": created, "m": modified, "a": accessed})
    # Hilangkan duplikat path, pertahankan urutan
    seen, uniq = set(), []
    for f in files:
        if f["path"] not in seen:
            seen.add(f["path"])
            uniq.append(f)
    files = uniq
    order = files[:]
    r.shuffle(order)
    enc_count = int(len(order) * r.uniform(0.55, 0.78))
    t, first_in_folder = t_enc, {}
    for f in order[:enc_count]:
        f["path"] += ext
        f["size"] += 512
        f["c"] = f["m"] = f["a"] = t
        first_in_folder.setdefault(f["folder"], t)
        t = jitter(r, t + timedelta(seconds=r.randint(1, 3)))
    for folder, when in first_in_folder.items():
        files.append({"path": f"D:\\Finance\\{folder}\\{note}", "folder": folder, "size": r.randint(1800, 2600),
                      "c": when, "m": when, "a": when})

    host = lambda dt: dt + ctx.drift  # noqa: E731 — jam sistem server
    values = {
        "org": org["name"], "org_short": org["short"], "server": server, "server_ip": srv_ip,
        "laptop": laptop, "laptop_user": laptop_user, "malproc": malproc, "alert_time": hms(t_alert),
        "arrive_time": hms(t_arrive), "domain": dom,
    }

    # ── EV-001 tasklist (live response EDR) ─────────────────────────────────
    base_procs = [
        ("System Idle Process", 0, "Services", "8 K", "NT AUTHORITY\\SYSTEM"),
        ("System", 4, "Services", "140 K", "N/A"),
        ("Registry", 92, "Services", "61,204 K", "N/A"),
        ("smss.exe", 348, "Services", "1,092 K", "NT AUTHORITY\\SYSTEM"),
        ("csrss.exe", 452, "Services", "5,320 K", "NT AUTHORITY\\SYSTEM"),
        ("wininit.exe", 528, "Services", "6,840 K", "NT AUTHORITY\\SYSTEM"),
        ("services.exe", 604, "Services", "10,112 K", "NT AUTHORITY\\SYSTEM"),
        ("lsass.exe", 620, "Services", "21,448 K", "NT AUTHORITY\\SYSTEM"),
    ]
    pid = 700
    for svcname, user in [("svchost.exe", "NT AUTHORITY\\SYSTEM"), ("svchost.exe", "NT AUTHORITY\\NETWORK SERVICE"),
                          ("svchost.exe", "NT AUTHORITY\\LOCAL SERVICE"), ("svchost.exe", "NT AUTHORITY\\SYSTEM"),
                          ("spoolsv.exe", "NT AUTHORITY\\SYSTEM"), ("svchost.exe", "NT AUTHORITY\\SYSTEM"),
                          ("dfsrs.exe", "NT AUTHORITY\\SYSTEM"), ("svchost.exe", "NT AUTHORITY\\LOCAL SERVICE"),
                          ("edr-agent.exe", "NT AUTHORITY\\SYSTEM"), ("vmtoolsd.exe", "NT AUTHORITY\\SYSTEM"),
                          ("svchost.exe", "NT AUTHORITY\\NETWORK SERVICE"), ("WmiPrvSE.exe", "NT AUTHORITY\\SYSTEM"),
                          ("msdtc.exe", "NT AUTHORITY\\NETWORK SERVICE"), ("svchost.exe", "NT AUTHORITY\\SYSTEM"),
                          ("SearchIndexer.exe", "NT AUTHORITY\\SYSTEM"), ("svchost.exe", "NT AUTHORITY\\LOCAL SERVICE"),
                          ("sqlwriter.exe", "NT AUTHORITY\\SYSTEM"), ("WmiPrvSE.exe", "NT AUTHORITY\\NETWORK SERVICE"),
                          ("dllhost.exe", "NT AUTHORITY\\SYSTEM"), ("svchost.exe", "NT AUTHORITY\\SYSTEM"),
                          ("taskhostw.exe", f"{dom}\\{admin}"), ("explorer.exe", f"{dom}\\{admin}"),
                          ("RuntimeBroker.exe", f"{dom}\\{admin}"), ("ctfmon.exe", f"{dom}\\{admin}"),
                          ("conhost.exe", "NT AUTHORITY\\SYSTEM")]:
        pid += r.randrange(24, 260, 4)
        sess = "Console" if "\\" + admin in user else "Services"
        base_procs.append((svcname, pid, sess, f"{r.randint(1200, 98000):,} K", user))
    if "av_tampered" not in fx:
        base_procs.append((malproc, malpid, "Services", f"{r.randint(40000, 180000):,} K", "NT AUTHORITY\\SYSTEM"))
        base_procs.append(("cmd.exe", cmdpid, "Services", "4,016 K", "NT AUTHORITY\\SYSTEM"))
    base_procs.append(("tasklist.exe", pid + 1880, "Services", "8,240 K", "NT AUTHORITY\\SYSTEM"))
    base_procs.sort(key=lambda p: p[1])
    rows = ['"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"']
    for name, p, sess, mem, user in base_procs:
        status = "Running" if sess == "Console" else "Unknown"
        if name == malproc:
            status = "Suspended" if "edr_suspended" in fx else "Unknown"
        cpu = f"0:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}"
        rows.append(f'"{name}","{p}","{sess}","{0 if sess == "Services" else 1}","{mem}","{status}","{user}","{cpu}","N/A"')
    tasklist = "\n".join(rows) + "\n"

    # ── EV-002 netstat -anob ────────────────────────────────────────────────
    def nline(proto, local, remote, state, p, owner, svcname=None):
        out = f"  {proto:<6} {local:<22} {remote:<22} {state:<15} {p}"
        if svcname:
            out += f"\n  {svcname}"
        return out + f"\n [{owner}]"

    pid_of = {n: p for n, p, *_ in base_procs}
    conns = [
        nline("TCP", "0.0.0.0:135", "0.0.0.0:0", "LISTENING", pid_of["svchost.exe"], "svchost.exe", "RpcSs"),
        "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n Can not obtain ownership information",
        nline("TCP", "0.0.0.0:3389", "0.0.0.0:0", "LISTENING", pid_of["svchost.exe"], "svchost.exe", "TermService"),
        "  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4\n Can not obtain ownership information",
        nline("TCP", "0.0.0.0:49664", "0.0.0.0:0", "LISTENING", 620, "lsass.exe"),
        nline("TCP", "0.0.0.0:49665", "0.0.0.0:0", "LISTENING", 528, "wininit.exe"),
        nline("TCP", "0.0.0.0:49668", "0.0.0.0:0", "LISTENING", pid_of["spoolsv.exe"], "spoolsv.exe"),
    ]
    for u in staff[1:]:
        ip = f"10.{net}.30.{r.randint(20, 230)}"
        conns.append(f"  TCP    {srv_ip}:445{'':<{22 - len(srv_ip) - 4}} {ip + ':' + str(r.randint(49700, 65000)):<22} "
                     f"ESTABLISHED     4\n Can not obtain ownership information")
    conns.append(f"  TCP    {srv_ip}:445{'':<{22 - len(srv_ip) - 4}} {lt_ip + ':' + str(r.randint(49700, 65000)):<22} "
                 f"ESTABLISHED     4\n Can not obtain ownership information")
    for port in (389, 88, 135):
        conns.append(nline("TCP", f"{srv_ip}:{r.randint(50000, 64000)}", f"{dc_ip}:{port}", "ESTABLISHED", 620, "lsass.exe"))
    conns.append(nline("TCP", f"{srv_ip}:{r.randint(50000, 64000)}", f"10.{net}.5.20:443", "ESTABLISHED",
                       pid_of["edr-agent.exe"], "edr-agent.exe"))
    if "av_tampered" not in fx:
        state = "SYN_SENT" if "edr_suspended" in fx else "ESTABLISHED"
        conns.append(nline("TCP", f"{srv_ip}:{r.randint(50000, 64000)}", f"{c2_ip}:{c2_port}", state, malpid, malproc))
    conns.append(nline("UDP", "0.0.0.0:123", "*:*", "", pid_of["svchost.exe"], "svchost.exe", "W32Time"))
    conns.append(nline("UDP", "0.0.0.0:5355", "*:*", "", pid_of["svchost.exe"], "svchost.exe", "Dnscache"))
    head, rest = conns[:7], conns[7:]
    r.shuffle(rest)
    netstat = ("\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n"
               + "\n".join(head + rest) + "\n")

    # ── EV-003 strings dari image memori ───────────────────────────────────
    config = json.dumps({"cmp": campaign, "c2": f"{c2_ip}:{c2_port}", "ext": ext, "note": note,
                         "kill": ["sqlservr", "veeam", "msexchange", "backup"], "net": True, "wipe_vss": True},
                        separators=(",", ":"))
    mem_lines = noise_strings(r, 2600, [f"{drop}\\{malproc}", "vssadmin.exe delete shadows /all /quiet",
                                         "bcdedit /set {default} recoveryenabled No", f"\\\\{server}\\Finance$"])
    if "av_tampered" not in fx:
        mem_lines.insert(r.randint(400, 2200), config)
        mem_lines.insert(r.randint(100, 2400), f"YOUR FILES ARE ENCRYPTED. ID: {campaign}")
    memory = "\n".join(mem_lines) + "\n"

    # ── EV-004 log peristiwa (Security + System + Application) ─────────────
    events = []

    def ev(dt, eid, channel, keywords, user, remote, desc, p1, p2="", exe=""):
        events.append((dt, eid, channel, keywords, user, remote, desc, p1, p2, exe))

    win_start = t0 - timedelta(hours=3)
    span = int((t_arrive - win_start).total_seconds())
    for _ in range(r.randint(520, 700)):
        dt = jitter(r, win_start + timedelta(seconds=r.randint(0, span)))
        u = r.choice(staff[1:])
        roll = r.random()
        if roll < 0.32:
            ev(dt, 4624, "Security", "Audit Success", f"{dom}\\{u}", f"- ({f'10.{net}.30.{r.randint(20, 230)}'})",
               "Successful logon", "LogonType 3", "AuthPackage Kerberos")
        elif roll < 0.55:
            ev(dt, 4634, "Security", "Audit Success", f"{dom}\\{u}", "", "An account was logged off", "LogonType 3")
        elif roll < 0.72:
            ev(dt, 5140, "Security", "Audit Success", f"{dom}\\{u}", f"10.{net}.30.{r.randint(20, 230)}",
               "Network share accessed", "Share: \\\\*\\Finance$", "Access 0x1")
        elif roll < 0.82:
            ev(dt, 7036, "System", "Classic", "", "", "Service state change",
               f"Name: {r.choice(['Windows Update', 'BITS', 'WinHTTP Web Proxy Auto-Discovery Service', 'Windows Modules Installer', 'Device Setup Manager'])}",
               f"State: {r.choice(['running', 'stopped'])}")
        elif roll < 0.88:
            ev(dt, 4672, "Security", "Audit Success", f"{dom}\\svc_backup", "", "Special privileges assigned",
               "SeBackupPrivilege SeRestorePrivilege")
        elif roll < 0.93:
            ev(dt, 4625, "Security", "Audit Failure", f"{dom}\\{u}", f"- ({f'10.{net}.30.{r.randint(20, 230)}'})",
               "Failed logon", "LogonType 3", "Status 0xC000006D SubStatus 0xC000006A")
        else:
            ev(dt, 4768, "Security", "Audit Success", f"{dom}\\{u}", dc_ip, "Kerberos TGT requested", "Result 0x0")
    for dt in tries:
        ev(dt, 4625, "Security", "Audit Failure", f"{dom}\\{admin}", f"{laptop} ({lt_ip})", "Failed logon",
           "LogonType 3", "Status 0xC000006D SubStatus 0xC000006A")
    ev(t_logon, 4624, "Security", "Audit Success", f"{dom}\\{admin}", f"{laptop} ({lt_ip})", "Successful logon",
       "LogonType 3", "AuthPackage NTLM")
    ev(jitter(r, t_logon), 4672, "Security", "Audit Success", f"{dom}\\{admin}", "", "Special privileges assigned",
       "SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege")
    ev(t_svc, 7045, "System", "Classic", f"{dom}\\{admin}", "", "A service was installed in the system",
       f"Name: {svc}", f"ImagePath: {drop}\\{malproc}", f"{drop}\\{malproc}")
    ev(t_task, 4698, "Security", "Audit Success", f"{dom}\\{admin}", "", "A scheduled task was created",
       f"TaskName: {task}", f"Command: {drop}\\{malproc} -s")
    ev(t_proc, 4688, "Security", "Audit Success", "NT AUTHORITY\\SYSTEM", "", "A new process has been created",
       f"NewProcessName: {drop}\\{malproc}", "ParentProcessName: C:\\Windows\\System32\\services.exe",
       f"{drop}\\{malproc}")
    ev(jitter(r, t_proc + timedelta(seconds=8)), 4688, "Security", "Audit Success", "NT AUTHORITY\\SYSTEM", "",
       "A new process has been created", "NewProcessName: C:\\Windows\\System32\\vssadmin.exe",
       f"ParentProcessName: {drop}\\{malproc}", "vssadmin.exe delete shadows /all /quiet")
    ev(t_clear, 104, "System", "Classic", f"{dom}\\{admin}", "", "The log file was cleared", "Channel: Application")
    ev(t_contain if "edr_suspended" in fx else t_arrive, 1, "Application", "Classic", "", "",
       "EDR agent notification", "Host containment state changed", "Isolated" if "edr_suspended" in fx else "Online")
    events.sort(key=lambda e: e[0])
    header = "TimeCreated,EventId,Channel,Computer,Keywords,UserName,RemoteHost,MapDescription,PayloadData1,PayloadData2,ExecutableInfo"
    evrows = [header]
    for dt, eid, ch, kw, user, remote, desc, p1, p2, exe in events:
        ts = host(dt).strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}0"
        evrows.append(",".join(csv_cell(x) for x in (ts, eid, ch, f"{server}.{dom.lower()}.local", kw, user, remote,
                                                 desc, p1, p2, exe)))
    eventlog = "\n".join(evrows) + "\n"

    # ── EV-005 listing file D:\Finance ─────────────────────────────────────
    t_scene = t_arrive + timedelta(minutes=15)
    if "fs_contaminated" in fx:
        for f in files:
            f["a"] = jitter(r, t_scene + timedelta(seconds=r.randint(0, 240)))
        for folder in folders:
            files.append({"path": f"D:\\Finance\\{folder}\\Thumbs.db", "folder": folder, "size": r.randint(9000, 60000),
                          "c": t_scene, "m": t_scene, "a": t_scene})
    files.sort(key=lambda f: f["path"].lower())
    fsrows = ["FullPath,SizeBytes,Created,Modified,Accessed"]
    fmt = lambda dt: host(dt).strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731
    for f in files:
        fsrows.append(",".join([csv_cell(f["path"]), str(f["size"]), fmt(f["c"]), fmt(f["m"]), fmt(f["a"])]))
    fslist = "\n".join(fsrows) + "\n"

    # ── EV-006 triage laptop ───────────────────────────────────────────────
    olk = hexstr(r, 8)
    benign = [fill(x, {"n": str(r.randint(100, 999))}) for x in r.sample(P["benign_attachments"], 5)]
    lap = [f"# Triage {laptop} — dikumpulkan dengan KAPE (target: !SANS_Triage)", f"# Pengguna aktif: {dom}\\{laptop_user}", "",
           f"== C:\\Users\\{laptop_user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{olk}\\ ==",
           "LastWriteTime (lokal)     Length  Name"]
    items = [(stamp(r, t_phish - timedelta(days=r.randint(0, 9), minutes=r.randint(10, 600))), b) for b in benign]
    items.append((t_phish, attachment))
    for dt, name in sorted(items):
        lap.append(f"{dt.strftime('%Y-%m-%d %H:%M:%S')}  {r.randint(40_000, 2_400_000):>8}  {name}")
    lap += ["", "== C:\\Windows\\Prefetch (diurai PECmd) ==", "LastRun (lokal)           RunCount  Executable"]
    pf = [(stamp(r, t_phish - timedelta(hours=r.randint(1, 60), minutes=r.randint(0, 59))), r.randint(2, 90), x)
          for x in ["OUTLOOK.EXE", "EXCEL.EXE", "MSEDGE.EXE", "ONEDRIVE.EXE", "TEAMS.EXE", "WINWORD.EXE", "ACRORD32.EXE"]]
    pf.append((jitter(r, t_phish + timedelta(seconds=r.randint(20, 90))), 1, attachment.upper()))
    pf.append((jitter(r, t_phish + timedelta(minutes=r.randint(2, 5))), 1, "POWERSHELL.EXE"))
    pf.append((jitter(r, t0 - timedelta(minutes=r.randint(2, 9))), 1, "NET.EXE"))
    for dt, cnt, exe in sorted(pf):
        lap.append(f"{dt.strftime('%Y-%m-%d %H:%M:%S')}  {cnt:>8}  {exe}")
    laptop_txt = "\n".join(lap) + "\n"

    # ── Rakitan bukti ──────────────────────────────────────────────────────
    t_collect = t_arrive + timedelta(minutes=8)
    ev_list = [
        Evidence("tasklist", "EV-001", f"EV-001_{server}_tasklist.csv", "Daftar proses aktif", server, True,
                 "tasklist /v /fo csv (EDR live response)", tasklist, acquired_at=t_collect),
        Evidence("netstat", "EV-002", f"EV-002_{server}_netstat.txt", "Koneksi jaringan aktif", server, True,
                 "netstat -anob (EDR live response)", netstat, acquired_at=t_collect + timedelta(minutes=1)),
        Evidence("memory", "EV-003", f"EV-003_{server}_memdump.strings.txt", "Strings dari image RAM (32 GB)", server,
                 True, "WinPmem → strings -a -n 8", memory, acquired_at=t_collect + timedelta(minutes=4)),
        Evidence("eventlog", "EV-004", f"EV-004_{server}_EventLogs.csv", "Log peristiwa Security/System/Application",
                 server, False, "KAPE + EvtxECmd", eventlog, acquired_at=t_collect + timedelta(minutes=48)),
        Evidence("fslist", "EV-005", f"EV-005_{server}_Finance_listing.csv", "Listing file share D:\\Finance", server,
                 False, "KAPE (MFT) + MFTECmd", fslist, acquired_at=t_collect + timedelta(minutes=52)),
        Evidence("laptop", "EV-006", f"EV-006_{laptop}_triage.txt", f"Triage laptop {laptop}", laptop, False,
                 "KAPE !SANS_Triage (di lab)", laptop_txt, acquired_at=t_arrive + timedelta(hours=2)),
    ]
    for e in ev_list:
        if e.key in ("tasklist", "netstat") and "live_lost" in fx:
            e.available, e.reason = False, "Sistem sudah mati sebelum live response — data proses & koneksi hilang."
        if e.key == "memory" and ("memory_lost" in fx or "live_lost" in fx):
            e.available, e.reason = False, "RAM tidak sempat diakuisisi — isi memori hilang saat sistem padam/restart."
        if e.key == "laptop" and "laptop_lost" in fx:
            e.available, e.reason = False, "Laptop terkunci BitLocker / terhapus — triage tidak dapat dilakukan."
        if e.key == "fslist" and "fs_contaminated" in fx:
            e.note = "Timestamp Accessed terkontaminasi aktivitas di TKP; Thumbs.db baru tercipta."
        if e.key in ("tasklist", "netstat", "memory") and "av_tampered" in fx and e.available:
            e.note = "Diambil setelah pemindaian antivirus — sebagian artefak sudah dikarantina."

    scene = _scene_log(ctx, r, t_alert, t_arrive, server, values)

    truth = {
        "F1": lt_ip, "F2": f"{dom}\\{admin}", "F3": hms(t_logon), "F4": f"{malproc} {malpid}",
        "F5": f"{c2_ip}:{c2_port}", "F6": svc, "F7": str(enc_count), "F8": attachment, "F9": campaign,
    }
    timeline = [
        (t_phish, f"{laptop_user} membuka lampiran `{attachment}` di {laptop}"),
        (tries[0], f"Brute-force SMB/NTLM dari {laptop} ({lt_ip}) terhadap akun {dom}\\{admin} — {attempts} percobaan"),
        (t_logon, f"Logon sukses {dom}\\{admin} dari {lt_ip} (LogonType 3)"),
        (t_svc, f"Service `{svc}` dipasang → `{drop}\\{malproc}`"),
        (t_task, f"Scheduled task `{task}` dibuat untuk persistence"),
        (t_proc, f"`{malproc}` (PID {malpid}) berjalan; shadow copy dihapus"),
        (t_clear, "Log Application dibersihkan (System 104)"),
        (t_enc, f"Enkripsi `D:\\Finance` dimulai — ekstensi `{ext}`"),
        (t_alert, "Alert EDR mass file rename diterima SOC"),
        (t_arrive, "First responder tiba di ruang server"),
    ]
    iocs = [("IP C2", f"{c2_ip}:{c2_port}"), ("Proses", f"{drop}\\{malproc}"), ("Service", svc),
            ("Scheduled task", task), ("Ekstensi", ext), ("Ransom note", note), ("Campaign ID", campaign),
            ("Lampiran phishing", attachment), ("Host awal", f"{laptop} ({lt_ip})")]
    return Build(host=server, evidence=ev_list, truth=truth, scene_log=scene, timeline=timeline,
                 facts=values, iocs=iocs, clock_recorded="drift_unknown" not in fx)


def _scene_log(ctx: Context, r, t_alert, t_arrive, server, values):
    o = ctx.outcomes
    at = lambda m: t_arrive + timedelta(minutes=m, seconds=r.randint(0, 50))  # noqa: E731
    t_clock = at(4)
    log = [
        (t_alert, f"SOC menerima alert EDR 'mass file rename' pada {server}. CSIRT diaktifkan."),
        (t_arrive, f"Tim first responder tiba di ruang server. {server} menyala, layar terkunci."),
        (at(2), o["D1"]),
        (t_clock, o["D4"]),
        (at(7), o["D2"]),
        (at(15), o["D5"]),
        (at(24), o["D3"]),
        (at(58), "Triage disk (KAPE) selesai; seluruh bukti di-hash dan disegel."),
    ]
    return [(t, fill(msg, clock_values(ctx, values, t_clock))) for t, msg in log]

