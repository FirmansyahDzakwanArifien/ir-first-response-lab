# IR First Response Lab

Simulasi penanganan insiden untuk mata kuliah **Incident Response — First Response**.
Mahasiswa berperan sebagai *first responder*: mengambil keputusan di TKP, menerima paket bukti
forensik yang terbentuk dari keputusan tersebut, menganalisisnya dengan alat sungguhan, lalu
menyerahkan laporan. Seluruh proses berjalan di GitHub Issues dan GitHub Actions — tanpa server,
tanpa instalasi.

```
 Issue dibuka ──▶ Briefing + 5 keputusan TKP ──▶ /respond ──▶ Paket bukti (unik per NIM)
                                                                 │
          Debrief: Laporan Insiden · Chain of Custody ◀── /submit ◀┘  analisis di laptop
                   Lesson Learned · Skor                               (sha256sum, grep, awk…)
```

## Mengapa simulasi ini terasa nyata

- **Keputusan punya konsekuensi pada bukti.** Mematikan server berarti `tasklist`, `netstat`,
  dan image RAM tidak pernah ada di paket Anda. Menjalankan antivirus mengkarantina malware sebelum
  dicatat. Tidak mencatat selisih jam berarti timestamp tidak bisa dikoreksi.
- **Bukti forensik realistis.** Ekspor EvtxECmd, `netstat -anob`, listing MFT, `ps auxf`,
  `ss -tunap`, log nginx, mactime, Suricata `fast.log`, log proxy W3C, `setupapi.dev.log`,
  strings memori — ribuan baris dengan noise yang wajar.
- **Unik per mahasiswa.** IP, akun, PID, nama malware, waktu, selisih jam, jumlah file, hingga
  urutan opsi jawaban diturunkan dari NIM dan kunci rahasia. Menyalin jawaban teman tidak berguna.
- **Integritas bukti diuji sungguhan.** Satu file bukti berubah setelah akuisisi; mahasiswa harus
  menemukannya dengan membandingkan SHA-256 terhadap manifest akuisisi.
- **Kunci jawaban tidak ada di repositori.** Isi skenario disegel (`bank.sealed`, Fernet/AES)
  dan hanya dibuka oleh runner yang memegang secret.

## Skenario

| Kode | Skenario | Fokus |
|---|---|---|
| **LEDGERLOCK** | Ransomware pada file server keuangan (Windows Server) | Containment EDR, order of volatility, preservasi laptop, clock drift, MAC times |
| **GLASSDOOR** | Webshell pada web server publik (Ubuntu · nginx · PHP-FPM) | Egress block, akuisisi RAM Linux, alat tepercaya vs rootkit userland, intervensi developer |
| **QUIET HARBOR** | Eksfiltrasi data oleh orang dalam (Windows · proxy · file server) | Investigasi tertutup, kewenangan & UU ITE/PDP, media USB, analisis log proxy |

Skenario dibagi otomatis dan merata berdasarkan NIM (dapat dikunci ke satu skenario lewat `course.yml`).

## Penilaian

| Komponen | Bobot |
|---|:-:|
| Lima keputusan di TKP | 40 |
| Analisis bukti (8–9 temuan) | 45 |
| Integritas bukti (ID bukti bermasalah + SHA-256 aktual) | 15 |

Grade dan predikat diatur di [`course.yml`](course.yml).

## Mulai

- **Mahasiswa** → [Panduan mahasiswa](docs/panduan-mahasiswa.md), lalu buka
  [issue baru](../../issues/new/choose) dengan template **Penugasan Kasus IR**.
- **Dosen / asisten** → [Panduan dosen](docs/panduan-dosen.md).

## Struktur

```
.github/
  ISSUE_TEMPLATE/penugasan-kasus.yml   formulir pembukaan kasus
  workflows/case-desk.yml              memproses issue & perintah /respond, /paket, /submit
  workflows/selftest.yml               uji otomatis seluruh skenario
irsim/
  scenarios/                           generator bukti per skenario
  grading.py                           penilaian
  render.py · report.py                briefing, paket bukti, debrief (Markdown + HTML)
  desk.py                              integrasi GitHub
  __main__.py                          perkakas dosen (seal, preview, selftest, rekap)
bank.sealed                            isi skenario terenkripsi
course.yml                             pengaturan mata kuliah
```

---

<sub>Dibuat untuk keperluan pendidikan. Seluruh organisasi, orang, alamat IP, dan domain dalam
skenario adalah fiktif; IP penyerang memakai rentang dokumentasi RFC 5737.</sub>
