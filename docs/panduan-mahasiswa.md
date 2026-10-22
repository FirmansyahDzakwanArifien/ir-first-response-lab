# Panduan Mahasiswa

> **Tonton dulu video panduannya (±4,5 menit, tanpa suara):** [Panduan_Praktikum_IR_First_Response.mp4](https://github.com/FirmansyahDzakwanArifien/ir-first-response-lab/releases/download/panduan-v1/Panduan_Praktikum_IR_First_Response.mp4)
> Seluruh langkah di bawah diperagakan di video, mulai dari membuka kasus sampai membaca debrief.
>
> **Tenggat: Sabtu, 24 Oktober 2026 · 23.59 WIB.** Setelah tenggat, kasus baru ditolak dan laporan ditandai terlambat.

Simulasi ini berlangsung di **satu issue** milik Anda. Tidak perlu fork, tidak perlu menginstal apa
pun selain alat analisis yang biasa Anda pakai.

## 1. Buka kasus

1. Masuk ke tab **Issues** → **New issue** → pilih **Penugasan Kasus IR**.
2. Isi NIM dan nama lengkap, centang pernyataan, lalu **Create**.
3. Dalam ±1 menit sistem membalas dengan **briefing insiden** dan judul issue berubah menjadi
   `[IR-26-XXXXX] NIM · Nama`.

Satu NIM hanya boleh memiliki satu kasus.

## 2. Fase 1 — Keputusan di TKP

Baca briefing dengan saksama. Anda harus mengambil lima keputusan (D1–D5). Balas issue dengan
**satu komentar**:

```text
/respond
D1: B
D2: A
D3: D
D4: C
D5: A
```

- Keputusan **dikunci** dan tidak dapat diubah.
- Urutan opsi A–D diacak untuk setiap mahasiswa.
- Konsekuensi keputusan langsung terlihat pada log TKP dan **menentukan bukti apa saja yang Anda
  terima**. Bukti yang hilang karena keputusan keliru tidak akan pernah kembali — sama seperti di
  dunia nyata.

## 3. Fase 2 — Analisis paket bukti

Sistem membalas dengan log tindakan di TKP dan tautan **paket bukti** (artifact `.zip`, perlu
login GitHub). Isi paket:

| File | Isi |
|---|---|
| `BRIEFING.md` | Situasi, log TKP, daftar bukti, pertanyaan, format laporan |
| `CATATAN_RESPONDER.txt` | Log aktivitas responder (termasuk selisih jam bila tercatat) |
| `MANIFEST_AKUISISI.json` | Hash SHA-256 setiap bukti **saat diakuisisi** |
| `bukti/` | File bukti forensik |

### Langkah analisis yang disarankan

1. **Verifikasi integritas lebih dulu.** Satu file tidak lagi cocok dengan manifest.

   ```bash
   sha256sum bukti/*
   ```
   ```powershell
   Get-FileHash .\bukti\* -Algorithm SHA256 | Format-Table Hash, Path
   ```

2. **Koreksi waktu.** Log dari host memakai jam host. Bila `CATATAN_RESPONDER.txt` mencatat
   `Selisih +00:03:36 (jam sistem − referensi)`, maka **waktu sebenarnya = waktu di log − selisih**.
   Contoh: log `02:21:05`, selisih `+00:03:36` → `02:17:29` WIB.
3. **Filter, hitung, korelasikan.** Beberapa contoh:

   ```bash
   grep ',4625,' bukti/EV-004_*.csv | cut -d, -f7 | sort | uniq -c | sort -rn
   awk -F, 'NR>1 {print $1}' bukti/EV-005_*.csv | grep -c '\.ekstensi$'
   awk '$4=="10.0.0.5" && $7=="host.tujuan" {s+=$10} END {print s}' bukti/EV-001_*.log
   ```
   ```powershell
   Import-Csv .\bukti\EV-004_*.csv | Where-Object EventId -eq 4625 | Group-Object RemoteHost
   ```

   Alat lain yang berguna: Timeline Explorer, CyberChef (URL decode), VS Code, LibreOffice Calc.

## 4. Kirim laporan

Balas issue dengan satu komentar berformat YAML (templatnya ada di balasan fase 2 dan di
`BRIEFING.md`):

```yaml
/submit
temuan:
  F1: 10.20.30.40
  F2: CORP\adm.contoh
  F3: "02:17:29"
  ...
integritas:
  bukti_bermasalah: EV-004
  sha256_aktual: 3f9a...e1
catatan: |
  Ringkasan analisis Anda.
```

- Laporan hanya dapat dikirim **sekali**. Periksa kembali sebelum mengirim.
- Waktu ditulis `HH:MM:SS` dalam WIB yang sudah dikoreksi. Beri tanda kutip bila perlu.
- Temuan yang buktinya hilang boleh dikosongkan atau dijawab dari sumber lain.

## 5. Debrief

Setelah dinilai, sistem membalas dengan skor, grade, dan tautan **debrief**:

- `DEBRIEF.html` — siap dibuka di browser dan dicetak ke PDF
- `01_Laporan_Insiden.md` — laporan insiden berbasis temuan Anda
- `02_Chain_of_Custody.md` — formulir CoC dengan hash akuisisi vs hash diterima
- `03_Lesson_Learned.md` — pembahasan setiap keputusan & temuan, kunci, dan rujukan materi
- `skor.json`

Issue kemudian ditutup.

## Perintah

| Perintah | Fungsi |
|---|---|
| `/respond` | Mengirim keputusan D1–D5 |
| `/paket` | Menerbitkan ulang tautan paket bukti |
| `/submit` | Mengirim laporan analisis |
| `/bantuan` | Menampilkan daftar perintah dan status kasus |

Perintah hanya diproses bila ditulis oleh pembuka issue.
