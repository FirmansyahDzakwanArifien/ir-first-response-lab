# Panduan Dosen & Asisten

## Arsitektur singkat

- Mahasiswa bekerja di **issue** pada repositori ini (tidak perlu fork). Setiap issue dan komentar
  berawalan `/` memicu workflow [`case-desk.yml`](../.github/workflows/case-desk.yml) di
  GitHub-hosted runner.
- Isi skenario (narasi, opsi, kunci jawaban, pembahasan, pool nilai) disimpan terenkripsi di
  `bank.sealed`. Runner membukanya dengan secret `IRSIM_KEY`. Kode generator bersifat publik, tetapi
  tanpa kunci tidak ada yang bisa mereproduksi kasus atau kuncinya.
- Seluruh kasus **deterministik**: NIM + kunci + keputusan → bukti dan kunci jawaban yang sama
  persis. Tidak ada basis data; status kasus tersimpan sebagai penanda tersembunyi di komentar bot.
- Paket bukti disimpan sebagai artifact 30 hari (bisa diterbitkan ulang dengan `/paket`), debrief
  90 hari. Nilai juga tersimpan di komentar bot, sehingga rekap tidak bergantung pada masa simpan
  artifact.

Kapasitas: setiap perintah memakai ±30–60 detik runner. Untuk 60 mahasiswa (±3 run per mahasiswa)
total ±2–3 jam runner — gratis untuk repositori publik.

## Persiapan awal (sekali)

```bash
pip install -r requirements.txt
python -m irsim unseal          # membuka bank.sealed ke folder bank/ (butuh .irsim.key)
python -m irsim setup --repo OWNER/REPO
gh secret set IRSIM_KEY < .irsim.key
```

- `.irsim.key` dan folder `bank/` sudah di-`.gitignore`. **Simpan cadangan `.irsim.key`** di
  tempat aman; tanpa kunci ini `bank.sealed` tidak dapat dibuka.
- Opsional, batasi peserta: simpan daftar NIM (satu per baris, boleh `NIM,Nama`) sebagai secret
  `IRSIM_ROSTER`.

  ```bash
  gh secret set IRSIM_ROSTER < roster.csv
  ```

## Pengaturan kelas — `course.yml`

| Kunci | Fungsi |
|---|---|
| `scenario_assignment` | `auto` (dibagi per NIM) atau id skenario tertentu |
| `incident_window` | Rentang tanggal fiktif insiden |
| `deadline` | Tenggat ISO 8601, mis. `2026-12-01T23:59:00+07:00`; setelahnya kasus baru ditolak dan laporan ditandai terlambat |
| `max_submissions` | Jumlah `/submit` per kasus (bawaan 1) |
| `grading` | Ambang grade, predikat, dan pesan |

## Mengubah atau menambah isi skenario

1. `python -m irsim unseal` → edit `bank/*.yml` (narasi, opsi, pembahasan, bobot, pool nilai).
2. `python -m irsim selftest` → memastikan setiap kasus dapat diselesaikan dengan skor 100,
   deterministik, dan setiap temuan benar-benar ada di buktinya.
3. `python -m irsim seal` → commit `bank.sealed`.

Pratinjau kasus mahasiswa tertentu lengkap dengan kunci jawaban dan debrief:

```bash
python -m irsim preview --nim 0110224001
python -m irsim preview --nim 0110224001 --keputusan salah
python -m irsim preview --nim 0110224001 --keputusan B,A,D,C,A --skenario webshell-compromise
```

Hasilnya di folder `preview/` (tidak ikut di-commit) — berguna untuk menjawab sanggahan nilai.

## Rekap nilai

```bash
python -m irsim rekap --repo OWNER/REPO
```

Menghasilkan `rekap/rekap_nilai.csv` (siap dibuka di Excel/Sheets: NIM, nama, akun GitHub,
skenario, skor per komponen, benar/salah per butir, keterlambatan) dan `rekap/ringkasan.md`
(rata-rata per skenario dan persentase benar per butir — untuk melihat topik yang belum dikuasai
kelas).

## Penanganan kasus khusus

- **Mahasiswa salah mengisi NIM / perlu mengulang:** tutup issue-nya dan beri label `ditolak`;
  mahasiswa dapat membuka issue baru. Kasus dengan NIM yang sama akan menghasilkan bukti yang sama.
- **Run gagal:** bot mengirim komentar kendala beserta tautan log; status kasus tidak berubah dan
  mahasiswa cukup mengirim ulang perintahnya.
- **Mengganti kunci:** `unseal` dengan kunci lama, ganti `.irsim.key`, `seal`, perbarui secret.
  Semua kasus yang sedang berjalan akan berubah, jadi lakukan hanya di antara semester.

## Privasi

Issue bersifat publik: NIM, nama, dan skor terlihat oleh peserta lain. Bila tidak dikehendaki,
gunakan repositori di dalam GitHub Organization kampus dengan visibilitas *internal*, atau minta
mahasiswa mengisi nama panggilan dan cocokkan dengan roster.
