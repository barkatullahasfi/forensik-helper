# Network Forensics Helper

Alat bantu analisis forensik digital untuk **latihan dan pembelajaran**: pcap,
berkas (gambar/dokumen/executable), log server, disk image, dan RAM dump — dengan setiap
temuan disertai **filter Wireshark persis** yang menghasilkannya, supaya laporan
bisa diverifikasi ulang dan tidak perlu mencari-cari lagi secara manual.

> **English TL;DR** — A digital forensics assistant for practice and learning.
> Analyses pcap files, server logs, disk images, memory dumps, and arbitrary
> files. Every
> finding carries the exact Wireshark/tshark filter that produced it, so results
> are reproducible. Deterministic rules and statistics only — **no AI/ML**.
> Runs natively on Windows and Linux/WSL.

**Semua deteksi bersifat deterministik** — aturan, regex, dan statistik. Tidak ada
AI, tidak ada machine learning, tidak ada panggilan API ke layanan luar saat
analisis. Ini disengaja: hasilnya harus bisa dijelaskan dan dipertanggungjawabkan
baris per baris.

---

## Daftar isi

- [Untuk siapa](#untuk-siapa)
- [Apa yang dihasilkan](#apa-yang-dihasilkan)
- [Instalasi](#instalasi)
- [Cara pakai](#cara-pakai)
- [Daftar modul](#daftar-modul)
- [Berapa lama](#berapa-lama)
- [Batasan yang wajib dibaca](#batasan-yang-wajib-dibaca)
- [Tervalidasi terhadap](#tervalidasi-terhadap)
- [Berkontribusi](#berkontribusi)
- [Etika & lingkup penggunaan](#etika--lingkup-penggunaan)
- [Lisensi](#lisensi)

---

## Untuk siapa

Dibuat untuk latihan pribadi mempertajam kemampuan analisis manual — bukan untuk
menggantikannya. Cocok untuk:

- Latihan kompetisi forensik digital dan CTF
- Belajar membaca pcap, RAM dump, dan disk image
- Menyusun laporan insiden yang bisa diverifikasi ulang

Yang membedakan dari sekadar menjalankan tshark manual: setiap temuan membawa
**filternya sendiri**, jumlah sesi yang tidak berisi apa-apa **tetap dilaporkan**
(supaya bisa di-cross-check), dan setiap false positive yang sudah dikenal
**ditandai beserta alasannya** alih-alih disembunyikan.

## Apa yang dihasilkan

Analisis satu pcap menghasilkan, antara lain:

**Ringkasan investigasi** — pertanyaan baku, dijawab langsung:

```
[HIGH] Siapa korban dan siapa penyerangnya?
   -> 10.0.2.15 korban, 10.0.2.4 sumber serangan
[HIGH] Mesin fisik atau virtual?
   -> Virtual, 3 dari 3 host Oracle VirtualBox
[HIGH] Apakah ada aktivitas pemindaian?
   -> 10.0.2.4 memindai 1002 port dalam 59,8 detik
[HIGH] Apa yang TIDAK bisa dijawab dari evidence ini?
   -> 5 keterbatasan tercatat
```

**Kronologi serangan** berfase, menyebut pelaku tiap langkah:

```
--- Reconnaissance ---
05:44:28  10.0.2.4: Kontak pertama dengan 10.0.2.15
05:44:28  10.0.2.4: Memindai 1002 port dalam 59,8 detik

--- Initial Access ---
05:44:44  10.0.2.4: GET /nmaplowercheck1725947084
05:44:44  10.0.2.4: PROPFIND /

--- Aliran data ---
Korban MENERIMA 3.468.300 byte dan hanya MENGIRIM 184.398 byte.
Arah dominan masuk — pola pemasangan berkas, bukan pengambilan data.
```

**Lampiran reproduksibilitas** — filter persis per temuan:

```
mac_address: 00:21:5d:c8:0e:f2
  filter : ip.src==10.1.21.58 && eth.src
  catatan: 24117/24118 frame. Ada 2 MAC berbeda untuk IP ini,
           dipilih yang mayoritas
```

Plus: narasi bahasa Indonesia siap tempel, mapping MITRE ATT&CK, log seluruh sesi
koneksi (termasuk yang idle), dan hasil disimpan sebagai JSON.

---

## Instalasi

### Prasyarat

Python 3.11+ dan `tshark`. Sisanya opsional dan bisa ditambahkan belakangan.

### Windows

```bash
git clone https://github.com/barkatullahasfi/forensik-helper.git
```

```bash
cd forensik-helper && python -m venv venv && .\venv\Scripts\Activate.ps1
```

```bash
pip install -r backend/requirements.txt
```

```bash
python -m backend.setup
```

`backend.setup` mengecek tool eksternal dan **menginstall yang wajib** lewat
winget bila belum ada. Kalau `Activate.ps1` ditolak:

```bash
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Linux / WSL

```bash
sudo apt install -y tshark python3-venv
```

```bash
git clone https://github.com/barkatullahasfi/forensik-helper.git
```

```bash
cd forensik-helper && python3 -m venv venv && source venv/bin/activate
```

```bash
pip install -r backend/requirements.txt && python -m backend.setup
```

Tool opsional (di Linux justru lebih lengkap — `steghide` dan `zsteg` tidak punya
build Windows resmi):

```bash
sudo apt install -y libimage-exiftool-perl sleuthkit steghide ruby && sudo gem install zsteg
```

> **Hindari path berisi spasi.** Console script pip di Linux memakai shebang, dan
> kernel membaca shebang hanya sampai spasi pertama. venv di direktori seperti
> `my project/venv` membuat `vol` dan `binwalk` gagal dengan pesan menyesatkan
> "No such file or directory". Tools ini menanganinya sendiri, tapi perintah yang
> kamu ketik manual di terminal tetap akan gagal.

### Feed threat intel

Sekali di awal, lalu ulangi berkala:

```bash
python -c "from backend.services.threat_feed import download_feeds; print(download_feeds())"
```

Mengunduh URLhaus, ThreatFox, dan SSLBL dari abuse.ch ke `storage/feeds/`.
Gratis, tanpa API key. Lookup dilakukan dari berkas lokal, jadi analisis tetap
berjalan tanpa koneksi.

### Sleuth Kit di Windows

Tidak ada paket winget mandiri. Unduh ZIP rilis resmi dari
[github.com/sleuthkit/sleuthkit/releases](https://github.com/sleuthkit/sleuthkit/releases)
(~17 MB), ekstrak ke `%LOCALAPPDATA%\Programs\sleuthkit\`. Nomor versi boleh ikut
di nama direktori — resolusi path sudah menanganinya.

---

## Cara pakai

### GUI

```bash
uvicorn backend.main:app --reload --port 8000
```

Buka `http://127.0.0.1:8000`. Drag-drop berkas apa pun, progress bar mengikuti
tahap pipeline yang sebenarnya, hasil tampil sebagai dashboard.

**Tiap filter Wireshark bisa diklik untuk disalin** — itu alasan utama antarmuka
ini ada. Ctrl+klik dua entri riwayat lalu "Korelasikan" untuk skenario evidence
pack. Tombol ✕ menghapus satu analisis beserta berkas unggahan dan hasil
carving-nya.

> **Jangan pakai `--host 0.0.0.0`.** Tools ini menerima upload berkas arbitrer,
> menjalankan tshark/binwalk di atasnya, dan tidak punya autentikasi sama sekali.

### CLI — pcap

```bash
python -m backend.analyze capture.pcap
```

Target IP ditebak otomatis. Tentukan manual sebagai argumen kedua bila perlu:

```bash
python -m backend.analyze capture.pcap 10.1.21.58
```

### CLI — berkas apa pun

Gambar, dokumen, audio, `.exe`, log server, disk image, RAM dump:

```bash
python -m backend.analyze_file bukti.jpg
```

Log dikenali dari nama BERKAS maupun dari ISINYA, jadi `/var/log/secure` yang
tanpa ekstensi dan `access.log.3.gz` yang ter-rotasi sama-sama terbaca:

```bash
python -m backend.analyze_file /var/log/auth.log
```

Beberapa berkas sekaligus otomatis dibandingkan lewat fuzzy hash — mendeteksi
varian yang berbeda SHA256 tapi struktur mirip:

```bash
python -m backend.analyze_file sample1.exe sample2.exe
```

### Evidence pack (korelasi multi-sumber)

Analisis tiap berkas dulu, lalu di GUI Ctrl+klik entri yang ingin dikorelasikan
dan tekan "Korelasikan". Lewat API:

```bash
curl -X POST http://127.0.0.1:8000/api/evidence-pack -H "Content-Type: application/json" -d "[\"id_pcap\",\"id_memdump\"]"
```

Ini yang menghubungkan lalu lintas jaringan ke proses yang menghasilkannya —
sesuatu yang tidak bisa dilakukan pcap sendirian.

### Utilitas

```bash
python tests/test_mvp.py && python tests/test_modules.py
```

```bash
python tests/clean_storage.py
```

```bash
python tests/profile_pipeline.py capture.pcap
```

```bash
python tests/make_disk_fixture.py
```

Berturut-turut: jalankan test, bersihkan hasil analisis (feed dipertahankan; pakai
`--feeds` bila ingin ikut dihapus), ukur waktu tiap tahap pipeline, dan buat disk
image FAT16 untuk menguji modul disk tanpa perlu unduhan atau hak admin.

### API

Dokumentasi otomatis di `/docs`. Endpoint utama:

| Method | Endpoint | Keterangan |
|---|---|---|
| POST | `/api/upload` | Unggah berkas, mulai analisis di latar |
| GET | `/api/analysis/{id}/status` | Status + tahap berjalan (ringan, untuk polling) |
| GET | `/api/analysis/{id}` | Hasil lengkap |
| GET | `/api/analysis` | Riwayat |
| DELETE | `/api/analysis/{id}` | Hapus satu, beserta unggahan & carving |
| DELETE | `/api/analysis` | Hapus semua |
| POST | `/api/evidence-pack` | Korelasi lintas evidence |
| POST | `/api/feeds/refresh` | Tarik ulang feed abuse.ch |
| GET | `/api/system/tools` | Tool mana yang tersedia |

---

## Daftar modul

| Modul | Isi |
|---|---|
| `tools` | Resolusi binary lintas platform, auto-install, wrapper subprocess |
| `pcap_parser` | Wrapper tshark/capinfos, peta DNS, percakapan, probe protokol |
| `host_inventory` | Inventaris layer 2, lookup OUI, deteksi mesin virtual |
| `identity_extractor` | IP, MAC, hostname, username AD, Full Name (SAMR) |
| `beacon_detector` | Sesi lengkap dua arah, coefficient of variation, rotasi domain |
| `timeline_builder` | Timeline, log sesi, evidence index, normalisasi waktu |
| `attack_timeline` | Kronologi berfase + pelaku + aliran data |
| `investigation_summary` | Pertanyaan investigasi baku, dijawab langsung |
| `dns_chain_analyzer` | Delivery chain + analisis celah waktu |
| `dga_detector` | Entropy ternormalisasi, deret konsonan, TLD tidak umum |
| `threat_feed` | URLhaus / ThreatFox / SSLBL offline (abuse.ch) |
| `file_carver` | Ekstraksi berkas dari HTTP/SMB/FTP + hash + cross-check |
| `ja3_fingerprint` | JA3/JA3S + lookup SSLBL |
| `protocol_anomaly` | Port C2 non-standar, layanan terekspos, deteksi port scan |
| `kerberos_analyzer` | Downgrade RC4, pola Kerberoasting |
| `volume_analyzer` | Spike volume relatif baseline capture sendiri |
| `owasp_detector` | SQLi/XSS/command injection/traversal/SSRF + outcome |
| `hash_analyzer` | MD5/SHA1/SHA256 + fuzzy hash + perbandingan berkas |
| `metadata_extractor` | EXIF, GPS, authorship, anomali timestamp |
| `steganography_detector` | Signature tersisip (tervalidasi), trailing data, penanda akhir hilang, teks terbaca di dalam data terkompresi, LSB, steghide |
| `binary_analyzer` | Strings ASCII+UTF-16, IOC, header PE, packer, runtime, kapabilitas |
| `reverse_engineer` | Overlay PE, resource tersembunyi, string base64/XOR, disassembly entry point, imphash |
| `unpacker` | Bongkar UPX dan arsip/APK, lalu analisis ulang isinya |
| `smb_analyzer` | Tree connect, berkas di share, penandaan executable web |
| `tool_fingerprint` | Identifikasi perkakas penyerang dari User-Agent |
| `http_analyzer` | Transaksi HTTP lengkap: header, body, response |
| `log_analyzer` | Apache/Nginx, IIS W3C, syslog/auth.log, JSON lines: serangan web, brute force + login berhasil sesudahnya, webshell, sudo pasca-kompromi, enumerasi |
| `disk_image_analyzer` | Sleuth Kit: partisi, berkas terhapus, timeline MAC |
| `memory_analyzer` | Volatility 3: proses, koneksi, cmdline, malfind, persistence |
| `geoip_enrichment` | GeoLite2 lokal (opsional, butuh akun MaxMind gratis) |
| `location_analyzer` | Gabungan GPS + GeoIP, label sumber dipertahankan |
| `cross_evidence_correlator` | pcap ↔ RAM ↔ disk, master timeline |
| `mitre_mapper` | Mapping rule-based ke ATT&CK |
| `confidence_scorer` | HIGH/MEDIUM/LOW, gabungan ambil mata rantai terlemah |
| `narrative_generator` | Paragraf laporan bahasa Indonesia (template, bukan LLM) |
| `osint_helper` | Menyusun query untuk dicek manual — tidak scraping |

---

## Berapa lama

Pipeline melakukan banyak pass tshark terpisah, jadi waktunya sebanding dengan
ukuran capture — **bukan macet** kalau terasa lama. Terukur pada pcap web 28 MB /
88.862 paket: **±51 detik**.

Satu pass `tshark -z io,phs` di awal mendeteksi protokol yang benar-benar ada,
lalu modul yang tidak mungkin berhasil dilewati (Kerberos/TLS/SMB/DNS pada capture
yang tidak memuatnya). Itu menghemat belasan pembacaan penuh; yang dilewati
tercatat di `skipped_modules`.

Yang paling mahal biasanya file carving: `tshark --export-objects` menulis satu
berkas per body HTTP, jadi capture web bisa menghasilkan puluhan ribu objek untuk
beberapa berkas nyata. Artefak dan duplikatnya dihapus otomatis setelah diperiksa.

---

## Batasan yang wajib dibaca

Bagian ini bukan basa-basi. Menulis laporan forensik dari hasil tools tanpa
memahami batasannya adalah cara tercepat menghasilkan kesimpulan yang salah.

- **Bukan pengganti analisis manual.** Tools ini mempercepat langkah repetitif;
  interpretasi akhir tetap butuh judgment manusia.
- **Beaconing hanya menangkap C2 berinterval teratur.** C2 yang burst punya
  coefficient of variation tinggi dan lolos — itu sebabnya destinasi dengan
  payload HTTP dilaporkan terpisah sebagai `http_candidate_c2`.
- **Traffic TLS tidak terbaca isinya** tanpa key log; hanya metadata (SNI, timing,
  volume, JA3).
- **Whitelist menandai, tidak membuang.** Destinasi umum tetap muncul dengan
  `is_known_noise` dan confidence LOW. Whitelist yang menyembunyikan temuan adalah
  cara termudah melewatkan C2 yang menumpang domain terpercaya.
- **Hit threat feed di layanan hosting publik bukan IOC.** URLhaus mendaftar URL
  spesifik di `drive.google.com`, bukan domainnya. Ditandai `shared_hosting` dan
  tidak dimasukkan ke narasi.
- **Deteksi OWASP signature-based** — rawan false positive; verifikasi isi request
  lengkapnya sebelum menyimpulkan.
- **Teks terbaca di dalam berkas media dilaporkan tanpa perlu kata kunci.** Data
  gambar/audio yang sudah dikompresi tidak menghasilkan kalimat, jadi kalimat
  utuh di dalamnya berarti seseorang menaruhnya di sana. Daftar kata kunci saja
  tidak akan pernah cukup — pesan yang tidak memuat 'flag' atau 'secret' lolos
  sepenuhnya dari penyaring berbasis kata.
- **Log akses hanya memuat baris request, bukan isi response.** Apakah payload
  benar-benar dieksekusi tidak bisa dipastikan dari log web — status 200 berarti
  server menjawab, bukan berarti serangannya berhasil. Pastikan dari log
  aplikasi, log basis data, atau berkas di server.
- **Log web tidak mencatat username yang dicoba** (ia ada di body POST). Brute
  force lewat form login karena itu dilaporkan tanpa nama akun; brute force SSH
  di `auth.log` mencatatnya.
- **Format syslog tidak memuat tahun.** Tahun diambil dari waktu modifikasi
  berkas dan asumsinya dicetak di laporan. Kalau berkasnya pernah disalin ulang,
  cocokkan dulu dengan sumber lain sebelum dipakai di timeline gabungan.
- **Keterbacaan log dilaporkan sebagai angka.** Parser yang gagal atas mayoritas
  baris menghasilkan "0 temuan" yang terlihat persis sama dengan log bersih —
  karena itu persentase baris terbaca selalu muncul di atas temuan.
- **IP sumber di log adalah apa yang dicatat server.** Kalau ada proxy atau CDN
  di depannya, yang tercatat bisa IP proxy, bukan klien sebenarnya.
- **Strings dari berkas ter-pack tidak mencerminkan isinya.** "Tidak ditemukan
  domain apa pun" pada berkas ter-UPX adalah kesimpulan yang salah, bukan temuan
  negatif — bongkar dulu. Alat ini membongkar UPX otomatis; packer lain
  dilaporkan namanya beserta cara membongkarnya.
- **Domain hasil ekstraksi strings perlu dicocokkan ke lalu lintas DNS.** Domain
  yang tertanam di kode belum tentu pernah dihubungi, dan filter TLD tidak
  sempurna — sisa false positive masih mungkin lolos.
- **`System` PID 4 bukan nama layanan.** Di Windows, port 80 dan 445 dipegang
  HTTP.sys/SMB di kernel. Cari proses pekerjanya (mis. `w3wp.exe` untuk IIS).
- **malfind punya false positive tetap.** Windows Defender, csrss, svchost, dan
  explorer memang memakai memori RWX. Ditandai sebagai catatan, bukan dibuang.
- **GeoIP ≠ GPS.** GeoIP adalah perkiraan lokasi server (bisa VPN/CDN); GPS adalah
  lokasi fisik kamera. Jangan dicampur sebagai "lokasi pasti".
- **Timestamp compile PE bisa dipalsukan.** Perlakukan sebagai petunjuk.
- **Target IP hasil tebakan bukan fakta.** Dipilih dari total paket dua arah,
  bukan pengirim terbanyak — di capture serangan, pengirim terbanyak justru
  penyerang. Kandidat lain ikut dilaporkan di appendix.
- **Tidak cocok threat feed bukan berarti aman.** Feed publik hanya memuat yang
  sudah pernah dilaporkan.
- **Fuzzy hash dilewati di atas 128 MB** dan pemindaian in-memory di atas 512 MB
  (`MAX_FUZZY_HASH_BYTES`, `MAX_INMEMORY_SCAN_BYTES`).

### Yang sengaja tidak dilakukan

- **Tidak ada database.** Hasil = satu JSON per analisis di `storage/analyses/`.
- **Tidak menjalankan berkas apa pun.** Analisis binary murni statis. Pembongkaran
  UPX dan arsip dilakukan tanpa mengeksekusi isinya, dan selalu pada **salinan** —
  berkas bukti tidak pernah diubah. Tidak ada sandbox; itu butuh environment
  terisolasi di luar lingkup alat ini.
- **Tidak scraping OSINT.** `osint_helper` menyusun query untuk dicek manual.
- **Tidak ada CDN.** GUI memakai font sistem, jadi tetap berfungsi penuh saat
  mesin analisis offline.

---

## Tervalidasi terhadap

Ground truth dari analisis manual, direproduksi persis:

| pcap | MAC | Hostname | Username | Full name |
|---|---|---|---|---|
| Lumma Stealer | `00:21:5d:c8:0e:f2` | DESKTOP-ES9F3ML | gwyatt | Gabriel Wyatt |
| 2026-02-28 | `00:19:d1:b2:4d:ad` | DESKTOP-TEYQ2NR | brolf | Becka Rolf |

Kasus lain yang dipakai menguji:

- **Delivery chain Lumma** (`megafilehub4.lat` → `filemegahab4.sbs`) dan C2
  `whitepepper.su` terdeteksi.
- **Serangan web**: 76 temuan SQLi/XSS/traversal dari satu attacker, 31 di
  antaranya memicu HTTP 500.
- **Evidence pack** (pcap + RAM dump 4,6 GB + executable): process hollowing
  `RegSvcs.exe` → `update.exe`, dikonfirmasi malfind; korelasi memastikan RAM dump
  dan pcap berasal dari mesin yang sama.
- **Disk image**: fixture FAT16 dari `make_disk_fixture.py` — berkas terhapus
  terdeteksi dan berhasil di-recover utuh lewat `icat`.

Suite test: **61 test**, tanpa framework eksternal.

---

## Berkontribusi

Kontribusi sangat diterima — terutama **pcap atau evidence baru yang membuat tools
ini salah**. Itu jenis kontribusi paling berharga di sini.

### Tempat paling rawan

Pengalaman membangun ini menunjukkan bug hampir selalu muncul di tempat yang sama:

1. **Parser output tool eksternal.** Format bodyfile Sleuth Kit punya 11 field,
   bukan 12. `capinfos` mengikuti locale sistem, jadi di mesin Indonesia angkanya
   `623,925423`. Tabel `-z conv,ip` memakai satuan berubah-ubah. **Selalu uji
   parser terhadap output sungguhan, jangan terhadap dugaan formatnya.**
2. **Signature pendek.** `MZ` hanya 2 byte dan muncul acak sekali per ~65 KB. Satu
   JPEG 3,5 MB menghasilkan puluhan "PE executable tersisip" yang seluruhnya palsu.
   Signature < 4 byte wajib punya validator struktur.
3. **Asumsi tentang peran host.** "Pengirim terbanyak" adalah penyerang, bukan
   korban. Capture sisi server tidak punya alamat privat sama sekali. Server
   menerima koneksi, tidak memulainya.
4. **False positive yang memalukan di laporan.** `drive.google.com` di URLhaus
   bukan berarti domainnya jahat. Windows Defender di malfind itu normal.
   `c.pki.goog` lewat HTTP polos itu memang desainnya.

### Menambah modul

1. Buat `backend/services/<nama>.py`
2. Panggil tool eksternal **hanya** lewat `tools.resolve()` + `tools.run()` —
   jangan `subprocess` langsung
3. Terima parameter `evidence: EvidenceLog` dan catat tiap temuan dengan filter
   yang menghasilkannya. Gunakan `if evidence is None:` — **jangan**
   `evidence or EvidenceLog()`, karena `EvidenceLog` kosong bernilai falsy
4. Sambungkan di `backend/analyze.py`
5. Tambahkan test di `tests/test_modules.py`

### Menulis test

Tanpa framework — `assert` biasa, dijalankan lewat `python tests/test_modules.py`
(tetap kompatibel dengan pytest). Fokuskan pada **logika yang bisa rusak
diam-diam**: parser, ambang skor, klasifikasi. Setiap perbaikan bug sebaiknya
meninggalkan test yang gagal bila bug itu kembali.

### Sebelum push

```bash
python tests/test_mvp.py && python tests/test_modules.py
```

**Jangan pernah commit berkas evidence.** `.gitignore` sudah menutup ekstensi
umum (`.pcap`, `.mem`, `.dd`, `.E01`, dst), tapi periksa `git status` sebelum
commit. Berkas yang sudah masuk riwayat git tetap ada meski dihapus belakangan.

---

## Etika & lingkup penggunaan

Alat ini untuk **analisis defensif dan pembelajaran**: bukti yang kamu miliki
haknya, evidence latihan, soal kompetisi, atau insiden di lingkungan yang kamu
punya wewenang atasnya.

Menganalisis lalu lintas jaringan atau berkas milik orang lain tanpa izin
melanggar hukum di banyak yurisdiksi. Data forensik hampir selalu memuat informasi
pribadi — perlakukan dengan hati-hati, dan jangan unggah ke layanan pihak ketiga
tanpa memikirkan konsekuensinya.

Catatan tambahan: alat ini sengaja tidak memakai AI/ML agar hasilnya deterministik
dan bisa dijelaskan. Beberapa kompetisi forensik melarang penggunaan alat AI
agentic — periksa aturan lombamu sendiri sebelum memakai alat apa pun, termasuk
yang ini.

---

## Lisensi

[MIT](LICENSE) — bebas dipakai, dimodifikasi, dan didistribusikan, termasuk untuk
keperluan komersial, selama pemberitahuan hak cipta disertakan.

Perlu ditegaskan bagian yang sering terlewat: perangkat lunak ini disediakan
**apa adanya, tanpa jaminan apa pun**. Untuk alat forensik itu bukan sekadar
formalitas hukum — hasil analisisnya bisa keliru, dan tanggung jawab atas
kesimpulan yang kamu tulis di laporan tetap ada padamu. Baca bagian
[Batasan yang wajib dibaca](#batasan-yang-wajib-dibaca).
