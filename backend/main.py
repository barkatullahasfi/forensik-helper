"""
API tipis di atas pipeline analisis.

    uvicorn backend.main:app --reload --port 8000

UI-nya memakai Swagger bawaan FastAPI di /docs -- sudah ada form upload file di
sana, jadi belum perlu halaman HTML sendiri untuk MVP.
"""
import re
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from . import config as settings
from .analyze import analyze_pcap, save_result
from .analyze_file import analyze as analyze_generic_file
from .services import cross_evidence_correlator, threat_feed, tools
from .services.file_carver import _force_unlink

TOOL_STATUS: dict[str, bool] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.init_storage()
    global TOOL_STATUS
    # auto_install=False di sini: startup server bukan tempat menunggu winget.
    # Instalasi dilakukan sekali lewat `python -m backend.setup`.
    TOOL_STATUS = tools.preflight(auto_install=False)
    yield


app = FastAPI(title="Network Forensics Helper", lifespan=lifespan)


@app.get("/", include_in_schema=False)
def index():
    """
    Satu berkas HTML statis, tanpa build tooling dan tanpa CDN.

    Tidak memakai StaticFiles mount: cuma ada satu halaman, dan CDN tidak dipakai
    supaya tools ini tetap berfungsi penuh saat dijalankan offline -- kondisi
    yang wajar untuk mesin analisis forensik.
    """
    return FileResponse(settings.ROOT / "frontend" / "index.html")


def _record_path(analysis_id: str) -> Path:
    return settings.ANALYSIS_DIR / f"{analysis_id}.json"


def _write_status(analysis_id: str, status: str, **extra) -> None:
    import json
    path = _record_path(analysis_id)
    record = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    record.update({"analysis_id": analysis_id, "status": status}, **extra)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")


_STAGE = re.compile(r"^\[(\d+)/(\d+)\]\s*(.*)$")


def _progress_writer(analysis_id: str):
    """
    Catat tahap yang sedang berjalan ke berkas status.

    Pipeline sudah melaporkan kemajuannya lewat callback `progress` berformat
    '[3/9] ...' untuk keperluan CLI; menyalurkannya ke berkas status membuat
    GUI bisa menampilkan kemajuan NYATA, bukan animasi yang cuma berputar.
    """
    def write(message: str) -> None:
        match = _STAGE.match(message)
        if match:
            _write_status(analysis_id, "processing", stage=match.group(3),
                          step=int(match.group(1)), total=int(match.group(2)))
        else:
            _write_status(analysis_id, "processing", stage=message)
    return write


def _run_analysis(analysis_id: str, path: Path, target_ip: str | None) -> None:
    _write_status(analysis_id, "processing", stage="menyiapkan", step=0, total=9)
    progress = _progress_writer(analysis_id)
    try:
        # Rute ditentukan ekstensi: pcap masuk pipeline jaringan, sisanya
        # (gambar/dokumen/audio/executable/disk/RAM) ke pipeline berkas.
        if settings.is_pcap(path):
            result = analyze_pcap(path, target_ip, progress=progress)
        else:
            result = analyze_generic_file(path, progress=progress)
        result["analysis_id"] = analysis_id
        result["status"] = "done"
        result["filename"] = path.name
        save_result(result)
    except Exception as e:  # noqa: BLE001 -- status error harus sampai ke user,
        _write_status(analysis_id, "error", error=str(e))  # bukan hilang di log


@app.post("/api/upload")
async def upload(background: BackgroundTasks, file: UploadFile,
                 target_ip: str | None = Form(default=None)):
    settings.init_storage()
    analysis_id = uuid.uuid4().hex[:12]
    # Path(...).name: nama file datang dari client, jangan pernah dipakai utuh
    # untuk membentuk path.
    dest = settings.UPLOAD_DIR / f"{analysis_id}_{Path(file.filename or 'upload.pcap').name}"
    with open(dest, "wb") as out:
        shutil.copyfileobj(file.file, out)   # streaming: pcap bisa ratusan MB
    _write_status(analysis_id, "pending", filename=dest.name)
    background.add_task(_run_analysis, analysis_id, dest, target_ip)
    return {"analysis_id": analysis_id, "status": "pending"}


@app.get("/api/analysis/{analysis_id}/status")
def get_status(analysis_id: str):
    """
    Status saja, tanpa isi hasilnya.

    Polling ke endpoint hasil penuh akan menarik ulang seluruh JSON tiap dua
    detik -- untuk pcap besar itu berarti mengirim megabyte `all_sessions` dan
    `volume.buckets` berulang kali hanya untuk membaca satu kata.
    """
    import json
    path = _record_path(analysis_id)
    if not path.exists():
        raise HTTPException(404, "analysis_id tidak ditemukan")
    record = json.loads(path.read_text(encoding="utf-8"))
    return {k: record.get(k) for k in
            ("analysis_id", "status", "filename", "error", "stage", "step", "total")}


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    path = _record_path(analysis_id)
    if not path.exists():
        raise HTTPException(404, "analysis_id tidak ditemukan")
    return JSONResponse(content=__import__("json").loads(path.read_text(encoding="utf-8")))


@app.get("/api/analysis")
def list_analyses():
    # ponytail: membaca seluruh JSON tiap analisis (bisa MB-an, berisi ribuan
    # sesi) hanya untuk mengambil 5 field. Tidak masalah untuk puluhan analisis;
    # kalau sudah ratusan, tulis file index terpisah atau pindah ke SQLite.
    import json
    items = []
    for path in settings.ANALYSIS_DIR.glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        items.append({k: record.get(k) for k in
                      ("analysis_id", "filename", "status", "analyzed_at", "error",
                       "file_category")})
    # Diurutkan berdasarkan WAKTU analisis. Mengurutkan nama berkas tidak ada
    # artinya: namanya UUID hex, jadi riwayat tampil dalam urutan acak dan yang
    # baru saja dijalankan tenggelam di tengah daftar.
    return sorted(items, key=lambda i: i.get("analyzed_at") or "", reverse=True)


def _delete_one(analysis_id: str) -> dict:
    """
    Hapus satu analisis beserta jejaknya: record, berkas upload, dan direktori
    carving. Menghapus record saja akan meninggalkan pcap ratusan MB di
    storage/uploads tanpa apa pun yang menunjuk ke sana.
    """
    import json
    removed = {"record": 0, "uploads": 0, "carved": 0}
    record = _record_path(analysis_id)
    source_name = ""
    if record.exists():
        try:
            source_name = json.loads(record.read_text(encoding="utf-8")).get("filename") or ""
        except ValueError:
            pass
        record.unlink()
        removed["record"] = 1
    for upload in settings.UPLOAD_DIR.glob(f"{analysis_id}_*"):
        _force_unlink(upload)
        removed["uploads"] += 1

    # Direktori carving dinamai dari NAMA BERKAS, bukan analysis_id: lewat API
    # namanya '<id>_<berkas>' (karena upload disimpan begitu), tapi lewat CLI
    # hanya '<berkas>'. Kedua bentuk harus dicari, kalau tidak hasil carving dari
    # analisis CLI jadi yatim dan tidak pernah ikut terhapus.
    candidates = list((settings.STORAGE / "carved").glob(f"{analysis_id}_*"))
    if source_name:
        stem = Path(source_name).stem
        candidates += [d for d in (settings.STORAGE / "carved").glob(stem) if d not in candidates]
    for carved in candidates:
        for path in sorted(carved.rglob("*"), key=lambda p: -len(p.parts)):
            if path.is_file():
                _force_unlink(path)   # nama objek HTTP bisa berupa device Windows
                removed["carved"] += 1
        shutil.rmtree(carved, ignore_errors=True)
    return removed


@app.delete("/api/analysis/{analysis_id}")
def delete_analysis(analysis_id: str):
    if not _record_path(analysis_id).exists():
        raise HTTPException(404, "analysis_id tidak ditemukan")
    return {"deleted": analysis_id, **_delete_one(analysis_id)}


@app.delete("/api/analysis")
def delete_all_analyses():
    ids = [p.stem for p in settings.ANALYSIS_DIR.glob("*.json")]
    total = {"record": 0, "uploads": 0, "carved": 0}
    for analysis_id in ids:
        for key, value in _delete_one(analysis_id).items():
            total[key] += value

    # Seluruh isi direktori carving adalah data turunan dari analisis. Setelah
    # semua analisis dihapus, sisa apa pun di sana sudah pasti yatim.
    carved_root = settings.STORAGE / "carved"
    if carved_root.exists():
        for path in sorted(carved_root.rglob("*"), key=lambda p: -len(p.parts)):
            if path.is_file():
                _force_unlink(path)
                total["carved"] += 1
        shutil.rmtree(carved_root, ignore_errors=True)
    return {"deleted_count": len(ids), **total}


@app.post("/api/evidence-pack")
def correlate_evidence_pack(analysis_ids: list[str]):
    """
    Tautkan beberapa analisis (pcap + disk + RAM + berkas) sebagai satu kasus,
    lalu korelasikan.

    Ini yang menjawab pertanyaan besar soal 'evidence pack': bukan temuan per
    berkas, tapi bagaimana semuanya tersambung.
    """
    import json
    loaded = []
    for analysis_id in analysis_ids:
        path = _record_path(analysis_id)
        if not path.exists():
            raise HTTPException(404, f"analysis_id {analysis_id} tidak ditemukan")
        loaded.append(json.loads(path.read_text(encoding="utf-8")))

    # Jenis evidence dikenali dari ISI record, bukan dari field kategori: hasil
    # analisis pcap dibuat pipeline lain dan memang tidak punya 'file_category'.
    def pick(predicate) -> dict:
        matches = [r for r in loaded if predicate(r)]
        # Kalau satu berkas dianalisis beberapa kali, pakai yang TERBARU --
        # hasil lama bisa berasal dari versi modul sebelum field yang dibutuhkan
        # korelasi (mis. all_ips) ada, dan korelasinya jadi nihil tanpa sebab jelas.
        return max(matches, key=lambda r: r.get("analyzed_at") or "") if matches else {}

    pcap = pick(lambda r: "all_sessions" in r)
    memory = pick(lambda r: (r.get("memory") or {}).get("available"))
    disk = pick(lambda r: (r.get("disk") or {}).get("available"))

    result = cross_evidence_correlator.correlate_all(
        pcap_result=pcap,
        memory_result=memory.get("memory", {}),
        disk_result=disk.get("disk", {}),
        file_results=[r for r in loaded if r.get("exact_hashes")])
    result["inputs"] = [{"analysis_id": r.get("analysis_id"), "filename": r.get("filename"),
                         "role": ("pcap" if r is pcap else "memory_dump" if r is memory
                                  else "disk_image" if r is disk else "berkas")}
                        for r in loaded]
    if pcap and not pcap.get("all_ips"):
        result["warning"] = ("Hasil pcap ini dibuat sebelum field 'all_ips' ada -- "
                             "jalankan ulang analisis pcap-nya supaya korelasi jaringan bisa dihitung")
    return result


@app.post("/api/feeds/refresh")
def refresh_feeds():
    """Tarik ulang feed Abuse.ch. Dijalankan berkala, bukan tiap analisis."""
    status = threat_feed.download_feeds()
    return {"downloads": status, "loaded": threat_feed.ThreatFeedChecker().stats()}


@app.get("/api/system/tools")
def system_tools():
    """Dashboard perlu tahu modul mana yang hidup, supaya tab kosong tidak
    disalahartikan sebagai 'tidak ada temuan'."""
    return {name: {"available": ok, "required": tools.TOOLS[name].get("required", False),
                   "hint": "" if ok else tools.hint(name)}
            for name, ok in TOOL_STATUS.items()}
