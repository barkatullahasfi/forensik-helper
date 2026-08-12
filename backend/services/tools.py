"""
Resolusi binary eksternal, auto-install, dan satu-satunya wrapper subprocess.

Dibuat pertama karena semua modul lain memanggil tool eksternal lewat sini.
Tanpa titik pusat, tiap modul mengulang tiga hal yang sama dan salah dengan cara
yang sama: mencari binary di PATH, menangani kegagalan subprocess, dan
menerjemahkan nama paket per OS.
"""
import glob
import os
import shutil
import subprocess
import sys
import sysconfig
from functools import lru_cache
from pathlib import Path

IS_WINDOWS = os.name == "nt"

# Direktori console script pip. Di Windows ini `<prefix>\Scripts`, BUKAN
# direktori python.exe -- `Path(sys.executable).parent / "vol.exe"` tidak akan
# pernah ketemu. Di venv pun ini yang benar, karena mengikuti prefix aktif.
SCRIPTS_DIR = Path(sysconfig.get_path("scripts"))

# Satu tabel: nama binary -> cara install per platform + tempat mencarinya kalau
# installer tidak menaruhnya di PATH (kasus paling sering di Windows).
TOOLS = {
    "tshark": {
        "winget": "WiresharkFoundation.Wireshark",
        "apt": "tshark",
        "brew": "wireshark",
        "win_paths": [r"C:\Program Files\Wireshark\tshark.exe"],
        "required": True,
    },
    "capinfos": {  # satu paket dengan tshark
        "winget": "WiresharkFoundation.Wireshark",
        "apt": "wireshark-common",
        "brew": "wireshark",
        "win_paths": [r"C:\Program Files\Wireshark\capinfos.exe"],
        "required": True,
    },
    "exiftool": {
        "winget": "OliverBetz.ExifTool",
        "apt": "libimage-exiftool-perl",  # BUKAN 'exiftool' -- nama paket apt-nya beda
        "brew": "exiftool",
        # winget memasang ExifTool PER-USER ke %LOCALAPPDATA%\Programs, bukan ke
        # Program Files. Kedua lokasi harus dicari.
        "win_paths": [r"%LOCALAPPDATA%\Programs\ExifTool\exiftool.exe",
                      r"C:\Program Files\ExifTool\exiftool.exe"],
        "required": False,
    },
    "vol": {  # Volatility 3. Entrypoint-nya 'vol', bukan 'vol3'.
        "pip": "volatility3",
        "required": False,
    },
    "binwalk": {"pip": "binwalk", "apt": "binwalk", "required": False},
    # Sleuth Kit tidak punya paket winget mandiri. Rilis resmi Windows berupa ZIP
    # yang diekstrak apa adanya, sehingga NOMOR VERSI ikut jadi nama direktori --
    # karena itu win_paths di sini memakai wildcard.
    **{name: {"apt": "sleuthkit", "brew": "sleuthkit", "choco": "sleuthkit",
              "required": False,
              "note_windows": "Tidak ada paket winget mandiri. Unduh ZIP resmi dari "
                              "github.com/sleuthkit/sleuthkit/releases, ekstrak ke "
                              r"%LOCALAPPDATA%\Programs\sleuthkit",
              "win_paths": [rf"%LOCALAPPDATA%\Programs\sleuthkit\*\bin\{name}.exe",
                            rf"C:\Program Files\sleuthkit\*\bin\{name}.exe",
                            rf"C:\Program Files\sleuthkit\bin\{name}.exe"]}
       for name in ("fls", "mmls", "icat", "istat", "fsstat")},
    "steghide": {"apt": "steghide", "brew": "steghide", "required": False,
                 "note_windows": "Tidak ada build Windows resmi -- pakai lewat WSL "
                                 "atau lewati modul stego steghide"},
    # 'gem' saja, JANGAN 'apt: ruby': apt akan memasang Ruby lalu melaporkan
    # sukses padahal zsteg-nya sendiri belum terpasang.
    "zsteg": {"gem": "zsteg", "required": False,
              "note": "Butuh Ruby lebih dulu (Linux: sudo apt install ruby; "
                      "Windows: RubyInstaller), lalu: gem install zsteg"},
}


class ToolMissing(RuntimeError):
    pass


@lru_cache(maxsize=None)
def resolve(name: str) -> str:
    """
    Path absolut binary. Urutan: PATH dulu, baru lokasi instalasi umum.

    Installer Wireshark di Windows TIDAK menambahkan dirinya ke PATH, jadi
    shutil.which('tshark') saja gagal di mesin yang sebenarnya sudah punya
    Wireshark terpasang.
    """
    found = shutil.which(name)
    if found:
        return found
    # Tool yang dipasang lewat pip: cek direktori console script lebih dulu.
    # Scripts/ sering tidak ada di PATH proses non-interaktif, dan itu membuat
    # tool yang JELAS sudah terinstall dilaporkan hilang.
    if TOOLS.get(name, {}).get("pip"):
        for suffix in (".exe", "") if IS_WINDOWS else ("",):
            candidate = SCRIPTS_DIR / f"{name}{suffix}"
            if candidate.exists():
                return str(candidate)
    for candidate in TOOLS.get(name, {}).get("win_paths", []):
        # os.path.expandvars: win_paths boleh memakai %LOCALAPPDATA% dsb, karena
        # banyak installer Windows memasang per-user, bukan ke Program Files.
        expanded = os.path.expandvars(candidate)
        if "*" in expanded:
            # Wildcard untuk paket yang diekstrak dengan nomor versi di nama
            # direktori (mis. sleuthkit-4.15.0-win32). Ambil versi TERBARU.
            matches = sorted(glob.glob(expanded), reverse=True)
            if matches:
                return matches[0]
        elif Path(expanded).exists():
            return expanded
    # winget menaruh shim untuk paket portable di direktori Links-nya sendiri,
    # yang juga tidak selalu masuk PATH proses non-interaktif.
    if IS_WINDOWS:
        for directory in (Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links",
                          Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / name):
            candidate = directory / f"{name}.exe"
            if candidate.exists():
                return str(candidate)
    raise ToolMissing(f"'{name}' tidak ditemukan di PATH maupun lokasi instalasi standar")


def is_available(name: str) -> bool:
    try:
        resolve(name)
        return True
    except ToolMissing:
        return False


def _winget() -> str | None:
    """
    winget sendiri sering tidak ada di PATH: ia dipasang sebagai app-execution
    alias di %LOCALAPPDATA%\\Microsoft\\WindowsApps, dan direktori itu hanya masuk
    PATH pada sesi interaktif. shutil.which('winget') saja akan menyimpulkan
    'tidak ada jalur install otomatis' di mesin yang sebenarnya punya winget.
    """
    found = shutil.which("winget")
    if found:
        return found
    alias = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "winget.exe"
    return str(alias) if alias.exists() else None


def install_command(name: str) -> list[str] | None:
    """Perintah install yang sesuai OS saat ini, atau None kalau tidak ada jalur otomatis."""
    spec = TOOLS[name]
    if spec.get("pip"):
        return [sys.executable, "-m", "pip", "install", spec["pip"]]
    if IS_WINDOWS:
        winget = _winget()
        if spec.get("winget") and winget:
            return [winget, "install", "--id", spec["winget"], "-e", "--silent",
                    "--accept-package-agreements", "--accept-source-agreements"]
        if spec.get("choco") and shutil.which("choco"):
            return ["choco", "install", "-y", spec["choco"]]
        return None
    if shutil.which("apt-get") and spec.get("apt"):
        return ["sudo", "apt-get", "install", "-y", spec["apt"]]
    if shutil.which("brew") and spec.get("brew"):
        return ["brew", "install", spec["brew"]]
    if shutil.which("gem") and spec.get("gem"):
        return ["sudo", "gem", "install", spec["gem"]]
    return None


def hint(name: str) -> str:
    """
    Cara memasang tool ini DI OS YANG SEDANG DIPAKAI.

    Catatan statis di TOOLS bersifat per-platform: menampilkan "unduh ZIP resmi
    lalu ekstrak ke %LOCALAPPDATA%" kepada pengguna Linux -- yang cukup
    `apt install sleuthkit` -- adalah petunjuk yang menyesatkan.
    """
    spec = TOOLS.get(name, {})
    cmd = install_command(name)
    if cmd:
        return "jalankan: " + " ".join(cmd)
    if IS_WINDOWS and spec.get("note_windows"):
        return spec["note_windows"]
    if spec.get("note"):
        return spec["note"]
    manual = [f"{mgr}: {spec[mgr]}" for mgr in ("apt", "brew", "gem", "choco", "winget")
              if spec.get(mgr)]
    return ("belum ada jalur otomatis di OS ini"
            + (f" -- paketnya bernama {', '.join(manual)}" if manual else ""))


def ensure(name: str, auto_install: bool = True) -> str:
    """
    Kembalikan path tool; install dulu kalau belum ada.

    Dipanggil sekali di preflight, bukan di setiap pemanggilan -- supaya tidak
    menembak winget/apt puluhan kali per analisis.
    """
    if is_available(name):
        return resolve(name)
    cmd = install_command(name) if auto_install else None
    if not cmd:
        note = TOOLS[name].get("note", "")
        raise ToolMissing(
            f"'{name}' belum terinstall dan tidak ada jalur install otomatis di OS ini. {note}".strip())
    print(f"[tools] '{name}' tidak ditemukan -- menginstall: {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True)
    # winget/apt menaruh binary di direktori yang belum tentu ada di PATH proses
    # yang sedang berjalan. Tambahkan lokasi standarnya sebelum resolve ulang.
    extra = [str(Path(p).parent) for p in TOOLS[name].get("win_paths", [])]
    if extra:
        os.environ["PATH"] = os.environ["PATH"] + os.pathsep + os.pathsep.join(extra)
    resolve.cache_clear()
    return resolve(name)


def preflight(auto_install: bool = True) -> dict[str, bool]:
    """
    Dipanggil sekali saat startup / `python -m backend.setup`.

    Tool `required` yang gagal = fatal, server tidak boleh naik diam-diam.
    Tool opsional yang gagal = dicatat, modul terkait di-disable, sisanya jalan.
    """
    status: dict[str, bool] = {}
    for name, spec in TOOLS.items():
        # Tool opsional tidak di-auto-install: `pip install volatility3` dan
        # `winget install` untuk fitur yang belum tentu dipakai itu menit-menit
        # yang terbuang di tiap startup. Diinstall saat modulnya dikerjakan.
        want_install = auto_install and spec.get("required", False)
        try:
            ensure(name, auto_install=want_install)
            status[name] = True
        except (ToolMissing, subprocess.CalledProcessError) as e:
            status[name] = False
            if spec.get("required"):
                raise RuntimeError(f"Tool wajib '{name}' tidak tersedia: {e}") from e
    return status


def _runnable(cmd: list) -> list[str]:
    r"""
    Siapkan argumen agar bisa dieksekusi, termasuk saat shebang-nya rusak.

    Console script pip di Linux/WSL diawali shebang berisi path interpreter venv.
    Kernel membaca shebang hanya sampai SPASI PERTAMA, jadi venv yang berada di
    direktori bernama 'forensik _helper' menghasilkan interpreter
    '/mnt/c/.../forensik' yang tidak ada -- eksekusi gagal dengan ENOENT, dan
    Python melaporkannya sebagai 'No such file or directory' pada nama SKRIPNYA,
    sehingga terlihat seolah tool-nya belum terpasang padahal ada.

    Menjalankan skripnya lewat interpreter secara eksplisit melewati shebang
    sepenuhnya, jadi tool tetap berfungsi tanpa perlu memindahkan project.
    """
    cmd = [str(c) for c in cmd]
    if not cmd:
        return cmd
    first = Path(cmd[0])
    try:
        in_scripts = first.parent.resolve() == SCRIPTS_DIR.resolve()
    except OSError:
        in_scripts = False
    if in_scripts and " " in str(SCRIPTS_DIR) and not IS_WINDOWS:
        return [sys.executable, cmd[0], *cmd[1:]]
    return cmd


def run(cmd: list[str], timeout: int = 900, check: bool = True,
        stdout_to: Path | None = None) -> str:
    """
    Satu wrapper subprocess untuk seluruh tools ini.

    Alasan wajib dipakai: pola `json.loads(subprocess.run(...).stdout)` tanpa cek
    returncode menghasilkan JSONDecodeError tanpa informasi apa pun ketika
    tool-nya gagal. Yang sebenarnya perlu dilihat analis ada di stderr --
    'file format not recognised', 'permission denied', 'no such plugin'.

    shell=False selalu (list argumen, bukan string): path Windows penuh spasi dan
    nama file evidence dari user tidak boleh sampai diinterpretasi shell.
    """
    cmd = _runnable(cmd)
    if stdout_to:
        with open(stdout_to, "wb") as out:
            proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, timeout=timeout)
        stdout, stderr = "", proc.stderr.decode("utf-8", errors="replace")
    else:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"{Path(cmd[0]).name} keluar dengan kode {proc.returncode}\n"
            f"perintah: {' '.join(cmd)}\nstderr: {stderr.strip()[:800]}")
    return stdout
