"""
Setup sekali jalan: `python -m backend.setup`

Cek 9 tool eksternal, install yang wajib kalau belum ada, siapkan folder storage.
"""
import sys

from . import config as settings
from .services import tools


def main() -> int:
    # Peringatan dini: spasi di path venv merusak shebang console script pip di
    # Linux/WSL. tools.run() sudah menanganinya, tapi perintah yang kamu ketik
    # sendiri di terminal tetap akan gagal -- lebih baik tahu sekarang.
    if " " in str(tools.SCRIPTS_DIR) and not tools.IS_WINDOWS:
        print(f"CATATAN: path berisi spasi -- {tools.SCRIPTS_DIR}")
        print("  Console script pip (vol, binwalk) tidak bisa dijalankan langsung dari")
        print("  terminal karena shebang Linux berhenti di spasi pertama.")
        print("  Tools ini menanganinya sendiri, tapi kalau ingin memanggil manual pakai:")
        print(f"    python {tools.SCRIPTS_DIR}/vol -f dump.mem windows.pslist")
        print("  Atau taruh venv di path tanpa spasi: python3 -m venv ~/venv-forensik\n")

    print("Menyiapkan folder storage...")
    settings.init_storage()
    print(f"  {settings.STORAGE}")

    print(f"\nCek tool eksternal (AUTO_INSTALL={'on' if settings.AUTO_INSTALL else 'off'})...")
    try:
        status = tools.preflight(auto_install=settings.AUTO_INSTALL)
    except RuntimeError as e:
        print(f"\nGAGAL: {e}", file=sys.stderr)
        print("Tool wajib tidak tersedia. Lihat section 4.0.1 spec untuk cara install manual.",
              file=sys.stderr)
        return 1

    for name, ok in status.items():
        if ok:
            print(f"  [ok]      {name:<10} {tools.resolve(name)}")
        else:
            label = "WAJIB" if tools.TOOLS[name].get("required") else "opsional"
            print(f"  [kosong]  {name:<10} ({label}) {tools.hint(name)}")

    missing = [n for n, ok in status.items() if not ok]
    print(f"\nSiap. {len(status) - len(missing)}/{len(status)} tool tersedia.")
    if missing:
        print(f"Modul yang butuh {', '.join(missing)} akan dilewati sampai tool-nya dipasang.")
        # Perintah gabungan jauh lebih berguna daripada sepuluh baris terpisah.
        packages = sorted({tools.TOOLS[n]["apt"] for n in missing
                           if tools.TOOLS[n].get("apt")}) if not tools.IS_WINDOWS else []
        pips = sorted({tools.TOOLS[n]["pip"] for n in missing if tools.TOOLS[n].get("pip")})
        if packages:
            print(f"\nPasang sekaligus:  sudo apt install -y {' '.join(packages)}")
        if pips:
            print(f"Lewat pip       :  pip install {' '.join(pips)}")
    print("\nCoba: python -m backend.analyze <file.pcap>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
