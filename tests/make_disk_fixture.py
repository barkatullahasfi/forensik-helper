"""
Generator disk image FAT16 untuk menguji disk_image_analyzer.

Dibuat sendiri, bukan diunduh: tidak butuh admin (diskpart/VHD butuh elevasi),
tidak butuh koneksi, dan yang terpenting KITA yang menentukan berkas mana yang
dihapus -- jadi hasil recovery bisa dibandingkan dengan kebenaran yang diketahui.

    python tests/make_disk_fixture.py [output.dd]
"""
import struct
import sys
from pathlib import Path

BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 4
RESERVED_SECTORS = 1
NUM_FATS = 2
ROOT_ENTRIES = 512
TOTAL_SECTORS = 20480          # 10 MB
SECTORS_PER_FAT = 20
MEDIA_DESCRIPTOR = 0xF8

ROOT_DIR_SECTORS = ROOT_ENTRIES * 32 // BYTES_PER_SECTOR          # 32
ROOT_DIR_START = RESERVED_SECTORS + NUM_FATS * SECTORS_PER_FAT    # 41
DATA_START = ROOT_DIR_START + ROOT_DIR_SECTORS                    # 73
CLUSTER_BYTES = BYTES_PER_SECTOR * SECTORS_PER_CLUSTER            # 2048

# (nama 8.3, isi, dihapus?)
FILES = [
    ("NOTES   TXT", b"Catatan biasa, tidak dihapus.\r\n", False),
    ("SECRET  TXT", b"FLAG{berkas_ini_sudah_dihapus_tapi_masih_bisa_direcover}\r\n", True),
    ("MALWARE EXE", b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64
                    + b"PE\x00\x00" + b"\x00" * 200, True),
]


def boot_sector() -> bytes:
    bs = bytearray(BYTES_PER_SECTOR)
    bs[0:3] = b"\xeb\x3c\x90"                      # jump
    bs[3:11] = b"MSDOS5.0"                          # OEM
    struct.pack_into("<H", bs, 11, BYTES_PER_SECTOR)
    bs[13] = SECTORS_PER_CLUSTER
    struct.pack_into("<H", bs, 14, RESERVED_SECTORS)
    bs[16] = NUM_FATS
    struct.pack_into("<H", bs, 17, ROOT_ENTRIES)
    struct.pack_into("<H", bs, 19, TOTAL_SECTORS)
    bs[21] = MEDIA_DESCRIPTOR
    struct.pack_into("<H", bs, 22, SECTORS_PER_FAT)
    struct.pack_into("<H", bs, 24, 63)              # sectors per track
    struct.pack_into("<H", bs, 26, 255)             # heads
    bs[36] = 0x80                                   # drive number
    bs[38] = 0x29                                   # extended boot signature
    struct.pack_into("<I", bs, 39, 0x12345678)      # volume serial
    bs[43:54] = b"UJICOBA    "                      # volume label
    bs[54:62] = b"FAT16   "
    bs[510:512] = b"\x55\xaa"
    return bytes(bs)


def dir_entry(name: str, size: int, first_cluster: int, deleted: bool) -> bytes:
    entry = bytearray(32)
    entry[0:11] = name.encode("ascii")
    if deleted:
        # Inilah "penghapusan" di FAT: byte pertama nama diganti 0xE5. Metadata
        # dan rantai cluster tetap utuh -- itu sebabnya recovery masih mungkin.
        entry[0] = 0xE5
    entry[11] = 0x20                                # attribute: archive
    struct.pack_into("<H", entry, 14, 0x6000)       # create time
    struct.pack_into("<H", entry, 16, 0x5A21)       # create date (2025-01-01)
    struct.pack_into("<H", entry, 18, 0x5A21)       # access date
    struct.pack_into("<H", entry, 22, 0x6100)       # write time
    struct.pack_into("<H", entry, 24, 0x5A22)       # write date
    struct.pack_into("<H", entry, 26, first_cluster)
    struct.pack_into("<I", entry, 28, size)
    return bytes(entry)


def build(output_path: Path) -> Path:
    image = bytearray(TOTAL_SECTORS * BYTES_PER_SECTOR)
    image[0:BYTES_PER_SECTOR] = boot_sector()

    fat = bytearray(SECTORS_PER_FAT * BYTES_PER_SECTOR)
    struct.pack_into("<H", fat, 0, 0xFF00 | MEDIA_DESCRIPTOR)
    struct.pack_into("<H", fat, 2, 0xFFFF)

    root = bytearray(ROOT_DIR_SECTORS * BYTES_PER_SECTOR)
    cluster = 2
    for index, (name, content, deleted) in enumerate(FILES):
        clusters_needed = max(1, -(-len(content) // CLUSTER_BYTES))
        for n in range(clusters_needed):
            current = cluster + n
            nxt = 0xFFFF if n == clusters_needed - 1 else current + 1
            struct.pack_into("<H", fat, current * 2, nxt)
        offset = (DATA_START + (cluster - 2) * SECTORS_PER_CLUSTER) * BYTES_PER_SECTOR
        image[offset:offset + len(content)] = content
        root[index * 32:(index + 1) * 32] = dir_entry(name, len(content), cluster, deleted)
        cluster += clusters_needed

    for n in range(NUM_FATS):
        start = (RESERVED_SECTORS + n * SECTORS_PER_FAT) * BYTES_PER_SECTOR
        image[start:start + len(fat)] = fat
    start = ROOT_DIR_START * BYTES_PER_SECTOR
    image[start:start + len(root)] = root

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(image))
    return output_path


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/test_disk.dd")
    build(target)
    deleted = [f[0] for f in FILES if f[2]]
    print(f"{target}  ({target.stat().st_size} byte)")
    print(f"  berkas       : {len(FILES)}")
    print(f"  ditandai hapus: {', '.join(deleted)}")
