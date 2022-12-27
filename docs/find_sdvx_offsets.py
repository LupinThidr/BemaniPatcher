import hashlib
import json
import mmap
import pefile
import re
import struct
import time
from pathlib import Path


def pos():
    return mm.tell()


def find_pattern(pattern, offset=0, adjust=0):
    if type(pattern) == str:
        return mm.seek(mm.find(bytes.fromhex(pattern), offset) + adjust)
    elif type(pattern) == bytes:
        return mm.seek(re.search(pattern, mm[offset:]).start() + offset + adjust)


def find_pattern_backwards(pattern, start=0, adjust=0):
    pattern = pattern.replace(" ", "")
    pattern_len = len(pattern) // 2
    while mm.read(pattern_len) != bytes.fromhex(pattern):
        mm.seek(pos() - pattern_len - 1)
    if adjust != 0:
        mm.seek(pos() + adjust)


def patch(title, on, toggle_in_game=False, tooltip=None):
    offset = pos()
    on = on.replace(" ", "") if type(on) == str else on.hex()
    off = mm.read(len(on) // 2).hex()

    if title not in game["data"]:
        game["data"][title] = {}
        game["data"][title]["tooltip"] = tooltip
        game["data"][title]["toggle_in_game"] = toggle_in_game
        game["data"][title]["type"] = "default"
        game["data"][title]["patches"] = []

    hack = {}
    hack["offset"] = f"0x{offset:X}"
    hack["rva"] = f"0x{pe.get_rva_from_offset(offset):X}"
    hack["off"] = off.upper()
    hack["on"] = on.upper()
    game["data"][title]["patches"].append(hack)


def patch_union(
    title, name, on, toggle_in_game=False, tooltip=None, patch_type="union", adjust=0
):
    offset = pos() + adjust
    if patch_type != "number":
        on = on.replace(" ", "").upper() if type(on) == str else on.hex().upper()

    if title not in game["data"]:
        game["data"][title] = {}
        game["data"][title]["tooltip"] = tooltip
        game["data"][title]["toggle_in_game"] = toggle_in_game
        game["data"][title]["type"] = patch_type
        game["data"][title]["patches"] = {}
        game["data"][title]["patches"]["offset"] = f"0x{offset:X}"
        game["data"][title]["patches"]["rva"] = f"0x{pe.get_rva_from_offset(offset):X}"

    game["data"][title]["patches"][name] = on


start_time = time.time()
game = None

for dll in Path(".").glob("soundvoltex*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "SOUND VOLTEX"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[11:].strip("-")
        game["info"]["file"] = "soundvoltex.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Disable power change"
        find_pattern("33 DB 85 C0 75 42", 0x100000, 4)
        patch(title, "EB", tooltip="Prevents power mode change on startup")

        title = "Disable monitor change"
        find_pattern("00 85 C0 75 2C E8", pos(), 3)
        patch(title, "EB", tooltip="Prevents monitor setting changes on startup")

        title = "Force BIO2 (KFC) IO in Valkyrie mode"
        find_pattern("18 48 8B F1 83 B9 98 00 00 00 00", 0x300000)
        find_pattern_backwards("C3")
        io = pe.get_rva_from_offset(pos())
        find_pattern("4E 0C 00 00 48", 0x300000, 7)
        patch(
            title,
            struct.pack("<i", io - pe.get_rva_from_offset(pos()) - 4),
            tooltip='Will only work with <spec __type=\\"str\\">F</spec> changed to either G or H, in ea3-config.xml.',
        )

        fps = (120, 144, 165, 240, 360)
        title = "Game FPS Target"
        find_pattern("40 00 00 00 00 00 00 4E", 0x600000, 1)
        patch_union(title, f"60 FPS (Default)", struct.pack("<d", 60))
        for value in fps:
            patch_union(title, f"{value} FPS", struct.pack("<d", value))

        title = "Note FPS Target"
        find_pattern("20 66 0F 6E F0 F3 0F E6 F6 F2 0F 59", 0x300000, 9)
        patch_union(title, "60 FPS (Default)", mm.read(15), adjust=-15)
        for value in fps:
            patch_union(
                title,
                f"{value} FPS",
                f"909090909090B8{struct.pack('<i', value).hex()}F20F2AF0",
            )

        title = "Force Note FPS Target"
        find_pattern("74 09", pos())
        patch(title, "90 90", tooltip="Enable this if above is not Default")
        find_pattern_backwards("74 5F", pos(), -2)
        patch(title, "90 90")

        title = "Shared mode WASAPI"
        find_pattern("90 BA 04 00 00 00 48 8B 0D", 0x400000, 2)
        patch(
            title,
            "00",
            tooltip="Only replaces the first audio device init attempt. Set output to 44100Hz 16bit if it doesn't work.",
        )

        title = "Shared mode WASAPI Valkyrie"
        find_pattern("90 BA 07 00 00 00 48 8B 0D", 0x400000, 2)
        patch(title, "00")

        title = "Allow non E004 cards"
        find_pattern("00 8B 11 83 FA 01 75", 0, 6)
        patch(
            title,
            "90 90",
            tooltip="Allows cards that do not have E004 card IDs (such as mifare cards) to work.",
        )
        find_pattern("74", pos())
        patch(title, "EB")

        title = "Unlock All Songs"
        for search in range(4):
            find_pattern("74 26 83", pos(), 1)
        mm.seek(pos() - 1)
        patch(title, "EB 1F")
        find_pattern("44 0F B6 74")
        patch(title, "41 BE  03 00 00 00")

        title = "Unlock All Difficulties"
        find_pattern("00 00 C7 40 30 04 00 00 00 E8", 0x200000)
        find_pattern("00 00 75", pos(), 2)
        patch(title, "EB")

        title = "Enable S-CRITICAL in Light Start"
        find_pattern("A8 00 00 00 48 83 C4 20 5B C3 48 83 EC 28", 0x60000)
        find_pattern("00 00 74", pos(), 2)
        patch(title, "90 90", tooltip="Only in Valkyrie mode")
        find_pattern("74 20 48", pos())
        patch(title, "90 90")
        start_pos = pos()
        find_pattern("00 00 74 04", pos(), 2)
        end_pos = pos()
        if end_pos - start_pos < 0xE00:
            patch(title, "90 90")

        title = "Uncensor album jackets (for K region only)"
        find_pattern(str.encode("jacket_mask"), 0x600000, 8)
        patch(title, "75")

        title = "Hide all bottom text"
        find_pattern(str.encode("FREE PLAY").hex(), 0x600000)
        patch(title, "00" * 9)
        find_pattern(str.encode("EVENT MODE").hex(), 0x600000)
        patch(title, "00" * 10)
        find_pattern(str.encode("TENKAICHI MODE").hex(), 0x600000)
        patch(title, "00" * 14)
        find_pattern(str.encode("PASELI: %s + %s").hex(), 0x600000)
        patch(title, "00" * 15)
        find_pattern(str.encode("CREDIT: %d   COIN: %d / %d").hex(), 0x600000)
        patch(title, "00" * 26)
        find_pattern(str.encode("CREDIT: %d\x00").hex(), 0x600000)
        patch(title, "00" * 11)
        find_pattern(str.encode("PASELI: NOT AVAILABLE").hex(), 0x600000)
        patch(title, "00" * 21)
        find_pattern(str.encode("PASELI: NO ACCOUNT").hex(), 0x600000)
        patch(title, "00" * 18)
        find_pattern(str.encode("\x00PASELI: %s\x00").hex(), 0x600000)
        patch(title, "00" * 12)
        find_pattern(str.encode("EXTRA PASELI: %s").hex(), 0x600000)
        patch(title, "00" * 16)
        find_pattern("00 25 30 2A 64 00", 0x600000)
        patch(title, "00" * 6)
        find_pattern(
            "83 47 81 5B 83 57 83 93 83 4F 92 86 82 C5 82 B7 28 25 73 81 60 29 89 F0 8F 9C 82 B7 82 E9 82 C9 82 CD 83 65 83 58 83 67 83 81 83 6A 83 85 81 5B 82 C9 93 FC 82 E8 81 41 83 65 83 93 83 4C 81 5B 82 F0 20 30 30 2C 20 30 30 2C 20 30 30 2C 20 36 2C 20 30 20 82 CC 8F 87 82 C5 89 9F 82 B5 82 C4 82 AD 82 BE 82 B3 82 A2 81 42 0A 83 47 81 5B 83 57 83 93 83 4F 82 F0 8D C4 8A 4A 82 B7 82 E9 8F EA 8D 87 82 CD 83 65 83 58 83 67 83 56 81 5B 83 93 82 C5 30 30 2C 20 30 30 2C 20 30 30 2C 20 36 2C 20 31 20 82 CC 8F 87 82 C5 89 9F 82 B5 82 C4 82 AD 82 BE 82 B3 82 A2 81 42",
            0x600000,
        )
        patch(title, "00" * 0xBA)

        title = "Disable subscreen in Valkyrie mode"
        find_pattern("83 BD B8 00 00 00 02", 0x300000, 15)
        rsp_offset = mm.read(1)
        mm.seek(pos() - 16)
        patch(title, f"41B60044887424{rsp_offset.hex()}9090909090909090")

        title = "Timer freeze"
        find_pattern("00 8B 83 80 00 00 00 85 C0 0F 84", 0x50000, 10)
        patch(title, "85")

        title = "Premium timer freeze"
        find_pattern("06 0F 85 84 00 00 00 8B", 0x200000, 1)
        patch(title, "90 E9")
        find_pattern("00 0F 84 83 00 00 00 8B 05", 0x200000, 1)
        patch(title, "90 E9")
        find_pattern("20 01 00 00 C6 80 E9", 0x100000)
        find_pattern("75 0D E8", pos())
        patch(title, "EB")

        title = "Hide premium guide banner"
        find_pattern(str.encode("pt_sousa_usr"))
        pt = pe.get_rva_from_offset(pos())
        find_pattern("00 44 89 44 24 28 48 8D 45", 0x200000)
        for search in range(4):
            find_pattern("45 33 C0", pos(), 6)
        patch(
            title,
            struct.pack("<i", pt - pe.get_rva_from_offset(pos()) - 4),
            tooltip="blpass_ef (rainbow outline on health gauge) is shown instead of pt_sousa_usr",
        )

        title = "Premium Time Length"
        find_pattern("B8 00 70 C9 B2 8B 00 00 00 48", 0x250000, 1)
        for meme in ("00:00", "00:01", "04:20", "13:37", "57:30", "69:00"):
            minutes = int(meme[:2])
            seconds = int(meme[3:]) + minutes * 60
            patch_union(
                title,
                meme,
                struct.pack("<q", seconds * 1000000000 if seconds != 0 else 6666666),
                toggle_in_game=True,
            )
        for minutes in (10, 15, 20, 30, 45, 60, 90):
            patch_union(
                title,
                f"{minutes} Minutes",
                struct.pack("<q", minutes * 60 * 1000000000),
                toggle_in_game=True,
            )

        title = "SDVX PLUS"
        find_pattern("76 04 44 89 51 18", 0x150000, 2)
        patch(title, "90" * 4, tooltip="v2.10")
        find_pattern("00 48 8B DA 4C 8B F1 48 8D", pos())
        for search in range(4):
            find_pattern("00 FF 15", pos(), 1)
        patch(title, "41 C6 46 05 58 90")
        find_pattern(str.encode("/data/others/music_db.xml").hex(), 0x600000, 1)
        patch(title, str.encode("plus"))
        find_pattern(str.encode("/data/music").hex(), 0x600000, 1)
        patch(title, str.encode("plus"))
        find_pattern(str.encode("game_bg/gmbg_edp2016.ifs").hex(), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_edp2016.ifs") + b"\x00" * 3)
        find_pattern(str.encode("game_bg/gmbg_kac5th_small.ifs").hex(), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_kac5th_s.ifs") + b"\x00" * 2)
        find_pattern(str.encode("game_bg/gmbg_omega18_maxma.ifs").hex(), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_omega18_m.ifs") + b"\x00")
        find_pattern(str.encode("game_bg/gmbg_omega_nianoa.ifs").hex(), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_omega_n.ifs") + b"\x00" * 3)
        find_pattern("73 5F 6A 61 63 6B 65 74 30", 0x600000)
        for n in range(1, 20):
            try:
                find_pattern(str.encode(f"s_jacket{str(n).zfill(2)}.ifs").hex(), 0, 8)
                if pos() > 0x1000:
                    patch(title, "30 30")
            except ValueError:
                continue
        find_pattern(str.encode("game_bg/gmbg_diver_02_rishna.ifs"), 0x600000)
        patch(
            title, str.encode("../../plus/g/gmbg_diver_02_rishna.ifs\x00\x00\x00").hex()
        )
        find_pattern(str.encode("game_bg/gmbg_omega_inoten.ifs"), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_omega_ino.ifs\x00").hex())
        find_pattern(str.encode("game_bg/gmbg_2015_kac01.ifs"), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_2015_k01.ifs\x00\x00").hex())
        find_pattern(str.encode("game_bg/gmbg_kac5th_rasis.ifs"), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_kac5th_ra.ifs\x00").hex())
        find_pattern(str.encode("game_bg/gmbg_nishinippori.ifs"), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_nishinip.ifs\x00\x00").hex())
        find_pattern(str.encode("game_bg/gmbg_tenkaichi03.ifs"), 0x600000)
        patch(title, str.encode("../../plus/g/gmbg_tenkai03.ifs\x00\x00").hex())

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("soundvoltex", "sdvx")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
