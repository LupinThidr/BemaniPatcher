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

for dll in Path(".").glob("game*.dll"):

    # no ddr here
    if str(dll).startswith("gamemdx"):
        continue

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "GITADORA"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[4:].strip("-")
        game["info"]["file"] = "game.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Timer Freeze"
        find_pattern("84 C0 0F 85 3E 01 00", 0, 2)
        patch(title, "90 E9", toggle_in_game=True)

        if not game["info"]["datecode"] or int(game["info"]["datecode"]) >= 2022121400:

            title = "Premium Timer Freeze"
            find_pattern("75 0C 85 C9 7E 2F FF C9 89 0D", 0, 6)
            patch(title, "90 90", toggle_in_game=True)

            for premium_time in (
                {"name": "Premium Time 15", "pattern": "F0 D2 00 00 FF 15"},
                {"name": "Premium Time 10", "pattern": "A0 8C 00 00 FF 15"},
            ):
                title = premium_time["name"]
                find_pattern(premium_time["pattern"])
                for meme in ("00:00", "00:01", "04:20", "13:37", "57:30", "69:00"):
                    minutes = int(meme[:2])
                    seconds = int(meme[3:]) + minutes * 60
                    patch_union(
                        title,
                        meme,
                        struct.pack("<i", seconds * 60 if seconds != 0 else 6),
                        toggle_in_game=True,
                    )
                for minutes in (10, 15, 20, 30, 45, 60, 90):
                    patch_union(
                        title,
                        f"{minutes} Minutes",
                        struct.pack("<i", minutes * 60 * 60),
                        toggle_in_game=True,
                    )

        title = "Cursor Hold"
        find_pattern("03 8B C2 C1 E8 1F 03 D0 6B C2 0F")
        find_pattern("0F 85", pos())
        patch(title, "90 E9", toggle_in_game=True)

        title = "Stage Freeze"
        find_pattern(
            rb"\xB9\x01\x00\x00\x00.....\x00\x84\xC0\x0F\x85.\x01\x00\x00.\x05", 0, 13
        )
        patch(title, "90 E9", toggle_in_game=True)

        title = "Skip Tutorial"
        find_pattern("30 83 F8 0D 0F 87", 0, 4)
        patch(title, "90 E9", toggle_in_game=True)

        title = "Unlock all songs"
        find_pattern("00 00 00 00 00 00 00 00 00 00 44 00 61 00 02 00 00", 0, 12)
        patch(title, "4D 01", toggle_in_game=True)
        find_pattern("00 00 00 00 00 00 00 00 00 00 44 00 63 00 02 00 00", pos(), 12)
        patch(title, "4D 01")
        find_pattern("C3 85 C9 75 08", 0, 3)
        patch(title, "EB 11")

        title = "Enable Long Music"
        find_pattern("CC CC 80 79 30 00 74", 0, 6)
        patch(title, "EB", toggle_in_game=True)

        title = "Autoplay"
        find_pattern(rb"\x00\x00\x00\x00\x75.\x80\x3D...\x02\x00\x75", 0, 13)
        patch(title, "EB", toggle_in_game=True)
        find_pattern(
            rb"\x00\x00\x74\x09\x83\x3D...\x02\x01\x74.\x44\x8B\x40\x20", pos()
        )
        find_pattern("02 00 0F 85", pos(), 2)
        patch(title, "90 E9")
        find_pattern("02 20 03 00 00 7F", pos())
        find_pattern("75 60", pos())
        patch(title, "EB")

        title = "Skip 'NOW DATA INITIALIZING'"
        find_pattern("00 00 0F 84 74 01 00 00", 0, 2)
        patch(title, "90" * 6, tooltip="Useful for testing only", toggle_in_game=True)

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("game", "gitadora")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
