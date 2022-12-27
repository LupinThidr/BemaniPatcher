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

for dll in Path(".").glob("jubeat*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "jubeat"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[6:].strip("-")
        game["info"]["file"] = "jubeat.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Skip Tutorial"
        find_pattern("6A 01 8B C8 FF 15", 0x75000)
        find_pattern("84 C0 0F 85", pos(), 2)
        patch(title, "90 E9")

        title = "Select Music Timer Freeze"
        find_pattern("01 00 84 C0 75", 0x75000, 4)
        patch(title, "EB")

        title = "Skip Category Select"
        find_pattern("68 00 04", pos(), 2)
        patch(title, "07")

        title = "Result Timer Freeze"
        try:
            find_pattern("B3 01 83 BE", 0x75000, 1)
            find_pattern("B3 01 83 BE", pos())
            find_pattern("00 75", pos(), 1)
            patch(title, "EB", tooltip="Counts down to 0 then stops")
        except ValueError:
            find_pattern("00 75 09 33 C9 E8", 0x75000, 1)
            patch(title, "EB", tooltip="Counts down to 0 then stops")

        title = "Skip Online Matching"
        find_pattern("00 8B D7 33 C9 E8", 0x50000)
        find_pattern("0F 84", pos())
        patch(title, "90 E9")

        title = "Force Unlock All Markers"
        find_pattern("C8 22 10 84 C0 75 2B 0F 28 44 24 40", 0x150000, 5)
        patch(title, "EB")
        find_pattern("75 47 0F 28 85 B0 FD FF", pos())
        patch(title, "EB")
        find_pattern("0F B7 45 B0", pos())
        patch(title, "31 C0 90 90")

        title = "Force Unlock All Backgrounds"
        find_pattern("84 C0 75 43 0F 28 85 B0", 0x100000, 2)
        patch(title, "EB")
        find_pattern("0F B7 45 B0", pos())
        patch(title, "31 C0 90 90")
        find_pattern("6A 40 50 6A 06 56 FF 15 64", pos(), 1)
        find_pattern("6A 40 50 6A 06 56 FF 15 64", pos())
        find_pattern("10 84 C0 75", pos(), 3)
        patch(title, "EB")

        title = "Force Enable Expert Option"
        find_pattern("D1 C6 45 FF 01 A8 01 75 13", 0x90000)
        find_pattern_backwards("55 8B", pos(), -2)
        patch(title, "B0 01 C3")

        title = "Default Marker For Guest Play"
        find_pattern("B9 0B 66 C7 05", 0x45000, -2)
        patch_union(title, "Default", "31")
        patch_union(title, "Festo", "2E")
        patch_union(title, "Qubell", "28")
        patch_union(title, "Shutter", "04")

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("jubeat", "jubeat")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
