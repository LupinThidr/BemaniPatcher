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

for dll in Path(".").glob("popn22*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "pop'n music"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[6:].strip("-")
        game["info"]["file"] = "popn22.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "E: Drive Fix"
        find_pattern("65 3A 2F", 0x200000)
        patch(title, "64 65 76", tooltip="Fix crash caused by no E: drive")

        title = "HDMI Audio Fix"
        find_pattern("10 85 C0 75 96", 0x100000, 1)
        patch(title, "90" * 4)

        title = "Prevent Windows volume change on boot"
        find_pattern("10 89 44 24 14 8B C6", 0x100000)
        find_pattern_backwards("83 EC", pos(), -2)
        patch(title, "C3", tooltip="If your volume gets forced to max, turn this on")

        title = "Boot to Event Mode"
        find_pattern(
            "8B 00 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC C7 40 04 00 00 00 00",
            0x80000,
        )
        patch(title, "31 C0 40 C3")

        title = "Remove Timer"
        find_pattern("00 0F 85 65 05 00 00", 0x90000, 1)
        patch(title, "90 E9")

        title = "Skip Menu and Long Note Tutorials"
        find_pattern("00 84 C0 74 3A E8", 0x20000, 3)
        patch(title, "EB")
        find_pattern_backwards("75 5E", pos(), -2)
        patch(title, "EB")
        find_pattern("5F 5E 66 83 F8 01 75", 0x70000, 6)
        patch(title, "EB")

        title = "Unlock All Songs"
        find_pattern("FF FF A9 06 00 00 68 74", 0x90000, 7)
        patch(title, "EB")
        find_pattern_backwards("74 13", pos(), -2)
        patch(title, "90 90")

        title = "Unlock EX Charts"
        ex = []
        mm.seek(0x200000)
        while True:
            find_pattern("80 00 00 03", pos(), 1)
            if int(pos() - 2) > 0x200000:
                mm.seek(pos() - 1)
                patch(title, "00")
            else:
                break
        mm.seek(0x200000)
        while True:
            find_pattern("80 00 00 07", pos(), 1)
            if int(pos() - 2) > 0x200000:
                mm.seek(pos() - 1)
                patch(title, "00")
            else:
                break

        find_pattern("83 38 00 75 22", 0x90000, 3)
        if pos() > 0x1000:
            title = "Unlock Deco Parts"
            patch(title, "90 90")

        title = "Unlock Characters"
        find_pattern("01 00 00 74 0E 8B FA E8", 0x90000, 3)
        patch(title, "EB")

        title = "Premium Free"
        find_pattern("CC FE 46 0E 80 BE", 0x90000, 1)
        patch(title, "90 90 90", tooltip="Score buffer never resets, use offline")
        find_pattern("75", pos())
        patch(title, "EB")
        find_pattern("77 3E", pos())
        patch(title, "EB 07")

        title = "Autoplay"
        find_pattern("84 C0 0F 84 08 01 00 00", 0x90000, 2)
        patch(title, "90" * 6)
        find_pattern("74 53", pos())
        patch(title, "90 90")

        title = "Replace COLOR CHECK test menu with debug CHARA VIEWER"
        find_pattern(str.encode("COLOR CHECK").hex(), 0x190000)
        patch(
            title,
            str.encode("CHARA VIEWER\x00"),
            tooltip="Press service button to exit",
        )
        find_pattern("33 C0 68 A4 06", 0x10000)
        find_pattern_backwards("CC CC", pos())
        chara = pe.get_rva_from_offset(pos())
        find_pattern("00 00 00 00 68 AC 00 00 00 E8", 0x20000, 5)
        patch(title, "B0 34 0C")
        find_pattern("50 E8", pos(), 2)
        here = pe.get_rva_from_offset(pos())
        patch(title, struct.pack("<i", chara - here - 4))

        title = "Replace SCREEN CHECK test menu with debug MUSIC INFO CHECKER"
        find_pattern(str.encode("SCREEN CHECK"), 0x190000)
        patch(
            title,
            str.encode("MUSIC INFO\x00\x00"),
            tooltip="Press service button to exit",
        )
        find_pattern("33 C0 33 C9 33 D2 66 89 86 DC", 0x10000)
        find_pattern_backwards("CC CC", pos())
        music = pe.get_rva_from_offset(pos())
        find_pattern("00 00 00 00 68 8C 00 00 00 E8", 0x20000, 5)
        patch(title, "B0 34 0C")
        find_pattern("50 E8", pos(), 2)
        here = pe.get_rva_from_offset(pos())
        patch(title, struct.pack("<i", music - here - 4))

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("popn22", "popn")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
