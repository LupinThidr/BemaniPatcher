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

for dll in Path(".").glob("nostalgia*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "NOSTALGIA"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[10:].strip("-")
        game["info"]["file"] = "nostalgia.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Timer Freeze"
        find_pattern("00 00 41 FF C8 33 FF", 0x250000, 2)
        patch(title, "90 90 90")

        title = "Shorter Monitor Check"
        find_pattern("00 00 00 EB 31 83 FA 1E 7C", 0x150000, 7)
        patch(title, "00")

        title = "Unscramble Pin Pad"
        find_pattern("48 8D 0C 80 48 03 C9", 0x150000)
        patch(title, "48 C7 C1 78 00 00 00")

        title = "Hide All Bottom Text"
        find_pattern(str.encode("FREE PLAY"), 0x450000)
        patch(title, "00" * 9)
        find_pattern(str.encode("EVENT MODE"), 0x450000)
        patch(title, "00" * 10)
        find_pattern(str.encode("PASELI: %s + %s").hex(), 0x450000)
        patch(title, "00" * 15)
        find_pattern(str.encode("CREDIT: %d   COIN: %d / %d"), 0x450000)
        patch(title, "00" * 26)
        find_pattern(str.encode("CREDIT: %d\x00"), 0x450000)
        patch(title, "00" * 11)
        find_pattern(str.encode("PASELI: NOT AVAILABLE"), 0x450000)
        patch(title, "00" * 21)
        find_pattern(str.encode("PASELI: NO ACCOUNT"), 0x450000)
        patch(title, "00" * 18)
        find_pattern(str.encode("\x00PASELI: %s\x00"), 0x450000)
        patch(title, "00" * 12)
        find_pattern(str.encode("EXTRA PASELI: %s"), 0x450000)
        patch(title, "00" * 16)

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("nostalgia", "nostalgia")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
