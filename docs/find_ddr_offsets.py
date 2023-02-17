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

for dll in Path(".").glob("gamemdx*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()

        game = {}
        game["info"] = {}
        game["info"]["title"] = "DDR"
        game["info"]["version"] = None
        game["info"]["datecode"] = dll.stem[7:].strip("-")
        game["info"]["file"] = "gamemdx.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Force enable fast/slow"
        find_pattern("8B 41 44 C3", 0x75000)
        patch(title, "31 C0 40")

        title = "Force background judgement"
        find_pattern("8B 41 40 C3", 0x75000)
        patch(title, "31 C0")

        title = "Force darkest background"
        find_pattern("75 03 33 C0 C3 8B 41 34 C3", 0x80000)
        patch(title, "33 C0 B0 03")

        title = "Opaque background for darkest background option"
        find_pattern("00 00 00 00 00 00 44 40", 0x100000, 12)
        patch(
            title,
            "A4 70 7D",
            tooltip="This makes the darkest background option be 99% opaque, hiding the dancers and videos.",
        )

        title = "Song Unlock"
        find_pattern("83 7D 08 01 BA 01 00 00 00 0F", 0x75000)
        find_pattern_backwards("CC CC CC CC CC CC", pos())
        find_pattern("32 C0", pos())
        patch(title, "B0 01")
        find_pattern_backwards("75", pos(), -1)
        patch(title, "90 90")
        try:
            find_pattern("83 C4 0C 03 FE 89 7B 34", 0x75000)
            find_pattern("0F", pos())
            patch(title, "90 E9")
        except ValueError:
            pass
        try:
            find_pattern(str.encode("eventno_2").hex(), pos())
            patch(title, "62")
        except ValueError:
            pass
        find_pattern(str.encode("eventno\x00").hex(), pos())
        patch(title, "62")
        find_pattern(str.encode("region\x00").hex(), pos())
        patch(title, "62")
        find_pattern(str.encode("limited_cha"), pos())
        patch(title, "62")
        find_pattern(str.encode("limited\x00").hex(), pos())
        patch(title, "62")

        title = "Tutorial Skip"
        find_pattern("8B 08 83 39 01 74")
        find_pattern("84 C0 75", pos(), 2)
        patch(title, "EB")

        # title = "Caution Screen Skip"
        # find_pattern(rb"FF FF 8B FB C7 05", 0x10000, 2)
        # start_pos = pos()
        # find_pattern("FF FF E8", pos())
        # end_pos = pos()
        # mm.seek(start_pos)
        # patch(
        #     title,
        #     f"EB {hex(end_pos - start_pos)[2:]}",
        #     tooltip="Breaks network score loading",
        # )

        title = "Timer Freeze"
        find_pattern("7E 05 BE 63")
        find_pattern("74", pos())
        patch(title, "EB")

        title = "Unlock options"
        while True:
            find_pattern("04 00 00 00 00 E8", pos(), 1)
            if int(pos() - 2) in range(0x1000, 0x75000):
                patch(
                    title,
                    "01",
                    tooltip="Extended e-amusement exclusive options such as ARROW COLOR and 0.25 speed mod",
                )
            else:
                break

        title = "Enable all speed modifiers"
        find_pattern("7C FF FF FF 7E 02", 0x90000, 4)
        patch(
            title,
            "EB",
            tooltip="Including x4.25/x7.75, Must have the Unlock Options patch enabled",
        )

        title = "Enable LIFE8 modifier"
        find_pattern("77 1A", pos())
        patch(title, "EB 07", tooltip="Must have the Unlock Options patch enabled")
        find_pattern("8A C3 5B 8B 4D FC", pos())
        patch(title, "7F DC B0 01 EB DA")

        title = "PFC Mode"
        find_pattern("0F 9C C0 5D C2 04 00 83 F8 04", pos())
        patch(
            title,
            "B0 01 90",
            tooltip="Like Extra Encore Stage. If you hit a Great or a Good, you lose a life. This feature requires you to select LIFE8/LIFE4/RISKY on the Options, otherwise it has no effect.",
        )

        title = "MFC Mode"
        find_pattern_backwards("83 F8 02", pos(), -1)
        patch(
            title,
            "01",
            tooltip="Like PFC Mode except this time no Perfects. Requires PFC Mode to be enabled.",
        )

        title = "Hide all bottom text"
        find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
        start_pos = pos()
        find_pattern("00 4E 4F 54 20 41 56 41 49 4C 41 42 4C 45", pos())
        end_pos = pos() + 14
        hide_length = end_pos - start_pos
        find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
        patch(
            title,
            "00" * hide_length,
            tooltip="Such as EVENT MODE, PASELI, COIN, CREDIT, MAINTENANCE",
        )

        title = "Autoplay"
        find_pattern("01 00 00 74 40 6A 34 E8")
        find_pattern("74", pos())
        patch(title, "90 90")
        find_pattern("74", pos())
        patch(title, "90 90")

        title = "Force Cabinet Type 6"
        find_pattern(rb"\xFF\x24\x85..\x00\x10\x8B\x45\xFC\x85\xC0")
        start_pos = pos()
        find_pattern("BE 06 00 00 00", pos())
        end_pos = pos()
        mm.seek(start_pos)
        patch(
            title,
            f"E9 {hex(end_pos - start_pos - 5)[2:]} 00 00 00 90 90",
            tooltip="Gold cab, some assets (such as menu background) may not work",
        )

        title = "Force blue menu background"
        find_pattern("FE FF 83 F8 06", 0x10000, 5)
        a = pos()
        if mm.read(1).hex() == "75":
            mm.seek(pos() - 1)
            patch(title, "EB")
        else:
            mm.seek(pos() - 1)
            patch(title, "90 90")

        title = "Enable cabinet lights for Cabinet Type 6"
        find_pattern("CC CC CC CC CC CC CC CC CC 53 E8", 0, 10)
        patch(
            title,
            "B8 00 00",
            tooltip="This enables the use of cabinet lighting for Cabinet Type 6",
        )
        find_pattern("8B 00 83 60 04 FE E8", 0x20000, 6)
        patch(title, "B8 00 00 00 00")
        find_pattern("00 80 7C 24 12 00 0F 85")
        find_pattern("E8", pos())
        patch(title, "B8 01 00 00 00")

        title = "Enable DDR SELECTION"
        find_pattern("07 83 C0 04 3B C1 75 F5 3B C1 0F 95 C0 84 C0 75", 0x75000)
        find_pattern("32 C0", pos())
        patch(title, "B0 01", tooltip="Even works in offline/local mode!")

        title = "Premium Free"
        find_pattern("B9 01 00 00 00 89 0D", 0x10000, 1)
        patch(title, "00", tooltip="Breaks network score saving")

        title = "Mute Announcer"
        find_pattern("C6 40 85 C0 0F 84", 0x20000, 4)
        patch(
            title,
            "90 E9",
            tooltip="Also mutes crowd cheering and booing during gameplay",
        )
        find_pattern(str.encode("voice.xwb"), 0x100000)
        patch(title, "62")
        try:
            find_pattern(str.encode("voice_n.xwb"), pos())
            patch(title, "62")
        except ValueError:
            pass

        title = "Force DDR SELECTION theme everywhere"
        find_pattern("0F 84 F7 00 00 0057 8B FB", 0x20000)
        patch(
            title,
            "90 E9",
            tooltip="Skips intro and enables the skin selected below on all songs",
        )
        find_pattern("C9 83 7A 10 0D 75", 0x90000, 5)
        patch(title, "90 90")
        find_pattern("FF FF FF 83 F8 04 77", pos(), 6)
        patch(title, "90 90")
        find_pattern("FF 24 85", pos())
        patch(title, "EB 11")

        title = "Choose forced theme"
        find_pattern("C3 B9 02 00 00 00 89", pos(), 2)
        patch_union(title, "1st", "01")
        patch_union(title, "EXTREME", "02")
        patch_union(title, "SuperNOVA2", "03")
        patch_union(title, "X2", "04")
        patch_union(title, "2013", "05")

        title = "Choose cabinet type timing offset. Set this to default for individual offsets below"
        find_pattern("88 5D F8 E8", 0x10000, 3)
        patch_union(title, "Default", mm.read(5), adjust=-5)
        patch_union(title, "Force CRT 945 p3io timing", "B800000000")
        patch_union(title, "Force LCD 945 p3io timing", "B801000000")
        patch_union(title, "Force LCD HM64 p4io timing", "B802000000")
        patch_union(title, "Force CRT ADE-6291 p3io timing", "B803000000")
        patch_union(title, "Force LCD ADE-6291 p3io timing", "B804000000")
        patch_union(title, "Force LCD ADE-6291 p4io timing", "B805000000")
        patch_union(title, "Force LCD ADE-6291 bio2 timing", "B806000000")

        title = "SSQ Offset"
        find_pattern("57 00 00 00", 0x10000)
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", -1000, patch_type="number")
        patch_union(title, "max", 1000, patch_type="number")

        title = "Sound Offset"
        find_pattern_backwards("1C 00 00 00", pos(), -4)
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", 0, patch_type="number")
        patch_union(title, "max", 1000, patch_type="number")

        title = "Input Offset"
        find_pattern("11 00 00 00", pos())
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", 0, patch_type="number")
        patch_union(title, "max", 1000, patch_type="number")

        title = "Render Offset"
        find_pattern("00 00 00 00", pos())
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", 0, patch_type="number")
        patch_union(title, "max", 1000, patch_type="number")

        title = "Bomb Frame Offset"
        find_pattern_backwards("01 00 00 00", pos(), -4)
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", 0, patch_type="number")
        patch_union(title, "max", 10, patch_type="number")

        title = "Center arrows for single player"
        find_pattern("7C 24 48 39 02 75 14", 0x20000, 5)
        patch(title, "EB")
        find_pattern("75 05 B8", pos())
        patch(title, "90 90")
        x_axis = struct.pack("<i", 495).hex()
        # freeze_judge
        find_pattern("CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC")
        int3_absolute = pos()
        int3_rva = pe.get_rva_from_offset(int3_absolute)
        find_pattern("83 C4 0C 8D 44 24 1C", pos())
        find_pattern("83 C4 0C 8D 4C 24 1C", pos())
        freeze = pe.get_rva_from_offset(pos())
        patch(title, f"E9 {struct.pack('<i', int3_rva - freeze - 5).hex()} 90 90")
        mm.seek(int3_absolute)
        patch(
            title,
            f"83 C4 0C 8D 4C 24 1C 36 C7 01 {x_axis} E9 {struct.pack('<i', freeze - int3_rva - 12).hex()}",
        )
        # arrow
        find_pattern(
            "CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC",
            int3_absolute + 20,
        )
        int3_absolute = pos()
        int3_rva = pe.get_rva_from_offset(int3_absolute)
        for search in range(6):
            find_pattern("83 C4 0C 8D 44 24 1C", pos() + 1)
        arrow = pe.get_rva_from_offset(pos())
        patch(title, f"E9 {struct.pack('<i', int3_rva - arrow - 5).hex()} 90 90")
        mm.seek(int3_absolute)
        patch(
            title,
            f"83 C4 0C 8D 44 24 1C 36 C7 00 {x_axis} E9 {struct.pack('<i', arrow - int3_rva - 12).hex()}",
        )

        title = "Fullscreen FPS Target"
        find_pattern("00 00 00 3C 00 00 00", 0x1000, 3)
        for fps in (60, 120, 144, 165, 240, 360):
            patch_union(title, f"{fps} FPS", struct.pack("<i", fps))

        # title = "Omnimix"
        # find_pattern("00 85 C0 74 07 E8", 0x1000, 1)
        # find_pattern("00 85 C0 74 07 E8", pos(), 3)
        # patch(title, "EB", tooltip="v1.1")
        # find_pattern("83 F8 04 75 05 C6 44 24 1B 01", 0x25000)
        # try:
        #    find_pattern("75 08 C7 44 24 20 12", pos())
        #    patch(title, "90 90 C7 44 24 20 26")
        # except ValueError:
        #    find_pattern("14 00 00 00", pos())
        #    patch(title, "26")
        # find_pattern("0F 82 99 00 00 00", 0x80000)
        # find_pattern("01 0F 84", pos(), 1)
        # patch(title, "90 E9")
        # find_pattern("24 74 07 83 C0 04 3B C1 75 F4 3B C1 0F 95 C0 84 C0 0F 85", 0x80000, 12)
        # patch(title, "B0 01 90")
        # find_pattern("FF 00 75 3E", 0x80000, 2)
        # patch(title, "EB")
        # find_pattern("10 57 89 85 1C FE FF FF 68 00 00 10 00 33 C0", 0x90000, 11)
        # patch(title, "20")
        # find_pattern("68 00 00 10 00", pos(), 3)
        # patch(title, "20")
        # find_pattern("66 66 66 3F 66 66 66 3F 66 66 66 3F 33 33 33 3F CD CC", 0x100000)
        # find_pattern_backwards("80 3F", pos(), -4)
        # find_pattern_backwards("80 3F", pos())
        ## find_pattern("00 00 00 00 00 00", pos(), -2)    # overwrite A3 attract song defaults (add 5 more songs to attract_mcodes)
        # find_pattern("5A 96 00 00 00 00 00 00", pos())    # keep A3 attract song defaults
        # attract_mcodes = (10836, 37481, 33551, 32792, 397, 36865, 37202, 220, 255, 10523, 33567, 37911, 36864, 36, 36879, 28715, 454, 314, 32810)
        # patch(title, struct.pack('q'*len(attract_mcodes), *attract_mcodes))

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("gamemdx", "ddr")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
