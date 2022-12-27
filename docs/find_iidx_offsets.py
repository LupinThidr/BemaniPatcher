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


def get_iidx():
    find_pattern("67 72 61 70 68 69 63 00", 0, 8)
    start = pos()
    find_pattern("00", pos())
    end = pos()
    find_pattern("67 72 61 70 68 69 63 00", 0, 8)
    full_title = mm.read(end - start).decode("cp932").replace(" main", "")
    game_version = int(full_title[15:][:2])
    return full_title, game_version


start_time = time.time()
game = None

for dll in Path(".").glob("bm2dx*.dll"):

    with open(dll, "r+b") as infile:
        mm = mmap.mmap(infile.fileno(), length=0, access=mmap.ACCESS_READ)
        pe = pefile.PE(dll, fast_load=True)
        h = infile.read()
        full_title, game_version = get_iidx()

        game = {}
        game["info"] = {}
        game["info"]["title"] = full_title
        game["info"]["version"] = game_version
        game["info"]["datecode"] = dll.stem[5:].strip("-")
        game["info"]["file"] = "bm2dx.dll"
        game["info"]["md5"] = hashlib.md5(h).hexdigest()
        game["info"]["sha1"] = hashlib.sha1(h).hexdigest()
        game["data"] = {}

        title = "Standard/Menu Timer Freeze"
        find_pattern(rb"\x83.\x50\x01\x7E")
        find_pattern("0F 84", pos())
        patch(title, "90 E9", toggle_in_game=True)

        title = "Premium Free Timer Freeze"
        find_pattern(rb"\x0A\x85\xC0\x74.\xB9\x01\x00\x00\x00\xFF\x15")
        find_pattern_backwards("85 C0 75", pos(), -1)
        patch(title, "EB", toggle_in_game=True)

        title = "Hide Time Limit Display on Results Screen"
        find_pattern(
            rb"\xFF\x45\x33\xC0\xBA\x03\x00\x00\x00\x48\x8B......\xE8...\xFF\xE8"
        )
        find_pattern("0F 84", pos())
        patch(title, "90 E9", toggle_in_game=True)

        title = "Hide Background Color Banners on Song List"
        while True:
            find_pattern(str.encode("listb_").hex(), pos(), 5)
            if int(pos()) > 1000:
                patch(title, "00")
            else:
                break

        title = "Cursor Lock"
        find_pattern(rb"\x01\x00\x00\x00\xE8...\xFF\x48\x8B\xC8\xE8...\xFF")
        find_pattern("C0 74", pos(), 1)
        patch(title, "90 90", toggle_in_game=True)

        title = "Unlock All Songs and Charts"
        find_pattern(
            rb"\xC0\x74.\x44\x8B...\x48\x8B...\x48\x8B...\xE8.\x00\x00\x00..\xC0\x85\xC0\x74.\xB0\x01"
        )
        find_pattern("32 C0", pos())
        patch(title, "B0 01", toggle_in_game=True)

        title = "CS-style Song Start Delay"
        find_pattern(rb"\xC7.\x14\x00\x00\x00\x00\xEB.........\xFF")
        find_pattern_backwards("7C", pos(), -1)
        patch(
            title,
            "EB",
            toggle_in_game=True,
            tooltip="Holding Start will pause the song at the beginning until you release it",
        )

        title = "Show Lightning Model Folder in LDJ"
        find_pattern(rb"\xE8..\xFF\xFF...\xFF\xFF...\xFF\xFF\xE8...\x00....\xC0\x74")
        find_pattern_backwards("C0 74", pos(), -1)
        patch(title, "90 90", tooltip="This folder is normally exclusive to TDJ mode")

        title = "Bypass Lightning Monitor Error"
        find_pattern(rb"\x8C\x00\x00\x00\x39.\x88\x00\x00\x00\x0F\x8C")
        find_pattern("C0 0F 84", pos(), 1)
        patch(title, "90 E9")

        title = "Shim Lightning Mode IO (for spicetools)"
        # find_pattern(rb'\x48.\x44\x24\x60\x48\xC7\x40\x08?\x00\x00\x00')
        find_pattern(
            "48 83 C4 48 C3 CC CC CC CC CC 48 89 4C 24 08 B0 01 C3 CC CC CC CC CC CC CC CC 48 89 4C 24 08 48 83 EC 58 48 C7 44 24 38 FE FF FF FF C7 44 24 20",
            0x500000,
            26,
        )
        find_pattern_backwards("CC CC", pos())
        tdj = pe.get_rva_from_offset(pos())
        find_pattern(rb"\x0F\xB6.\x0E.........\xE8...\xFF", pos())
        find_pattern("01 74", pos(), 1)
        patch(title, "EB")
        find_pattern(rb"\x48\x8B......\x48..\x08\x48...\xD8.\x00", pos())
        find_pattern("00 00 E8", pos(), 3)
        patch(title, struct.pack("<i", tdj - pe.get_rva_from_offset(pos()) - 4))

        title = "Lightning Mode Camera Crash Fix (for spicetools) / Force LDJ Software Video Decoder for All Boot Modes"
        find_pattern(rb"\x00\x00\x48\x8B...........\x78\x00\x74\x0A\xC7")
        find_pattern("C0 0F 85", pos(), 1)
        patch(title, "90" * 6)

        title = "Force Custom Timing and Adapter Mode in LDJ (Experimental)"
        find_pattern(rb"\x24.\xE8...\x00............\x08........\x01\x75")
        find_pattern("01 75", pos(), 1)
        patch(title, "EB", tooltip="Enable this if the patch below is not default")
        find_pattern(rb"\x3C\x00\x00\x00\x48..\x24.\x83", pos())
        find_pattern("01 75", pos(), 1)
        patch(title, "EB")

        fps = (60, 120, 144, 165, 240, 360)
        title = "Choose Custom LDJ Timing/Adapter FPS"
        find_pattern("40 3C 00 00 00 8B", 0, 1)
        for val in fps:
            patch_union(title, f"{val} FPS", struct.pack("<H", val))

        title = "Choose Custom TDJ Timing/Adapter FPS"
        find_pattern("C7 44 24 48 78 00 00 00", pos())
        for val in fps:
            packed = struct.pack("<I", val).hex()
            patch_union(
                title,
                f"{val} FPS",
                f"C7 44 24 48 {packed} 8B 44 24 30 89 84 24 0C 01 00 00 48 8B 44 24 44 48 89 84 24 10 01 00 00 C7 44 24 34 04 00 00 00 C7 44 24 4C 01 00 00 00 C7 44 24 50 {packed}",
            )

        title = "Choose Fullscreen Monitor Check FPS Target"
        find_pattern("98 0B 00 00 3C 00 00 00 C7", 0, 4)
        for val in fps:
            patch_union(
                title,
                f"{val} FPS",
                struct.pack("<H", val),
                tooltip="Match with the two patches above if >120",
            )

        title = "Skip Monitor Check"
        find_pattern(rb"\x8C\x00\x00\x00\x39.\x88\x00\x00\x00\x0F\x8C", 0, 11)
        patch(title, "8D")

        title = "Choose Skip Monitor Check FPS"
        find_pattern(rb"\x44..\x8B.\x48\x0B\x00\x00..\x01\x00\x00")
        find_pattern_backwards("CC CC", pos())
        patch_union(title, "Default", mm.read(27), adjust=-27)
        for val in fps:
            patch_union(
                title,
                f"{val}.0000 FPS",
                f"48 B8 {struct.pack('<d', val).hex()} 66 48 0F 6E C0 F2 0F 58 C8 C3 CC CC CC CC CC CC CC",
            )

        title = "Monitor Adjust Offset"
        find_pattern("01 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00", 0, 4)
        patch_union(title, "size", 4, patch_type="number")
        patch_union(title, "min", -1000, patch_type="number")
        patch_union(title, "max", 1000, patch_type="number")
        # struct.pack('<i', -10).hex())

        title = "Skip CAMERA DEVICE ERROR Prompt"
        find_pattern(rb"\x30\x01\xE9..\x00\x00\xBA\x05\x00\x00\x00")
        find_pattern("C0 0F 84", pos(), 2)
        patch(title, "81")

        ###    title("Unscramble Touch Screen Keypad in TDJ")
        ###    find_pattern("4D 03 C8 49 F7 F1 89", 0x400000)
        ###    patch("90" * 6)

        title = "Force Max V-Discs"
        find_pattern(rb"\x00\x00\x48...\xB0\x00\x00\x00\x00\x0F\x84", 0, 11)
        patch(title, "90 E9", tooltip="Infinite leggendaria plays in pfree")

        title = "Enable 1P Premium Free"
        find_pattern(rb"\x45\x33\xC9\x4C\x8D.\x24....\x48\x8B....\x00\x00....\xE8")
        find_pattern("C0 75", pos(), 1)
        patch(title, "EB", toggle_in_game=True)

        title = "Enable 2P Premium Free"
        find_pattern("74 30 E8", pos())
        patch(title, "90 90", toggle_in_game=True)
        find_pattern("85 C0 74 0A", pos(), 2)
        patch(title, "90 90")

        ###    title("Enable ARENA")
        ###    start()
        ###    find_pattern("83 F8 01 75", pos(), 3)
        ###    patch_multi("90 90")
        ###    find_pattern("FF 84 C0 74", pos(), 3)
        ###    patch_multi("90 90")
        ###    end()
        ###
        ###    title("Enable BPL BATTLE")
        ###    find_pattern("74", pos())
        ###    patch("90 90")

        title = "All Notes Preview 12s"
        find_pattern("0C 00 00 00 EB 08 C7 44 24 44 05 00 00 00 8B 44", 0, 10)
        patch(title, "0C", toggle_in_game=True)
        find_pattern("05 00 00 00", pos())
        patch(title, "0C")

        title = "Dark Mode"
        find_pattern(rb"\x85\xC0\x0F\x84.\x01\x00\x00\xB8\x08\x00\x00\x00")
        patch(title, "90 90", toggle_in_game=True)

        title = "Hide Measure Lines"
        find_pattern("84 24 C0 00 00 00 83 38 04 75 76", 0x250000, 9)
        patch(title, "EB", toggle_in_game=True)

        title = "WASAPI Shared Mode (with 44100Hz)"
        find_pattern("E6 01 45 33", 0x90000, 1)
        patch(title, "00")

        title = "SSE4.2 Fix"
        find_pattern(
            "24 24 F3 45 0F B8 D3 41 8B C2 66 44 89 54 24 22 0F AF C2 66", 0x90000, 2
        )
        patch(title, "90" * 3)

        ###    title("Skip Decide Screen")
        ###    find_pattern("8B F8 E8 6B 00 00 00 48", 0x90000, 2)
        ###    patch("90" * 5)

        title = "Quick Retry"
        find_pattern(
            "48 89 4C 24 08 48 83 EC 38 C6 44 24 20 00 8B 4C 24 48 E8", 0x200000, 13
        )
        patch(title, "01", toggle_in_game=True)
        find_pattern("85 C0 74", pos(), 2)
        patch(title, "EB", toggle_in_game=True)

        title = "Disable News Sound"
        find_pattern(
            "73 79 73 73 64 5F 6E 65 77 73 5F 63 75 74 69 6E 5F 73 65", 0x600000
        )
        patch(
            title,
            "73 79 73 73 64 5F 64 75 6D 6D 79 00 00 00 00 00 00 00 00",
            tooltip="Disables the sound played when news banners appear.",
        )

        title = "Increase Game Volume"
        find_pattern("70 FF 94 24 00 01 00 00 90 48 83", 0x400000, 1)
        patch(
            title,
            "90" * 7,
            tooltip="Ignore the in-game volume settings and use the maximum possible volume level. Especially helpful for TDJ which tends to be very quiet.",
        )

        try:
            find_pattern(
                "41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 2D",
                0x200000,
            )
            title = "QWERTY Keyboard Layout for Song Search"
            patch(
                title,
                "51 57 45 52 54 59 55 49 4F 50 41 53 44 46 47 48 4A 4B 4C 2D 5A 58 43 56 42 4E 4D",
                tooltip="Changes the touch keyboard layout from alphabetical to QWERTY in song and artist search menu (TDJ only)",
            )
        except ValueError:
            pass

        title = "Hide All Bottom Text"
        find_pattern(
            "43 52 45 44 49 54 3A 20 25 64 20 43 4F 49 4E 3A 20 25 64 20 2F 20 25 64 00 00 00 00 00 00 00 00 43 52 45 44 49 54 3A 20 25 64 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 4E 4F 54 20 41 56 41 49 4C 41 42 4C 45 00 00 00 45 58 54 52 41 20 50 41 53 45 4C 49 3A 20 25 64 00 00 00 00 00 00 00 00 45 58 54 52 41 20 50 41 53 45 4C 49 3A 20 25 73 00 00 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 25 64 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 25 73 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 2A 2A 2A 2A 2A 2A 00 00 20 2B 20 25 64 00 00 00 20 2B 20 25 73 00 00 00 50 41 53 45 4C 49 3A 20 4E 4F 20 41 43 43 4F 55 4E 54 00 00 00 00 00 00 49 4E 53 45 52 54 20 43 4F 49 4E 5B 53 5D 00 00 50 41 53 45 4C 49 3A 20 2A 2A 2A 2A 2A 2A 20 2B 20 30 30 30 30 30 00 00 43 52 45 44 49 54 3A 20 39 39 20 43 4F 49 4E 3A 20 39 39 20 2F 20 31 30",
            0x600000,
        )
        patch(title, "00" * 272, toggle_in_game=True, tooltip="Except for FREE PLAY")

        # TICKER OFFSET
        # find_pattern("41 B8 00 02 00 00 48 8D 0D", 0x300000, 9)
        find_pattern("41 B8 00 02 00 00 48 8B 54 24 30 48 8D 0D", 0x300000, 14)
        relative = pe.get_rva_from_offset(pos())
        offset = struct.unpack("<i", mm.read(4))[0]
        absolute_ticker_offset = relative + offset

        # HIDDEN OFFSET
        find_pattern("00 00 00 20 20 00 00", 0x700000, 3)
        hidden = pe.get_rva_from_offset(pos())

        title = "Reroute FREE PLAY Text"
        find_pattern("8B 44 24 50 89 44 24 54 48 8D 05", 0x200000, 11)
        patch_union(title, "Default", mm.read(4), toggle_in_game=True, adjust=-4)
        patch_union(
            title,
            "Song Title/Ticker information",
            struct.pack(
                "<i", absolute_ticker_offset - pe.get_rva_from_offset(pos()) + 4
            ),
            True,
        )
        find_pattern("8B 44 24 50 89 44 24 54 48 8D 05", 0x200000, 11)
        patch_union(
            title,
            "Hide",
            struct.pack("<i", hidden - pe.get_rva_from_offset(pos()) - 4),
            toggle_in_game=True,
        )

        title = "Reroute PASELI: ****** Text To Song Title/Ticker Information"
        find_pattern("B1 00 EB 1A 4C 8D 05", 0x200000, 7)
        patch(
            title,
            struct.pack("<i", absolute_ticker_offset - pe.get_rva_from_offset(pos())),
            toggle_in_game=True,
        )

        title = "Debug Mode"
        find_pattern(
            "C3 32 C0 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC 89", 0x300000, 1
        )
        patch(
            title,
            "B0 01",
            tooltip="While in game, press F1 to enable menu. (Disables Profile/Score saving)",
        )

        title = "Increase 'All Factory Settings' Buffer"
        find_pattern("FE FF FF FF B9 58 01 00 00 E8", 0x300000, 5)
        patch(
            title,
            "22 61 14 00",
            tooltip="Enable this if the option below is not default",
        )
        find_pattern("48 8B EA BA 58 01 00 00", 0x600000, 4)
        patch(title, "22 61 14 00")

        # AfpViewerScene
        find_pattern("60 48 05 90 10 10 00 41 B8 00 00 04 00 33 D2", 0x250000)
        find_pattern_backwards("CC CC", pos())
        afp = pe.get_rva_from_offset(pos())

        # QproViewerScene
        find_pattern("48 05 00 01 00 00 41 B8 14 00", 0x250000)
        find_pattern_backwards("CC CC", pos())
        qpro = pe.get_rva_from_offset(pos())

        # SoundViewerScene
        find_pattern(
            "58 48 8B F8 48 8B F1 B9 10 00 00 00 F3 A4 45 33 C9 4C 8D 44 24 70",
            0x250000,
        )
        find_pattern_backwards("CC CC", pos())
        viewer = pe.get_rva_from_offset(pos())

        title = "Reroute 'All Factory Settings' Test Menu"
        find_pattern("FE FF FF FF B9 58 01 00 00 E8", 0x350000, 10)
        find_pattern("E8", pos(), 1)
        patch_union(title, "Default", mm.read(4), toggle_in_game=True, adjust=-4)
        here = pe.get_rva_from_offset(pos())
        patch_union(title, "AfpViewerScene", struct.pack("<i", afp - here))
        patch_union(title, "QproViewerScene", struct.pack("<i", qpro - here))
        patch_union(title, "SoundViewerScene", struct.pack("<i", viewer - here))

        # CustomizeViewerScene
        find_pattern("00 00 41 B8 98 00 00 00 33 D2 48 8B C8 E8", 0x250000)
        find_pattern_backwards("CC CC", pos())
        custom = pe.get_rva_from_offset(pos())

        # SoundRankingViewerScene
        find_pattern("0F 57 C0 F3 0F 11 80 44 01 00 00", 0x250000)
        find_pattern_backwards("CC CC", pos())
        ranking = pe.get_rva_from_offset(pos())

        # SystemSoundViewerScene
        # find_pattern("C7 80 F8 00 00 00 90 01 00 00", 0x250000)
        find_pattern(rb"\x24\x70\xC7\x80\xF8\x00\x00\x00..\x00\x00")
        find_pattern_backwards("CC CC", pos())
        system = pe.get_rva_from_offset(pos())

        title = "Reroute 'Ecomode Options' Test Menu"
        find_pattern("C3 CC 48 83 EC 48 48 C7 44 24 38 FE FF FF FF B9", 0x350000)
        find_pattern("20 E8", pos(), 2)
        patch_union(title, "Default", mm.read(4), toggle_in_game=True, adjust=-4)
        here = pe.get_rva_from_offset(pos())
        patch_union(title, "CustomizeViewerScene", struct.pack("<i", custom - here))
        patch_union(title, "SoundRankingViewerScene", struct.pack("<i", ranking - here))
        patch_union(title, "SystemSoundViewerScene", struct.pack("<i", system - here))

        title = "Auto Play"
        find_pattern(rb"\x00\xB9\x3A\x00\x00\x00\xE8...\xFF\xE8...\xFF")
        find_pattern("C6 80", pos(), 6)
        patch(title, "01", toggle_in_game=True)

        title = "Omnimix"
        find_pattern("44 24 40 85 C0 0F 84 F8 00 00 00", 0x800000, 5)
        patch(title, "90 E9 48")
        find_pattern("C6 40 05 41", pos(), 3)
        patch(title, "58")
        find_pattern("2C 08 07 00 00 7F 0A", 0x800000, 5)
        patch(title, "90 90")
        find_pattern("00 00 7E", pos(), 2)
        patch(title, "EB")
        find_pattern(str.encode("mdata.ifs"), 0x600000, 4)
        patch(title, str.encode("o"))
        find_pattern(str.encode("music_data.bin"), 0x600000, 6)
        patch(title, str.encode("omni"))
        find_pattern(str.encode("music_title_yomi.xml"), 0x600000, 12)
        patch(title, str.encode("omni"))
        find_pattern(str.encode("music_artist_yomi.xml"), 0x600000, 13)
        patch(title, str.encode("omni"))
        find_pattern(str.encode("video_music_list.xml"), 0x600000, 12)
        patch(title, str.encode("omni"))
        find_pattern(
            "41 B9 04 00 00 00 4C 8B 44 24 70 BA 0D 00 00 00 48 8B 4C 24 50 E8",
            0x600000,
        )
        find_pattern_backwards("0F B6 C0 85 C0", pos(), -10)
        patch(title, "B8 01 00 00 00")

        with open(dll.stem + ".json", "w") as outfile:
            json.dump(game, outfile, indent=2)
            print(dll, "->", dll.stem + ".json")

if Path("json_to_bemanipatcher.py").is_file() and game:
    from json_to_bemanipatcher import json_to_bemanipatcher

    json_to_bemanipatcher("bm2dx", "iidx")

if game:
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)
    print()
