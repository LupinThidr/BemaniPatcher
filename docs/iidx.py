import mmap
import pefile
import struct

def title(name, tooltip = None):
    print("{")
    print(f'    name: "{name}",')
    if tooltip is not None:
        print(f'    tooltip: "{tooltip}",')

def find_pattern(pattern, start = 0, adjust = 0):
    return mm.seek(mm.find(tobytes(pattern), start) + adjust)

def find_pattern_backwards(pattern, start = 0, adjust = 0):
    pattern = pattern.replace(" ", "")
    pattern_len = int(len(pattern) / 2)
    while mm.read(pattern_len) != tobytes(pattern):
        mm.seek(pos() - pattern_len - 1)
    if adjust != 0:
        mm.seek(pos() + adjust)

def patch_if_match(off, on):
    off = off.replace(" ", "")
    off_len = int(len(off) / 2)
    if mm.read(off_len).hex().upper() == off.upper():
        mm.seek(pos() - off_len)
        patch(on)
    else:
        mm.seek(pos() - off_len)

def patch(on):
    offset = pos()
    try:
        on = on.replace(" ", "")
    except TypeError:
        on = on.hex()
    off = mm.read(int(len(on) / 2))
    on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(off.hex()), 2)]))
    off_formatted = '[%s]' % ', '.join(map(str, ["0x"+(off.hex().upper()[i:i+2]) for i in range(0, len(off.hex()), 2)]))
    print(f"    patches: [{{ offset: 0x{hex(offset)[2:].upper()}, off: {off_formatted}, on: {on_formatted} }}],")
    print("},")

def patch_multi(on):
    offset = pos()
    try:
        on = on.replace(" ", "")
    except TypeError:
        on = on.hex()
    off = mm.read(int(len(on) / 2))
    on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(off.hex()), 2)]))
    off_formatted = '[%s]' % ', '.join(map(str, ["0x"+(off.hex().upper()[i:i+2]) for i in range(0, len(off.hex()), 2)]))
    print(f"        {{ offset: 0x{hex(offset)[2:].upper()}, off: {off_formatted}, on: {on_formatted} }},")

def start():
    print(f"    patches: [")

def end():
    print("    ]")
    print("},")

def union(on, name, tooltip = None):
    try:
        on = on.replace(" ", "")
        on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(on), 2)]))
    except TypeError:
        on = on.hex()
        on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(on), 2)]))
    print("        {")
    print(f'            name : "{name}",')
    if tooltip is not None:
        print(f'            tooltip : "{tooltip}",')
    print(f"            patch : {on_formatted},")
    print("        },")

def tobytes(val):
    try:
        return bytes.fromhex(val.replace(" ", ""))
    except TypeError:
        val = val.hex()
        return bytes.fromhex(val.replace(" ", ""))

def pos():
    return mm.tell()

with open('bm2dx.dll', 'r+b') as bm2dx:
    mm = mmap.mmap(bm2dx.fileno(), 0)
    pe = pefile.PE('bm2dx.dll', fast_load=True)

    title("Standard/Menu Timer Freeze")
    find_pattern("FF FF 43 58 83 7B 50 01 7E 03 FF 43 5C 48 8D 4B 70 E8", 0x40000, 32)
    patch_if_match("0F 84", "90 E9")
    patch_if_match("74", "EB")

    title("Premium Free Timer Freeze")
    find_pattern("40 53 48 83 EC 20 83 79 14 00 48 8B D9 7E", 0x300000, 13)
    patch("EB")

    title("Hide Time Limit Display on Results Screen")
    find_pattern("FF 33 ED 84 C0 0F 84", 0x350000, 3)
    patch("90 90")

    title("Hide Background Color Banners on Song List")
    start()
    while True:
        find_pattern(str.encode('listb_'), pos(), 5)
        if int(pos()) > 1000:
            patch_multi("00")
        else:
            break
    end()

    title("Cursor Lock")
    find_pattern("08 8B D8 E8", 0x250000)
    find_pattern("84 C0 74", pos(), 2)
    patch("90 90")

    title("Unlock All Songs and Charts")
    find_pattern("32 C0 48 8B 74 24 48 48 83 C4 30 5F C3 CC CC CC CC CC CC CC", 0x250000)
    find_pattern("32 C0 48 8B 74 24 48 48 83 C4 30 5F C3 CC CC CC CC CC CC CC", pos() + 1)
    patch("B0 01")

    title("CS-style Song Start Delay", "Holding Start will pause the song at the beginning until you release it")
    try:
        find_pattern("48 8B 01 48 8B D9 8B", 0x500000)
        find_pattern("7D", pos())
        patch("90 90")
    except ValueError:
        try:
            find_pattern("48 83 EC 20 48 8B 11", 0x350000)
            find_pattern("7D", pos())
            patch("90 90")
        except ValueError:
            pass

    title("Show Lightning Model Folder in LDJ", "This folder is normally exclusive to TDJ mode")
    find_pattern("44 39 60 08 75", 0x300000, 4)
    patch("90 90")

    title("Bypass Lightning Monitor Error")
    find_pattern("0F 85 DF 00 00 00 F3", 0x350000)
    patch("90 E9")

    title("Shim Lightning Mode IO (for spicetools)")
    start()
    find_pattern("B0 01 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC 48 89 4C 24 08", 0x500000, 16)
    tdj = pe.get_rva_from_offset(pos())
    find_pattern("00 48 C7 45 20 FE FF FF FF 48 89", pos())
    find_pattern("0F 84", pos())
    patch_multi("90 E9")
    find_pattern("C1 43 0C 83 F8 01 75 0B 48 8B 4D 98 48 8B 01", pos())
    find_pattern("00 00 00 E8", pos(), 4)
    patch_multi(struct.pack('<i', tdj - pe.get_rva_from_offset(pos()) - 4))
    end()

    title("Lightning Mode Camera Crash Fix (for spicetools)")
    find_pattern("FF 0F 84 8D 00 00 00", 0x300000, 1)
    patch("90" * 6)

    title("Force LDJ Software Video Decoder for All Boot Modes")
    find_pattern("FF 0F 84 8D 00 00 00", 0x350000, -3)
    patch_if_match("02", "05")

    title("Force Custom Timing and Adapter Mode in LDJ (Experimental)", "Enable this if the patch below is not default")
    start()
    find_pattern("0F 5B F6 75 0C", 0x250000, 3)
    patch_multi("EB")
    find_pattern("B8 3C 00 00 00 74 03", 0x250000, 5)
    patch_multi("90 90")
    end()

    fps = (60, 120, 144, 165, 240, 360)
    print("{")
    print('    type : "union",')
    print('    name : "Choose Custom LDJ Timing/Adapter FPS",')
    find_pattern("DB 3C 00 00 00 C7", 0x350000, 1)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    for val in fps:
        union(struct.pack('<H', val), f"{val} FPS", "Default" if val == 60 else "Lightning" if val == 120 else None)
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Choose Custom TDJ Timing/Adapter FPS",')
    find_pattern("C7 45 DB 78 00 00 00", 0x350000)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    for val in fps:
        packed = struct.pack('<I', val).hex()
        union(f"C7 45 DB {packed} C7 45 0B 02 00 00 00 48 8B 45 D7 48 89 45 0F C7 45 D7 01 00 00 00 C7 45 DB{packed}", f"{val} FPS", "Default" if val == 120 else None)
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Choose Fullscreen Monitor Check FPS Target",')
    print('    tooltip : "Match with the two patches above if >120",')
    find_pattern("78 00 00 00 C7 45", 0x350000)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    for val in fps[1:]:
        union(struct.pack('<H', val), f"{val} FPS", "Default" if val == 120 else None)
    end()

    title("Skip Monitor Check")
    find_pattern("39 87 88 00 00 00 0F 8C", 0x350000, 7)
    patch("8D")

    print("{")
    print('    type : "union",')
    print('    name : "Choose Skip Monitor Check FPS",')
    find_pattern("44 8B 91 48 0B 00 00 44 8B CA 4C 8B D9 41 81 C2 67 01 00 00 B8 B7 60 0B B6 0F 57", 0x350000)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(27), "Default")
    for val in fps[1:]:
        union(f"48 B8 {struct.pack('<d', val).hex()} 66 48 0F 6E C0 F2 0F 58 C8 C3 CC CC CC CC CC CC CC", f"{val}.0000 FPS")
    end()

    print("{")
    print('    type : "number",')
    print('    name : "Monitor Adjust Offset",')
    find_pattern("80 01 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 0x700000, 5)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    size : 4,")
    print("    min : -1000,")
    print("    max : 1000,")
    print("},")

    title("Skip CAMERA DEVICE ERROR Prompt", "Prevents the CAMERA DEVICE ERROR message from popping up on boot")
    find_pattern("0F 84 AA 00 00 00 B9 3C", 0x350000, 1)
    patch("81")

    title("Unscramble Touch Screen Keypad in TDJ")
    find_pattern("4D 03 C8 49 F7 F1 89", 0x400000)
    patch("90" * 6)

    title("Force Max V-Discs", "Infinite leggendaria plays in pfree")
    find_pattern("CC 4D 85 C0 0F 84 72 01 00 00", 0x250000, 4)
    patch("90 E9")

    title("Enable 1P Premium Free")
    find_pattern("48 89 44 24 50 33 FF", 0x200000)
    find_pattern("FF 84 C0 75 14 E8", pos(), 3)
    patch("EB")

    title("Enable 2P Premium Free")
    start()
    find_pattern("BA 01 00 00 00", pos())
    find_pattern_backwards("84 C0", pos())
    patch_multi("90 90")
    find_pattern("74", pos())
    patch_multi("90 90")
    end()

    title("Enable ARENA")
    start()
    find_pattern("83 F8 01 75", pos(), 3)
    patch_multi("90 90")
    find_pattern("FF 84 C0 74", pos(), 3)
    patch_multi("90 90")
    end()

    title("Enable BPL BATTLE")
    find_pattern("74", pos())
    patch("90 90")

    title("All Notes Preview 12s")
    start()
    find_pattern("05 00 00 00 84 C0", 0x250000)
    patch_multi("0C")
    find_pattern("05 00 00 00 84 C0", pos())
    patch_multi("0C")
    end()

    title("Dark Mode")
    find_pattern("10 48 85 C9 74 10", 0x300000)
    find_pattern_backwards("84 C0", pos(), -2)
    patch("90 90")

    title("Hide Measure Lines")
    find_pattern("83 F8 04 75 37", 0x250000, 3)
    patch("EB")

    title("WASAPI Shared Mode (with 44100Hz)")
    find_pattern("E6 01 45 33", 0x90000, 1)
    patch("00")

    title("SSE4.2 Fix")
    find_pattern("24 24 F3 45 0F B8 D3 41 8B C2 66 44 89 54 24 22 0F AF C2 66", 0x90000, 2)
    patch("90" * 3)

    title("Skip Decide Screen")
    find_pattern("8B F8 E8 6B 00 00 00 48", 0x90000, 2)
    patch("90" * 5)

    title("Quick Retry")
    find_pattern("32 C0 48 83 C4 20 5B C3 CC CC CC CC CC CC CC CC CC 0F", 0x200000)
    patch("B0 01")

    title("Disable News Sound", "Disables the sound played when news banners appear.")
    find_pattern("73 79 73 73 64 5F 6E 65 77 73 5F 63 75 74 69 6E 5F 73 65", 0x600000)
    patch("73 79 73 73 64 5F 64 75 6D 6D 79 00 00 00 00 00 00 00 00")

    title("Increase Game Volume",
    "Ignore the in-game volume settings and use the maximum possible volume level. Especially helpful for TDJ which tends to be very quiet.")
    find_pattern("D7 FF 90 98 00 00 00 90", 0x400000, 1)
    patch("90" * 6)

    try:
        find_pattern("41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 2D", 0x200000)
        title("QWERTY Keyboard Layout for Song Search", "Changes the touch keyboard layout from alphabetical to QWERTY in song and artist search menu (TDJ only)")
        patch("51 57 45 52 54 59 55 49 4F 50 41 53 44 46 47 48 4A 4B 4C 2D 5A 58 43 56 42 4E 4D")
    except ValueError:
        pass

    title("Hide All Bottom Text", "Except for FREE PLAY")
    find_pattern("43 52 45 44 49 54 3A 20 25 64 20 43 4F 49 4E 3A 20 25 64 20 2F 20 25 64 00 00 00 00 00 00 00 00 43 52 45 44 49 54 3A 20 25 64 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 4E 4F 54 20 41 56 41 49 4C 41 42 4C 45 00 00 00 45 58 54 52 41 20 50 41 53 45 4C 49 3A 20 25 64 00 00 00 00 00 00 00 00 45 58 54 52 41 20 50 41 53 45 4C 49 3A 20 25 73 00 00 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 25 64 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 25 73 00 00 00 00 00 00 50 41 53 45 4C 49 3A 20 2A 2A 2A 2A 2A 2A 00 00 20 2B 20 25 64 00 00 00 20 2B 20 25 73 00 00 00 50 41 53 45 4C 49 3A 20 4E 4F 20 41 43 43 4F 55 4E 54 00 00 00 00 00 00 49 4E 53 45 52 54 20 43 4F 49 4E 5B 53 5D 00 00 50 41 53 45 4C 49 3A 20 2A 2A 2A 2A 2A 2A 20 2B 20 30 30 30 30 30 00 00 43 52 45 44 49 54 3A 20 39 39 20 43 4F 49 4E 3A 20 39 39 20 2F 20 31 30", 0x600000)
    patch("00" * 272)

    # TICKER OFFSET
    find_pattern("41 B8 00 02 00 00 48 8D 0D", 0x300000, 9)
    relative = pe.get_rva_from_offset(pos())
    offset = struct.unpack('<i', mm.read(4))[0]
    absolute_ticker_offset = relative + offset

    # HIDDEN OFFSET
    find_pattern("00 00 00 20 20 00 00", 0x700000, 3)
    hidden = pe.get_rva_from_offset(pos())

    print("{")
    print('    type : "union",')
    print('    name : "Reroute FREE PLAY Text",')
    find_pattern("44 0F 45 C8 48 8D 05", 0x200000, 7)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(4), "FREE PLAY", "Default")
    union(struct.pack('<i', absolute_ticker_offset - pe.get_rva_from_offset(pos()) + 4), "Song Title/Ticker information")

    find_pattern("44 0F 45 C8 48 8D 05", 0x200000, 7)
    union(struct.pack('<i', hidden - pe.get_rva_from_offset(pos()) - 4), "Hide")
    end()

    title("Reroute PASELI: ****** Text To Song Title/Ticker Information")
    find_pattern("00 EB 17 4C 8D 05", 0x200000, 6)
    patch(struct.pack('<i', absolute_ticker_offset - pe.get_rva_from_offset(pos())))

    title("Debug Mode", "While in game, press F1 to enable menu.  (Disables Profile/Score saving)")
    find_pattern("C3 CC CC CC 32 C0 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC", 0x300000, 4)
    patch("B001")

    title("Increase 'All Factory Settings' Buffer", "Enable this if the option below is not default")
    start()
    find_pattern("FE FF FF FF B9 48 01 00 00 E8", 0x300000, 5)
    patch_multi("22 61 14 00")
    find_pattern("48 8B EA BA 48 01 00 00 48", 0x600000, 4)
    patch_multi("22 61 14 00")
    end()

    #AfpViewerScene
    find_pattern("48 8D 8B 90 10 10 00 33", 0x250000)
    find_pattern_backwards("CC CC", pos())
    afp = pe.get_rva_from_offset(pos())

    #QproViewerScene
    find_pattern("01 00 33 C0 48 89 83", 0x250000)
    find_pattern_backwards("CC CC", pos())
    qpro = pe.get_rva_from_offset(pos())

    #SoundViewerScene
    find_pattern("48 89 5C 24 68 4C 89 33", 0x250000)
    find_pattern_backwards("CC CC", pos())
    viewer = pe.get_rva_from_offset(pos())

    #TestICCardQCScene
    find_pattern("FF 48 8D 9F F8 00", 0x250000)
    find_pattern_backwards("CC CC", pos())
    qc = pe.get_rva_from_offset(pos())

    print("{")
    print('    type : "union",')
    print("    name : \"Reroute 'All Factory Settings' Test Menu\",")
    find_pattern("FE FF FF FF B9 48 01 00 00 E8", 0x350000, 10)
    find_pattern("E8", pos(), 1)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(4), "TestAllFactorySettingsScene", "Default")
    here = pe.get_rva_from_offset(pos())
    union(struct.pack('<i', afp - here), "AfpViewerScene")
    union(struct.pack('<i', qpro - here), "QproViewerScene")
    union(struct.pack('<i', viewer - here), "SoundViewerScene")
    union(struct.pack('<i', qc - here), "TestICCardQCScene")
    end()

    #CustomizeViewerScene
    find_pattern("00 33 D2 41 B8 98 00", 0x250000)
    find_pattern_backwards("CC CC", pos())
    custom = pe.get_rva_from_offset(pos())

    #SoundRankingViewerScene
    find_pattern("00 48 89 5C 24 68 48 89 2B", 0x250000)
    find_pattern_backwards("CC CC", pos())
    ranking = pe.get_rva_from_offset(pos())

    #SystemSoundViewerScene
    find_pattern("48 89 44 24 30 89 74 24 38 0F 28 44 24 30 66 0F 7F 44 24 30 45 33 C9 4C 8D 44 24 30 48 8B D7 48 8D 8F 88 00 00 00 E8", 0x250000)
    find_pattern_backwards("CC CC", pos())
    system = pe.get_rva_from_offset(pos())

    print("{")
    print('    type : "union",')
    print("    name : \"Reroute 'I/O Check -> Camera Check -> 2D Code check' Test Menu\",")
    find_pattern("C3 CC CC CC CC CC CC CC CC CC CC 48 83 EC 38 48 C7 44 24 20 FE FF FF FF B9 D0 01 00 00 E8", 0x350000)
    find_pattern("C8 E8", pos(), 2)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(4), "TestIOCheckQrCheckScene", "Default")
    here = pe.get_rva_from_offset(pos())
    union(struct.pack('<i', custom - here), "CustomizeViewerScene")
    union(struct.pack('<i', ranking - here), "SoundRankingViewerScene")
    union(struct.pack('<i', system - here), "SystemSoundViewerScene")
    end()

    title("Auto Play")
    find_pattern("FD FF 33 C9 C6 80", 0x200000, 10)
    patch_if_match("00", "01")

    title("Omnimix")
    start()
    find_pattern("C3 CC CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 0F B6 D9 E8 22 01 00 00 84 C0 74 14 0F B6 CB E8 16 00 00 00 84 C0 74 08 B0 01 48 83 C4 20 5B C3 32 C0 48 83 C4 20 5B C3", 0x300000)
    patch_multi("C6 47 05 58 C3")
    find_pattern("66 39 48 08 7F", 0x300000, 4)
    patch_multi("90 90")
    find_pattern(str.encode('mdata.ifs'), 0x600000, 4)
    patch_multi(str.encode('o'))
    find_pattern(str.encode('music_data.bin'), 0x600000, 6)
    patch_multi(str.encode('omni'))
    find_pattern(str.encode('music_title_yomi.xml'), 0x600000, 12)
    patch_multi(str.encode('omni'))
    find_pattern(str.encode('music_artist_yomi.xml'), 0x600000, 13)
    patch_multi(str.encode('omni'))
    find_pattern(str.encode('video_music_list.xml'), 0x600000, 12)
    patch_multi(str.encode('omni'))
    find_pattern("7C ED 32 C0 C3", 0x200000, 2)
    patch_multi("B0 01")
    end()
