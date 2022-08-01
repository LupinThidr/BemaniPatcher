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

def patch(on, single = True):
    offset = pos()
    on = on.replace(" ", "")
    off = mm.read(int(len(on) / 2))
    on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(off.hex()), 2)]))
    off_formatted = '[%s]' % ', '.join(map(str, ["0x"+(off.hex().upper()[i:i+2]) for i in range(0, len(off.hex()), 2)]))
    if single:
        print(f"    patches: [{{ offset: 0x{hex(offset)[2:].upper()}, off: {off_formatted}, on: {on_formatted} }}],")
        print("},")
    else:
        print(f"        {{ offset: 0x{hex(offset)[2:].upper()}, off: {off_formatted}, on: {on_formatted} }},")

def start():
    print(f"    patches: [")

def end():
    print("    ]")
    print("},")

def union(on, name, tooltip = None):
    on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(on), 2)]))
    print("        {")
    print(f'            name : "{name}",')
    if tooltip is not None:
        print(f'            tooltip : "{tooltip}",')
    print(f"            patch : {on_formatted},")
    print("        },")

def tobytes(val):
    return bytes.fromhex(val.replace(" ", ""))

def pos():
    return mm.tell()

with open('gamemdx.dll', 'r+b') as gamemdx:
    mm = mmap.mmap(gamemdx.fileno(), 0)
    pe = pefile.PE('gamemdx.dll', fast_load=True)

    title("Force enable fast/slow")
    find_pattern("8B 41 44 C3", 0x75000)
    patch("31 C0 40")

    title("Force background judgement")
    find_pattern("8B 41 40 C3", 0x75000)
    patch("31 C0")

    title("Force darkest background")
    find_pattern("75 03 33 C0 C3 8B 41 34 C3", 0x80000)
    patch("33 C0 B0 03")

    title("Opaque background for darkest background option", "This makes the darkest background option be 99% opaque, hiding the dancers and videos.")
    find_pattern("00 00 00 00 00 00 44 40", 0x100000, 12)
    patch_if_match("66 66 66", "A4 70 7D")

    title("Song Unlock")
    start()
    find_pattern("83 7D 08 01 BA 01 00 00 00 0F", 0x75000)
    find_pattern_backwards("CC CC CC CC CC CC", pos())
    find_pattern("32 C0", pos())
    patch("B0 01", False)
    find_pattern_backwards("75", pos(), -1)
    patch("90 90", False)
    try:
        find_pattern("83 C4 0C 03 FE 89 7B 34", 0x75000)
        find_pattern("0F", pos())
        patch("90 E9", False)
    except ValueError:
        pass
    try:
        find_pattern("65 76 65 6E 74 6E 6F 5F 32", pos())
        patch("62", False)
    except ValueError:
        pass
    find_pattern("65 76 65 6E 74 6E 6F 00", pos())
    patch("62", False)
    find_pattern("72 65 67 69 6F 6E 00", pos())
    patch("62", False)
    find_pattern("6C 69 6D 69 74 65 64 5F 63 68 61", pos())
    patch("62", False)
    find_pattern("6C 69 6D 69 74 65 64 00", pos())
    patch("62", False)
    end()

    title("Tutorial Skip")
    find_pattern("8B 08 83 39 01 74")
    find_pattern("84 C0 75", pos(), 2)
    patch("EB")

    title("Caution Screen Skip", "Breaks network score loading")
    find_pattern("FF FF 8B FB C7 05", 0x10000, 2)
    start_pos = pos()
    find_pattern("FF FF E8", pos())
    end_pos = pos()
    mm.seek(start_pos)
    patch(f"EB {hex(end_pos - start_pos)[2:]}")

    title("Timer Freeze")
    find_pattern("7E 05 BE 63")
    find_pattern("74", pos())
    patch("EB")

    title("Unlock options", "Extended e-amusement exclusive options such as ARROW COLOR and 0.25 speed mod")
    start()
    while True:
        find_pattern("04 00 00 00 00 E8", pos(), 1)
        if int(pos() -2) in range(0x1000, 0x75000):
            patch("01", False)
        else:
            break
    end()

    title("Hide all bottom text", "Such as EVENT MODE, PASELI, COIN, CREDIT, MAINTENANCE")
    find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
    start_pos = pos()
    find_pattern("00 4E 4F 54 20 41 56 41 49 4C 41 42 4C 45", pos())
    end_pos = pos() + 14
    hide_length = end_pos - start_pos
    find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
    patch("00" * hide_length)

    title("Autoplay")
    start()
    find_pattern("01 00 00 74 40 6A 34 E8")
    find_pattern("74", pos())
    patch("90 90", False)
    find_pattern("74", pos())
    patch("90 90", False)
    end()

    title("Force Cabinet Type 6", "Gold cab, some assets (such as menu background) may not work")
    find_pattern("77 78 ff 24 85", 0, 2)
    patch("EB 71")

    title("Force blue menu background")
    find_pattern("FF 83 F8 06 75", 0x10000, 4)
    patch("EB")

    title("Enable cabinet lights for Cabinet Type 6",
    "This enables the use of cabinet lighting for Cabinet Type 6")
    start()
    find_pattern("CC CC CC CC CC CC CC CC CC 53 E8", 0, 10)
    patch("B8 00 00", False)
    find_pattern("8B 00 83 60 04 FE E8", 0x20000, 6)
    patch("B8 00 00 00 00", False)
    find_pattern("00 80 7C 24 12 00 0F 85")
    find_pattern("E8", pos())
    patch("B8 00 00 00 00", False)
    end()

    title("Enable DDR SELECTION", "Even works in offline/local mode!")
    find_pattern("07 83 C0 04 3B C1 75 F5 3B C1 0F 95 C0 84 C0 75", 0x75000)
    find_pattern("32 C0", pos())
    patch("B0 01")

    title("Premium Free", "Breaks network score saving")
    find_pattern("B9 01 00 00 00 89 0D", 0x10000, 1)
    patch("00")

    title("Mute Announcer", "Also mutes crowd cheering and booing during gameplay")
    start()
    find_pattern("C6 40 85 C0 0F 84", 0x20000, 4)
    patch("90 E9", False)
    find_pattern(str.encode('voice.xwb').hex(), 0x100000)
    patch("62", False)
    try:
        find_pattern(str.encode('voice_n.xwb').hex(), pos())
        patch("62", False)
    except ValueError:
        pass
    end()

    title("Force DDR SELECTION theme everywhere", "Skips intro and enables the skin selected below on all songs")
    start()
    find_pattern("0F 84 F7 00 00 0057 8B FB", 0x20000)
    patch("90 E9", False)
    find_pattern("C9 83 7A 10 0D 75", 0x90000, 5)
    patch("90 90", False)
    find_pattern("FF FF FF 83 F8 04 77", pos(), 6)
    patch("90 90", False)
    find_pattern("FF 24 85", pos())
    patch("EB 11", False)
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Choose forced theme",')
    find_pattern("C3 B9 02 00 00 00 89", pos(), 2)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union("01", "1st")
    union("02", "EXTREME")
    union("03", "SuperNOVA2")
    union("04", "X2")
    union("05", "2013")
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Choose cabinet type timing offset. Set this to default for individual offsets below",')
    find_pattern("88 5D F8 E8", 0x10000, 3)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(5).hex(), "Default")
    union("B800000000", "Force CRT 945 p3io timing")
    union("B801000000", "Force LCD 945 p3io timing")
    union("B802000000", "Force LCD HM64 p4io timing")
    union("B803000000", "Force CRT ADE-6291 p3io timing")
    union("B804000000", "Force LCD ADE-6291 p3io timing")
    union("B805000000", "Force LCD ADE-6291 p4io timing")
    union("B806000000", "Force LCD ADE-6291 bio2 timing")
    end()

    print("{")
    print('    type: "number",')
    print('    name: "SSQ Offset",')
    print('    tooltip: "Bigger numbers make arrows later",')
    find_pattern("57 00 00 00", 0x10000)
    print(f"    offset: 0x{hex(pos())[2:].upper()},")
    print("    size: 4,")
    print("    min: -1000,")
    print("    max: 1000,")
    print("},")

    print("{")
    print('    type: "number",')
    print('    name: "Sound Offset",')
    print('    tooltip: "Bigger numbers make audio later",')
    find_pattern_backwards("1C 00 00 00", pos(), -4)
    print(f"    offset: 0x{hex(pos())[2:].upper()},")
    print("    size: 4,")
    print("    min: 0,")
    print("    max: 1000,")
    print("},")

    print("{")
    print('    type: "number",')
    print('    name: "Input Offset",')
    print('    tooltip: "Bigger numbers make judgement earlier",')
    find_pattern("11 00 00 00", pos())
    print(f"    offset: 0x{hex(pos())[2:].upper()},")
    print("    size: 4,")
    print("    min: 0,")
    print("    max: 1000,")
    print("},")

    print("{")
    print('    type: "number",')
    print('    name: "Render Offset",')
    print('    tooltip: "Bigger numbers make arrows later visually",')
    find_pattern("00 00 00 00", pos())
    print(f"    offset: 0x{hex(pos())[2:].upper()},")
    print("    size: 4,")
    print("    min: 0,")
    print("    max: 1000,")
    print("},")

    print("{")
    print('    type: "number",')
    print('    name: "Bomb Frame Offset",')
    print('    tooltip: "Bigger numbers delay explosion animation",')
    find_pattern_backwards("01 00 00 00", pos(), -4)
    print(f"    offset: 0x{hex(pos())[2:].upper()},")
    print("    size: 4,")
    print("    min: 0,")
    print("    max: 10,")
    print("},")

    title("Center arrows for single player")
    start()
    find_pattern("7C 24 48 39 02 75 14", 0x20000, 5)
    patch("EB", False)
    find_pattern("75 05 B8", pos())
    patch("90 90", False)
    x_axis = struct.pack('<i', 495).hex()
    # freeze_judge
    find_pattern("CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC")
    int3_absolute = pos()
    int3_rva = pe.get_rva_from_offset(int3_absolute)
    find_pattern("83 C4 0C 8D 44 24 1C", pos())
    find_pattern("83 C4 0C 8D 4C 24 1C", pos())
    freeze = pe.get_rva_from_offset(pos())
    patch(f"E9 {struct.pack('<i', int3_rva - freeze - 5).hex()} 90 90", False)
    mm.seek(int3_absolute)
    patch(f"83 C4 0C 8D 4C 24 1C 36 C7 01 {x_axis} E9 {struct.pack('<i', freeze - int3_rva - 12).hex()}", False)
    # arrow
    find_pattern("CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", int3_absolute + 20)
    int3_absolute = pos()
    int3_rva = pe.get_rva_from_offset(int3_absolute)
    for search in range(6):
        find_pattern("83 C4 0C 8D 44 24 1C", pos() + 1)
    arrow = pe.get_rva_from_offset(pos())
    patch(f"E9 {struct.pack('<i', int3_rva - arrow - 5).hex()} 90 90", False)
    mm.seek(int3_absolute)
    patch(f"83 C4 0C 8D 44 24 1C 36 C7 00 {x_axis} E9 {struct.pack('<i', arrow - int3_rva - 12).hex()}", False)
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Fullscreen FPS Target",')
    find_pattern("C7 84 24 84 00 00 00 3C 00 00 00", 0x1000, 7)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    for fps in (60, 120, 144, 165, 240, 360):
        union(struct.pack('<i', fps).hex(), f"{fps} FPS", "Default" if fps == 60 else None)
    end()

    title("Omnimix", "v1.1")
    start()
    find_pattern("00 85 C0 74 07 E8", 0x1000, 1)
    find_pattern("00 85 C0 74 07 E8", pos(), 3)
    patch("EB", False)
    find_pattern("83 F8 04 75 05 C6 44 24 1B 01", 0x25000)
    try:
        find_pattern("75 08 C7 44 24 20 12", pos())
        patch("90 90 C7 44 24 20 26", False)
    except ValueError:
        find_pattern("14 00 00 00", pos())
        patch("26", False)
    find_pattern("0F 82 99 00 00 00", 0x80000)
    find_pattern("01 0F 84", pos(), 1)
    patch("90 E9", False)
    find_pattern("24 74 07 83 C0 04 3B C1 75 F4 3B C1 0F 95 C0 84 C0 0F 85", 0x80000, 12)
    patch("B0 01 90", False)
    find_pattern("FF 00 75 3E", 0x80000, 2)
    patch("EB", False)
    find_pattern("10 57 89 85 1C FE FF FF 68 00 00 10 00 33 C0", 0x90000, 11)
    patch("20", False)
    find_pattern("68 00 00 10 00", pos(), 3)
    patch("20", False)
    find_pattern("66 66 66 3F 66 66 66 3F 66 66 66 3F 33 33 33 3F CD CC", 0x100000)
    find_pattern_backwards("80 3F", pos(), -4)
    find_pattern_backwards("80 3F", pos())
    # find_pattern("00 00 00 00 00 00", pos(), -2)    # overwrite A3 attract song defaults (add 5 more songs to attract_mcodes)
    find_pattern("5A 96 00 00 00 00 00 00", pos())    # keep A3 attract song defaults
    attract_mcodes = (10836, 37481, 33551, 32792, 397, 36865, 37202, 220, 255, 10523, 33567, 37911, 36864, 36, 36879, 28715, 454, 314, 32810)
    patch(struct.pack('q'*len(attract_mcodes), *attract_mcodes).hex(), False)
    end()
