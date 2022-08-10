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

with open('gamemdx.dll', 'r+b') as gamemdx:
    mm = mmap.mmap(gamemdx.fileno(), 0)
    pe = pefile.PE('gamemdx.dll', fast_load=True)

    title("Force enable fast/slow")
    find_pattern("8B 41 48 C3", 0x90000)
    patch("B8 01 00 00 00 C3")

    title("Force background judgement")
    find_pattern("8B 41 44 C3", 0x90000)
    patch("B8 01 00 00 00 C3")

    title("Force darkest background")
    find_pattern("75 03 33 C0 C3 8B 41 38", 0x90000)
    patch("33 C0 B0 03")

    title("Opaque background for darkest background option", "This makes the darkest background option be 99% opaque, hiding the dancers and videos.")
    find_pattern("33 33 33 3F 66 66 66 3F", 0x200000, 4)
    patch("A4 70 7D")

    title("Song Unlock")
    start()
    find_pattern("06 80 38 00 0F", 0x90000, 4)
    if pos() > 0x100:
        patch_multi("90 E9")
        find_pattern("32 C0", pos())
        patch_multi("B0 01")
        find_pattern("B8 00 00 00 0F 8C", pos(), 4)
        patch_multi("90 E9")
    else:
        find_pattern("75 07 32 C0", 0xCCCCC)
        patch_multi("90 90 B0 01")
    find_pattern(str.encode('eventno_2'), 0x200000)
    patch_multi("62")
    find_pattern(str.encode('eventno') + b'\x00', pos())
    patch_multi("62")
    find_pattern(str.encode('region') + b'\x00', pos())
    patch_multi("62")
    find_pattern(str.encode('limited_cha'), pos())
    patch_multi("62")
    find_pattern(str.encode('limited') + b'\x00', pos())
    patch_multi("62")
    end()

    title("Tutorial Skip")
    find_pattern("0F 95 C0 84 C0 75 4A", 0x50000, 5)
    patch("EB")

    title("Timer Freeze")
    find_pattern("B0 00 00 00 74 5B", 0x25000, 4)
    patch("EB")

    title("Unlock options (force premium start)", "Extended e-amusement exclusive options such as ARROW COLOR and 0.25 speed mod")
    start()
    try:
        find_pattern("8B CB FF 15 92")
        if pos() > 0x60000:
            patch_multi("E9 AF 00 00 00")
            is_old = True
        else:
            find_pattern("33 D2 41 8B CC", 0x75000)
            find_pattern("33 D2 41 8B CC", pos(), 1)
            find_pattern("33 D2 41 8B CC", pos())
            patch_multi("E9 76 00 00 00")
            is_old = False
    except ValueError:
        find_pattern("33 D2 41 8B CC", 0x75000)
        find_pattern("33 D2 41 8B CC", pos(), 1)
        find_pattern("33 D2 41 8B CC", pos())
        patch_multi("E9 76 00 00 00")
        is_old = False
    if is_old:
        for search in range(4):
            find_pattern("00 00 00 49 8B", pos(), 3)
        patch_multi("EB 44")
    else:
        find_pattern("00 00 00 49 8B", pos(), 3)
        patch_multi("EB 42")
    end()

    title("Autoplay")
    start()
    find_pattern("41 8D 50 38 E8", 0x25000, -2)
    patch_multi("90 90")
    find_pattern("74", pos())
    patch_multi("90 90")
    end()

    title("Hide all bottom text", "Such as EVENT MODE, PASELI, COIN, CREDIT, MAINTENANCE")
    find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
    start_pos = pos()
    find_pattern("00 4E 4F 54 20 41 56 41 49 4C 41 42 4C 45", pos())
    end_pos = pos() + 14
    hide_length = end_pos - start_pos
    find_pattern("45 56 45 4E 54 20 4D 4F 44 45", 0x125000)
    patch("00" * hide_length)

    title("Force Cabinet Type 6", "Gold cab")
    start()
    find_pattern("BB 02 00 00 00", 0x7500, 1)
    find_pattern("BB 02 00 00 00", pos(), 1)
    patch_multi("06")
    find_pattern("0F 88", pos())
    patch_multi("90 E9")
    end()

    title("Enable cabinet lights for Cabinet Type 6", "This enables the use of cabinet lighting for Cabinet Type 6")
    start()
    find_pattern("CC CC CC CC CC CC 48 83 EC 28 E8", 0, 10)
    patch_multi("B8 00 00 00 00")
    find_pattern("83 61 08 FE E8", 0x35000, 4)
    patch_multi("B8 00 00 00 00")
    find_pattern("05 00 00 E8", pos(), 3)
    patch_multi("B8 00 00 00 00")
    end()

    title("Enable DDR SELECTION", "Even works in offline/local mode!")
    find_pattern("FF FF FF 32 C0 48", 0x90000, 3)
    patch("B0 01")

    title("Premium Free")
    start()
    find_pattern("FF 41 08", 0x20000)
    pfree = pe.get_rva_from_offset(pos())
    find_pattern_backwards("01", pos(), -1)
    patch_multi("00")
    find_pattern("CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", 0x150000)
    int3_absolute = pos()
    int3_rva = pe.get_rva_from_offset(pos())
    find_pattern("FF 41 08")
    patch_multi(f"E9{struct.pack('<i', int3_rva - pfree - 5).hex()}90")
    mm.seek(int3_absolute)
    patch_multi(f"C7 41 08 01 00 00 00 45 33 C0 E9 {struct.pack('<i', pfree - (int3_rva + 11) + 2).hex()}")
    end()

    title("Mute Announcer", "Also mutes crowd cheering and booing during gameplay")
    start()
    find_pattern("58 85 C9 0F 84", 0x30000, 3)
    patch_multi("90 E9")
    find_pattern(str.encode('voice.xwb'), 0x200000)
    patch_multi("62")
    find_pattern(str.encode('voice_n.xwb'), pos())
    patch_multi("62")
    end()

    title("Force DDR SELECTION theme everywhere", "Skips intro and enables the skin selected below on all songs")
    start()
    find_pattern("94 01 00 00 0F 84", 0x25000, 4)
    patch_multi("90 E9")
    find_pattern("0D 75 35", 0x90000, 1)
    patch_multi("90 90")
    find_pattern("74", pos())
    patch_multi("EB")
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Choose forced theme",')
    find_pattern("BA 01 00 00 00", pos(), 1)
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
    print('    name : "Choose cabinet type timing offset",')
    find_pattern("45 F8 01 E8", 0x15000, 3)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(5), "Default")
    union("B800000000", "Force CRT 945 p3io timing")
    union("B801000000", "Force LCD 945 p3io timing")
    union("B802000000", "Force LCD HM64 p4io timing")
    union("B803000000", "Force CRT ADE-6291 p3io timing")
    union("B804000000", "Force LCD ADE-6291 p3io timing")
    union("B805000000", "Force LCD ADE-6291 p4io timing")
    union("B806000000", "Force LCD ADE-6291 bio2 timing")
    end()

    title("Center arrows for single player")
    start()
    find_pattern("4C 0F 45 C9", 0x40000)
    mm.seek(pos() - 0x300)
    find_pattern_backwards("75", pos(), -1)
    patch_multi("EB")
    find_pattern("4c 0F 45 C9", pos())
    patch_multi("90" * 4)
    find_pattern("8B 5C 24", pos())
    patch_multi("BB EF 01 00 00 89 5C 24 38 EB 1F 90")
    find_pattern("EB 16", pos())
    patch_multi("C7 44 24 38 EF 01 00 00 EB 0E 90 90")
    end()
