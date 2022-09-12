import mmap
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

with open('jubeat.dll', 'r+b') as jubeat:
    mm = mmap.mmap(jubeat.fileno(), 0)

    title("Skip Tutorial")
    find_pattern("6A 01 8B C8 FF 15", 0x75000)
    find_pattern("84 C0 0F 85", pos(), 2)
    patch("90 E9")

    title("Select Music Timer Freeze")
    find_pattern("01 00 84 C0 75", 0x75000, 4)
    patch("EB")

    title("Skip Category Select")
    find_pattern("68 00 04", pos(), 2)
    patch("07")

    title("Result Timer Freeze", "Counts down to 0 then stops")
    try:
        find_pattern("B3 01 83 BE", 0x75000, 1)
        find_pattern("B3 01 83 BE", pos())
        find_pattern("00 75", pos(), 1)
        patch("EB")
    except ValueError:
        find_pattern("00 75 09 33 C9 E8", 0x75000, 1)
        patch("EB")

    title("Skip Online Matching")
    find_pattern("00 8B D7 33 C9 E8", 0x50000)
    find_pattern("0F 84", pos())
    patch("90 E9")

    title("Force Unlock All Markers")
    start()
    find_pattern("C8 22 10 84 C0 75 2B 0F 28 44 24 40", 0x150000, 5)
    patch_multi("EB")
    find_pattern("75 47 0F 28 85 B0 FD FF", pos())
    patch_multi("EB")
    find_pattern("0F B7 45 B0", pos())
    patch_multi("31 C0 90 90")
    end()

    title("Force Unlock All Backgrounds")
    start()
    find_pattern("84 C0 75 43 0F 28 85 B0", 0x100000, 2)
    patch_multi("EB")
    find_pattern("0F B7 45 B0", pos())
    patch_multi("31 C0 90 90")
    find_pattern("6A 40 50 6A 06 56 FF 15 64", pos(), 1)
    find_pattern("6A 40 50 6A 06 56 FF 15 64", pos())
    find_pattern("10 84 C0 75", pos(), 3)
    patch_multi("EB")
    end()

    title("Force Enable Expert Option")
    find_pattern("D1 C6 45 FF 01 A8 01 75 13", 0x90000)
    find_pattern_backwards("55 8B", pos(), -2)
    patch("B0 01 C3")

    print("{")
    print('    type : "union",')
    print('    name : "Default Marker For Guest Play",')
    find_pattern("B9 0B 66 C7 05", 0x45000, -2)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    default = struct.unpack('<B', mm.read(1))[0]
    if default == 49:
        union("31", "Default")
    union("2E", "Festo")
    union("28", "Qubell")
    union("04", "Shutter")
    end()
