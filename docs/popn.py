import mmap

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

def tobytes(val):
    try:
        return bytes.fromhex(val.replace(" ", ""))
    except TypeError:
        val = val.hex()
        return bytes.fromhex(val.replace(" ", ""))

def pos():
    return mm.tell()

with open('popn22.dll', 'r+b') as popn22:
    mm = mmap.mmap(popn22.fileno(), 0)

    title("E: Drive Fix", "Fix crash caused by no E: drive")
    find_pattern("65 3A 2F", 0x200000)
    patch("64 65 76")

    title("HDMI Audio Fix")
    find_pattern("10 85 C0 75 96", 0x100000, 1)
    patch("90" * 4)

    title("Prevent Windows volume change on boot", "If your volume gets forced to max, turn this on")
    find_pattern("10 89 44 24 14 8B C6", 0x100000)
    find_pattern_backwards("83 EC", pos(), -2)
    patch("C3")

    title("Boot to Event Mode")
    find_pattern("8B 00 C3 CC CC CC CC CC CC CC CC CC CC CC CC CC C7 40 04 00 00 00 00", 0x80000)
    patch("31 C0 40 C3")

    title("Remove Timer")
    find_pattern("00 0F 85 65 05 00 00", 0x90000, 1)
    patch("90 E9")

    title("Skip Menu and Long Note Tutorials")
    start()
    find_pattern("00 84 C0 74 3A E8", 0x20000, 3)
    patch_multi("EB")
    find_pattern_backwards("75 5E", pos(), -2)
    patch_multi("EB")
    find_pattern("5F 5E 66 83 F8 01 75", 0x75000, 6)
    patch_multi("EB")
    end()

    title("Unlock All Songs")
    start()
    find_pattern("FF FF A9 06 00 00 68 74", 0x90000, 7)
    patch_multi("EB")
    find_pattern_backwards("74 13", pos(), -2)
    patch_multi("90 90")
    end()

    title("Unlock EX Charts")
    start()
    ex = []
    mm.seek(0x200000)
    while True:
        find_pattern("80 00 00 03", pos(), 1)
        if int(mm.tell()-2) > 0x200000:
            mm.seek(pos() -1)
            patch_multi("00")
        else:
            break
    mm.seek(0x200000)
    while True:
        find_pattern("80 00 00 07", pos(), 1)
        if int(mm.tell()-2) > 0x200000:
            mm.seek(pos() -1)
            patch_multi("00")
        else:
            break
    end()

    title("Unlock Deco Parts")
    find_pattern("83 38 00 75 22", 0x90000, 3)
    patch("90 90")

    title("Unlock Characters")
    find_pattern("A9 50 01 00 00 74", 0x90000, 5)
    patch("EB")

    title("Premium Free", "Score buffer never resets, use offline")
    start()
    find_pattern("CC FE 46 0E 80 BE", 0x100000, 1)
    patch_multi("90 90 90")
    find_pattern("75", pos())
    patch_multi("EB")
    find_pattern("77 3E", pos())
    patch_multi("EB 07")
    end()

    title("Autoplay")
    start()
    find_pattern("84 C0 0F 84 08 01 00 00", 0x90000, 2)
    patch_multi("90" * 6)
    find_pattern("74 53", pos())
    patch_multi("90 90")
    end()

    title("Replace COLOR CHECK test menu with debug CHARA VIEWER", "Press service button to exit")
    start()
    find_pattern(str.encode("COLOR CHECK"), 0x190000)
    patch_multi(str.encode("CHARA VIEWER") + b"\x00")
    find_pattern("00 00 00 00 68 AC 00 00 00 E8", 0x20000, 5)
    patch_multi("B0 34 0C")
    find_pattern("E8 DC FE FF", pos(), 1)
    patch_multi("1C CD 09 00")
    end()

    title("Replace SCREEN CHECK test menu with debug MUSIC INFO CHECKER", "Press service button to exit")
    start()
    find_pattern(str.encode("SCREEN CHECK"), 0x190000)
    patch_multi(str.encode("MUSIC INFO") + b"\x00\x00")
    find_pattern("00 00 00 00 68 8C 00 00 00 E8", 0x20000, 5)
    patch_multi("B0 34 0C")
    find_pattern("E8 FC FE FF FF", pos(), 1)
    patch_multi("AC FB 09 00")
    end()
