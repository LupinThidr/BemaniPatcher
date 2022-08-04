import mmap

def title(name, tooltip = None):
    print("{")
    print(f'    name: "{name}",')
    if tooltip is not None:
        print(f'    tooltip: "{tooltip}",')

def find_pattern(pattern, start = 0, adjust = 0):
    return mm.seek(mm.find(tobytes(pattern), start) + adjust)

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

with open('game.dll', 'r+b') as game:
    mm = mmap.mmap(game.fileno(), 0)

    title("Timer Freeze")
    find_pattern("84 C0 0F 85 3E 01 00", 0, 2)
    patch("90 E9")

    title("Cursor Hold")
    find_pattern("00 85 C9 0F 85", 0, 3)
    patch("90 E9")

    title("Stage Freeze", "Not compatible for use on networks")
    find_pattern("00 84 C0 0F 85 56 01 00", 0, 3)
    patch("90 E9")

    title("Skip Tutorial", "Not compatible for use on networks")
    find_pattern("30 83 F8 0D 0F 87", 0, 4)
    patch("90 E9")

    title("Unlock all songs", "Not compatible for use on networks")
    start()
    find_pattern("00 00 00 00 00 00 00 00 00 00 44 00 61 00 02 00 00", 0, 12)
    patch_multi("4D 01")
    find_pattern("00 00 00 00 00 00 00 00 00 00 44 00 63 00 02 00 00", pos(), 12)
    patch_multi("4D 01")
    find_pattern("C3 85 C9 75 08", 0, 3)
    patch_multi("EB 11")
    end()

    title("Enable Long Music", "Not compatible for use on networks")
    find_pattern("CC CC CC 80 79 30 00 74", 0, 7)
    patch("EB")

    title("Autoplay", "Not compatible for use on networks")
    start()
    find_pattern("75 16 B9 02 00")
    patch_multi("EB")
    find_pattern("00 0F 85 BA 00 00 00 48", pos(), 1)
    patch_multi("90 E9")
    find_pattern("00 75 60 80", pos(), 1)
    patch_multi("EB")
    end()

    title("Skip 'NOW DATA INITIALIZING'", "Useful for testing only")
    find_pattern("00 00 0F 84 74 01 00 00", 0, 2)
    patch("90" * 6)
