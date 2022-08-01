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

def patch(on):
    offset = pos()
    on = on.replace(" ", "")
    off = mm.read(int(len(on) / 2))
    on_formatted = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2].upper()) for i in range(0, len(off.hex()), 2)]))
    off_formatted = '[%s]' % ', '.join(map(str, ["0x"+(off.hex().upper()[i:i+2]) for i in range(0, len(off.hex()), 2)]))
    print(f"    patches: [{{ offset: 0x{hex(offset)[2:].upper()}, off: {off_formatted}, on: {on_formatted} }}],")
    print("},")

def tobytes(val):
    return bytes.fromhex(val.replace(" ", ""))

def pos():
    return mm.tell()

with open('jubeat.dll', 'r+b') as jubeat:
    mm = mmap.mmap(jubeat.fileno(), 0)
    pe = pefile.PE('jubeat.dll', fast_load=True)

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
    find_pattern("B3 01 83 BE", 0x75000, 1)
    find_pattern("B3 01 83 BE", pos())
    find_pattern("00 00 75", pos(), 2)
    patch("EB")

    title("Skip Online Matching")
    find_pattern("00 8B D7 33 C9 E8", 0x50000)
    find_pattern("0F 84", pos())
    patch("90 E9")
