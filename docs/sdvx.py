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

with open('soundvoltex.dll', 'r+b') as soundvoltex:
    mm = mmap.mmap(soundvoltex.fileno(), 0)
    pe = pefile.PE('soundvoltex.dll', fast_load=True)

    title("Disable power change", "Prevents power mode change on startup")
    find_pattern("33 DB 85 C0 75 42", 0x100000, 4)
    patch("EB")

    title("Disable monitor change", "Prevents monitor setting changes on startup")
    find_pattern("00 85 C0 75 2C E8", pos(), 3)
    patch("EB")

    title("Force BIO2 (KFC) IO in Valkyrie mode", "Will only work with <spec __type=\\\"str\\\">F</spec> changed to either G or H, in ea3-config.xml.")
    find_pattern("18 48 8B F1 83 B9 98 00 00 00 00", 0x300000)
    find_pattern_backwards("C3")
    io = pe.get_rva_from_offset(pos())
    find_pattern("4E 0C 00 00 48", 0x300000, 7)
    patch(struct.pack('<i', io - pe.get_rva_from_offset(pos()) - 4))

    fps = (120, 144, 165, 240, 360)
    print("{")
    print('    type : "union",')
    print('    name : "Game FPS Target",')
    find_pattern("40 00 00 00 00 00 00 4E", 0x600000, 1)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print(f"    patches : [")
    union(mm.read(8), "Default")
    for value in fps:
        union(struct.pack('<d', value), f"{value} FPS")
    end()

    print("{")
    print('    type : "union",')
    print('    name : "Note FPS Target",')
    find_pattern("20 66 0F 6E F0 F3 0F E6 F6 F2 0F 59", 0x300000, 9)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    union(mm.read(15), "Default")
    for value in fps:
        union(f"909090909090B8{struct.pack('<i', value).hex()}F20F2AF0", f"{value} FPS")
    end()

    title("Force Note FPS Target", "Enable this if above is not Default")
    start()
    find_pattern("74 09", pos())
    patch_multi("90 90")
    find_pattern_backwards("74 5F", pos(), -2)
    patch_multi("90 90")
    end()

    title("Shared mode WASAPI", "Only replaces the first audio device init attempt. Set output to 44100Hz 16bit if it doesn't work.")
    find_pattern("90 BA 04 00 00 00 48 8B 0D", 0x400000, 2)
    patch("00")

    title("Shared mode WASAPI Valkyrie")
    find_pattern("90 BA 07 00 00 00 48 8B 0D", 0x400000, 2)
    patch("00")

    title("Allow non E004 cards", "Allows cards that do not have E004 card IDs (such as mifare cards) to work.")
    start()
    find_pattern("00 8B 11 83 FA 01 75", 0, 6)
    patch_multi("90 90")
    find_pattern("74", pos())
    patch_multi("EB")
    end()

    title("Unlock All Songs")
    start()
    for search in range(4):
        find_pattern("74 26 83", pos(), 1)
    mm.seek(pos() - 1)
    patch_multi("EB 1F")
    find_pattern("44 0F B6 74")
    patch_multi("41 BE  03 00 00 00")
    end()

    title("Unlock All Difficulties")
    find_pattern("00 00 C7 40 30 04 00 00 00 E8", 0x200000)
    find_pattern("00 00 75", pos(), 2)
    patch("EB")

    title("Enable S-CRITICAL in Light Start", "Only in Valkyrie mode")
    start()
    find_pattern("A8 00 00 00 48 83 C4 20 5B C3 48 83 EC 28", 0x60000)
    find_pattern("00 00 74", pos(), 2)
    patch_multi("90 90")
    find_pattern("74 20 48", pos())
    patch_multi("90 90")
    start_pos = pos()
    find_pattern("00 00 74 04", pos(), 2)
    end_pos = pos()
    if end_pos - start_pos < 0xE00:
        patch_multi("90 90")
    end()

    title("Uncensor album jackets (for K region only)")
    find_pattern(str.encode('jacket_mask'), 0x600000, 8)
    patch("75")

    title("Hide all bottom text")
    find_pattern(str.encode('credit_service'), 0x600000, 22)
    patch("00" * 0x1C2)

    title("Disable subscreen in Valkyrie mode")
    find_pattern("83 BD B8 00 00 00 02", 0x300000, 15)
    rsp_offset = mm.read(1)
    mm.seek(pos() - 16)
    patch(f"41B60044887424{rsp_offset.hex()}9090909090909090")

    title("Timer freeze")
    find_pattern("00 8B 83 80 00 00 00 85 C0 0F 84", 0x50000, 10)
    patch("85")

    title("Premium timer freeze")
    start()
    find_pattern("06 0F 85 84 00 00 00 8B", 0x200000, 1)
    patch_multi("90 E9")
    find_pattern("00 0F 84 83 00 00 00 8B 05", 0x200000, 1)
    patch_multi("90 E9")
    find_pattern("20 01 00 00 C6 80 E9", 0x100000)
    find_pattern("75 0D E8", pos())
    patch_multi("EB")
    end()

    title("Hide premium guide banner", "blpass_ef (rainbow outline on health gauge) is shown instead of pt_sousa_usr")
    find_pattern(str.encode('pt_sousa_usr'))
    pt = pe.get_rva_from_offset(pos())
    find_pattern("00 44 89 44 24 28 48 8D 45", 0x200000)
    for search in range(4):
        find_pattern("45 33 C0", pos(), 6)
    patch(struct.pack('<i', pt - pe.get_rva_from_offset(pos()) - 4))

    print("{")
    print('    type : "union",')
    print('    name : "Premium Time Length",')
    find_pattern("B8 00 70 C9 B2 8B 00 00 00 48", 0x250000, 1)
    print(f"    offset : 0x{hex(pos())[2:].upper()},")
    print("    patches : [")
    def premium(seconds, name, tip):
        result = seconds*1000000000 if seconds != 0 else 6666666
        union(struct.pack('q', result), name, tip)
    for seconds in (0, 1, 817, 3450):
        m, s = divmod(seconds, 60)
        premium(seconds, f'{m:02d}:{s:02d}', "Use with freeze")
    for minutes in (10, 15, 20, 30, 45, 60, 90):
        premium(minutes*60, f"{minutes} Minutes", "Default" if minutes == 10 else None)
    end()

    title("SDVX PLUS")
    start()
    find_pattern("76 04 44 89 51 18", 0x150000, 2)
    patch_multi("90" * 4)
    find_pattern("00 48 8B DA 4C 8B F1 48 8D", pos())
    for search in range(4):
        find_pattern("00 FF 15", pos(), 1)
    patch_multi("41 C6 46 05 58 90")
    find_pattern(str.encode('/data/others/music_db.xml'), 0x600000, 1)
    patch_multi(str.encode('plus'))
    find_pattern(str.encode('/data/music'), 0x600000, 1)
    patch_multi(str.encode('plus'))
    find_pattern(str.encode('game_bg/gmbg_edp2016.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_edp2016.ifs') + b'\x00' * 3)
    find_pattern(str.encode('game_bg/gmbg_kac5th_small.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_kac5th_s.ifs') + b'\x00' * 2)
    find_pattern(str.encode('game_bg/gmbg_omega18_maxma.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_omega18_m.ifs') + b'\x00')
    find_pattern(str.encode('game_bg/gmbg_omega_nianoa.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_omega_n.ifs') + b'\x00' * 3)
    find_pattern("73 5F 6A 61 63 6B 65 74 30", 0x600000)
    for n in range(1, 20):
        try:
            find_pattern(str.encode(f's_jacket{str(n).zfill(2)}.ifs'), 0, 8)
            if pos() > 0x1000:
                patch_multi("30 30")
        except ValueError:
            continue
    find_pattern(str.encode('game_bg/gmbg_diver_02_rishna.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_diver_02_rishna.ifs') + b'\x00' * 3)
    find_pattern(str.encode('game_bg/gmbg_omega_inoten.ifs'), 0x600000)
    patch_multi(str.encode('../../plus/g/gmbg_omega_ino.ifs') + b'\x00')
    end()
