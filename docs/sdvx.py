import mmap
import pefile
import struct

def title(name, tooltip):
    print("{")
    print(f'    name: "{name}",')
    if tooltip is not None:
        print(f'    tooltip: "{tooltip}",')

def patches(poffset, off, on, pcount):

    poff = '[%s]' % ', '.join(map(str, ["0x"+(off.hex().upper()[i:i+2]) for i in range(0, len(off.hex().upper()), 2)]))
    pon = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2]) for i in range(0, len(off.hex().upper()), 2)]))

    if pcount == 1:
        print(f"    patches: [{{ offset: 0x{hex(poffset)[2:].upper()}, off: {poff}, on: {pon} }}],")
        print("},")
    else:
        print(f"        {{ offset: 0x{hex(poffset)[2:].upper()}, off: {poff}, on: {pon} }},")

def union(on, name, tooltip):

    pon = '[%s]' % ', '.join(map(str, ["0x"+(on[i:i+2]) for i in range(0, len(on), 2)]))

    print("        {")
    print(f'            name : "{name}",')
    if tooltip is not None:
        print(f'            tooltip : "{tooltip}",')
    print(f"            patch : {pon},")
    print("        },")

def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))


with open('soundvoltex.dll', 'r+b') as soundvoltex:
        mm = mmap.mmap(soundvoltex.fileno(), 0)
        pe = pefile.PE('soundvoltex.dll', fast_load=True)

        title("Disable power change", "Prevents power mode change on startup")
        mm.seek(mm.find((b'\x33\xDB\x85\xC0\x75\x42'), 0)+4)
        patches(mm.tell(), mm.read(1), "EB", 1)

        title("Disable monitor change", "Prevents monitor setting changes on startup")
        mm.seek(mm.find((b'\x00\x85\xC0\x75\x2C\xE8'), mm.tell())+3)
        patches(mm.tell(), mm.read(1), "EB", 1)

        title("Force BIO2 (KFC) IO in Valkyrie mode", "Will only work with <spec __type=\\\"str\\\">F</spec> changed to either G or H, in ea3-config.xml.")
        mm.seek(mm.find((b'\x18\x48\x8B\xF1\x83\xB9\x98\x00\x00\x00\x00'), 0))
        while mm.read(1) != b"\xC3":
            mm.seek(mm.tell()-2)
        io = pe.get_rva_from_offset(mm.tell())
        mm.seek(mm.find((b'\x4E\x0C\x00\x00\x48'), 0)+7)
        s = tohex(-(pe.get_rva_from_offset(mm.tell())-io+4), 32)[2:].upper()
        result = "".join(map(str.__add__, ("0"+s)[-2::-2] ,("0"+s)[-1::-2])).upper()
        patches(mm.tell(), mm.read(2), result, 1)

        print("{")
        print("    type : \"union\",")
        print("    name : \"Game FPS Target\",")
        mm.seek(mm.find((b'\x40\x00\x00\x00\x00\x00\x00\x4E'), 0)+6)
        print(f"    offset : 0x{hex(mm.tell())[2:].upper()},")
        print("    patches : [")
        union(mm.read(2).hex().upper(), "Default", None)
        fps = (120, 144, 165, 240, 360)
        for value in fps:
            union(f"{struct.pack('d', value).hex().upper()[10:-2]}", f"{value} FPS", None)
        print("    ]")
        print("},")

        print("{")
        print("    type : \"union\",")
        print("    name : \"Note FPS Target\",")
        mm.seek(mm.find((b'\x20\x66\x0F\x6E\xF0\xF3\x0F\xE6\xF6\xF2\x0F\x59'), 0)+9)
        print(f"    offset : 0x{hex(mm.tell())[2:].upper()},")
        print("    patches : [")
        union(mm.read(15).hex().upper(), "Default", None)
        for value in fps:
            union(f"909090909090B8{struct.pack('i', value).hex().upper()}F20F2AF0", f"{value} FPS", None)
        print("    ]")
        print("},")

        title("Force Note FPS Target", "Enable this if above is not Default")
        print(f"    patches: [")
        mm.seek(mm.find((b'\x74\x09'), mm.tell()))
        patches(mm.tell(), mm.read(2), "9090", 2)
        while mm.read(2) != b"\x74\x5F":
            mm.seek(mm.tell()-3)
        mm.seek(mm.tell()-2)
        patches(mm.tell(), mm.read(2), "9090", 2)
        print("    ],")
        print("},")

        title("Shared mode WASAPI", "Only replaces the first audio device init attempt. Set output to 44100Hz 16bit if it doesn't work.")
        mm.seek(mm.find((b'\x90\xBA\x04\x00\x00\x00\x48\x8B\x0D'), 0)+2)
        patches(mm.tell(), mm.read(1), "00", 1)

        title("Shared mode WASAPI Valkyrie", None)
        mm.seek(mm.find((b'\x90\xBA\x07\x00\x00\x00\x48\x8B\x0D'), 0)+2)
        patches(mm.tell(), mm.read(1), "00", 1)

        title("Allow non E004 cards", "Allows cards that do not have E004 card IDs (such as mifare cards) to work.")
        print(f"    patches: [")
        mm.seek(mm.find((b'\x00\x8B\x11\x83\xFA\x01\x75'), 0)+6)
        patches(mm.tell(), mm.read(2), "9090", 2)
        mm.seek(mm.find((b'\x74'), mm.tell()))
        patches(mm.tell(), mm.read(1), "EB", 2)
        print("    ],")
        print("},")

        title("Unlock All Songs", None)
        print(f"    patches: [")
        mm.seek(mm.find((b'\xEB\x05\x33\xC9'), 0))
        patches(mm.tell(), mm.read(54), "909033C9B80300000090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090", 2)
        mm.seek(mm.find((b'\x44\x0F\xB6\x74'), 0))
        patches(mm.tell(), mm.read(6), "41BE03000000", 2)
        print("    ],")
        print("},")

        title("Unlock All Difficulties", None)
        mm.seek(mm.find((b'\x00\x00\xC7\x40\x30\x04\x00\x00\x00\xE8'), 0))
        mm.seek(mm.find((b'\x00\x00\x75'), mm.tell())+2)
        patches(mm.tell(), mm.read(1), "EB", 1)

        title("Enable S-CRITICAL in Light Start", "Only in Valkyrie mode")
        print(f"    patches: [")
        mm.seek(mm.find((b'\xA8\x00\x00\x00\x48\x83\xC4\x20\x5B\xC3\x48\x83\xEC\x28'), 0))
        mm.seek(mm.find((b'\x00\x00\x74'), mm.tell())+2)
        patches(mm.tell(), mm.read(2), "9090", 2)
        mm.seek(mm.find((b'\x74\x20\x48'), mm.tell()))
        patches(mm.tell(), mm.read(2), "9090", 2)
        start = mm.tell()
        mm.seek(mm.find((b'\x00\x00\x74\x04'), mm.tell())+2)
        end = mm.tell()
        if end-start < 0xE00:
            patches(mm.tell(), mm.read(2), "9090", 2)
        print("    ],")
        print("},")

        title("Uncensor album jackets (for K region only)", None)
        mm.seek(mm.find(str.encode('jacket_mask'), 0)+8)
        patches(mm.tell(), mm.read(1), "75", 1)

        title("Hide all bottom text", None)
        mm.seek(mm.find(str.encode('credit_service'), 0)+0x16)
        patches(mm.tell(), mm.read(0x192), "00"*0x192, 1)

        title("Disable subscreen in Valkyrie mode", None)
        mm.seek(mm.find((b'\x83\xBD\xB8\x00\x00\x00\x02'), 0)+15)
        rsp_offset = mm.read(1)
        mm.seek(mm.tell()-16)
        patches(mm.tell(), mm.read(16), f"41B60044887424{rsp_offset.hex()}9090909090909090", 1)

        title("Timer freeze", None)
        mm.seek(mm.find((b'\x00\x8B\x83\x80\x00\x00\x00\x85\xC0\x0F\x84'), 0)+10)
        patches(mm.tell(), mm.read(1), "85", 1)

        title("Premium timer freeze", None)
        print(f"    patches: [")
        mm.seek(mm.find((b'\x06\x0F\x85\x84\x00\x00\x00\x8B'), 0)+1)
        patches(mm.tell(), mm.read(2), "90E9", 2)
        mm.seek(mm.find((b'\x00\x0F\x84\x83\x00\x00\x00\x8B\x05'), 0x190000)+1)
        patches(mm.tell(), mm.read(2), "90E9", 2)
        mm.seek(mm.find((b'\x20\x01\x00\x00\xC6\x80\xE9'), 0))
        mm.seek(mm.find((b'\x75\x0D\xE8'), mm.tell()))
        patches(mm.tell(), mm.read(1), "EB", 2)
        print("    ],")
        print("},")

        title("Hide premium guide banner", "blpass_ef (rainbow outline on health gauge) is shown instead of pt_sousa_usr")
        mm.seek(mm.find(str.encode('pt_sousa_usr'), 0))
        pt = pe.get_rva_from_offset(mm.tell())
        mm.seek(mm.find((b'\x00\x44\x89\x44\x24\x28\x48\x8D\x45'), 0))
        mm.seek(mm.find((b'\x45\x33\xC0'), mm.tell()+1))
        mm.seek(mm.find((b'\x45\x33\xC0'), mm.tell()+1))
        mm.seek(mm.find((b'\x45\x33\xC0'), mm.tell()+1))
        mm.seek(mm.find((b'\x45\x33\xC0'), mm.tell()+1)+6)
        s = tohex(-(pe.get_rva_from_offset(mm.tell())-pt+4), 32)[2:].upper()
        result = "".join(map(str.__add__, ("0"+s)[-2::-2] ,("0"+s)[-1::-2])).upper()
        patches(mm.tell(), mm.read(3), result, 1)

        print("{")
        print("    type : \"union\",")
        print("    name : \"Premium Time Length\",")
        mm.seek(mm.find((b'\xB8\x00\x70\xC9\xB2\x8B\x00\x00\x00\x48'), 0)+1)
        print(f"    offset : 0x{hex(mm.tell())[2:].upper()},")
        print("    patches : [")
        def premium(seconds, name, tip):
            result = seconds*1000000000 if seconds != 0 else 6666666
            union(f"{struct.pack('q', result).hex().upper()}", name, tip)
        for seconds in (0, 1, 817, 3450):
            m, s = divmod(seconds, 60)
            premium(seconds, f'{m:02d}:{s:02d}', "Use with freeze")
        for minutes in (10, 15, 20, 30, 45, 60, 90):
            premium(minutes*60, f"{minutes} Minutes", "Default" if minutes == 10 else None)
        print("    ]")
        print("},")

        title("SDVX PLUS", None)
        print(f"    patches: [")
        mm.seek(mm.find((b'\x76\x04\x44\x89\x51\x18'), 0)+2)
        patches(mm.tell(), mm.read(4), "90909090", 2)
        mm.seek(mm.find((b'\x00\x48\x8B\xDA\x4C\x8B\xF1\x48\x8D'), 0))
        mm.seek(mm.find((b'\x00\xFF\x15'), mm.tell())+1)
        mm.seek(mm.find((b'\x00\xFF\x15'), mm.tell())+1)
        mm.seek(mm.find((b'\x00\xFF\x15'), mm.tell())+1)
        mm.seek(mm.find((b'\x00\xFF\x15'), mm.tell())+1)
        patches(mm.tell(), mm.read(6), "41C646055890", 2)
        mm.seek(mm.find(str.encode('/data/others/music_db.xml'), 0)+1)
        patches(mm.tell(), mm.read(4), "706C7573", 2)
        mm.seek(mm.find(str.encode('/data/music'), 0)+1)
        patches(mm.tell(), mm.read(4), "706C7573", 2)
        mm.seek(mm.find(str.encode('game_bg/gmbg_edp2016.ifs'), 0))
        patches(mm.tell(), mm.read(0x20), "2E2E2F2E2E2F706C75732F672F676D62675F656470323031362E696673000000", 2)
        mm.seek(mm.find(str.encode('game_bg/gmbg_kac5th_small.ifs'), 0))
        patches(mm.tell(), mm.read(0x20), "2E2E2F2E2E2F706C75732F672F676D62675F6B61633574685F732E6966730000", 2)
        mm.seek(mm.find(str.encode('game_bg/gmbg_omega18_maxma.ifs'), 0))
        patches(mm.tell(), mm.read(0x20), "2E2E2F2E2E2F706C75732F672F676D62675F6F6D65676131385F6D2E69667300", 2)
        mm.seek(mm.find(str.encode('game_bg/gmbg_omega_nianoa.ifs'), 0))
        patches(mm.tell(), mm.read(0x20), "2E2E2F2E2E2F706C75732F672F676D62675F6F6D6567615F6E2E696673000000", 2)
        mm.seek(mm.find((b'\x73\x5F\x6A\x61\x63\x6B\x65\x74\x30'), 0))
        for n in range(1, 20):
            try:
                mm.seek(mm.find(str.encode(f's_jacket{str(n).zfill(2)}.ifs'), 0)+8)
                if mm.tell() > 0x1000:
                    patches(mm.tell(), mm.read(2), "3030", 2)
            except ValueError:
                continue
        mm.seek(mm.find(str.encode('game_bg/gmbg_diver_02_rishna.ifs'), 0))
        patches(mm.tell(), mm.read(0x28), "2E2E2F2E2E2F706C75732F672F676D62675F64697665725F30325F726973686E612E696673000000", 2)
        mm.seek(mm.find(str.encode('game_bg/gmbg_omega_inoten.ifs'), 0))
        patches(mm.tell(), mm.read(0x20), "2E2E2F2E2E2F706C75732F672F676D62675F6F6D6567615F696E6F2E69667300", 2)
        print("    ],")
        print("},")
