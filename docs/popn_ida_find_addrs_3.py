import idc
import idaapi
import idautils
import struct

MUSIC_IDX = 0
CHART_IDX = 1
STYLE_IDX = 2
FLAVOR_IDX = 3
CHARA_IDX = 4

OFFSET_BLACKLIST = [
    # These offsets are known bads
    0x100be154,
    0x100be346,
    0x100bed91,
    0x100e56ec,
    0x100e56f5,
    0x100e5a55,
    0x100e5a5e,
    0x100fa4e2,
]


def find_binary(search, search_head, search_idx):
    ea = 0
    found = -1
    while True:
        ea = idc.find_binary(ea + 1, SEARCH_DOWN | SEARCH_NEXT, search)

        if ea == idc.BADADDR:
            break

        found += 1

        ea = ea + search_head

        if found != search_idx:
            continue

        return ea

    return None


def find_binary_xref(search, search_head, search_idx, xref_search_idx):
    ea = 0
    found = -1
    while True:
        ea = idc.find_binary(ea + 1, SEARCH_DOWN | SEARCH_NEXT, search)

        if ea == idc.BADADDR:
            break

        found += 1

        ea = ea + search_head

        if found != search_idx:
            continue

        for xref_idx, xref in enumerate(idautils.XrefsTo(ea)):

            if xref_idx == xref_search_idx:
                return xref.frm

    return None


def get_table_size_by_xref(ea, entry_size):
    # Skip 10 entries because why not. We're looking for the end anyway
    orig_ea = ea
    ea += entry_size * 10

    found_end = False
    while not found_end:
        for xref_idx, xref in enumerate(idautils.XrefsTo(ea)):
            found_end = True
            break

        if not found_end:
            ea += entry_size

    return (ea - orig_ea) // entry_size


def find_weird_update_patches(music_limit):
    new = True if music_limit > 2040 else False
    if new:
        ea = find_binary("83 C4 04 89 44 24 14 C7", 0, 0)
    else:
        ea = find_binary("83 C4 04 3B C5 74 09", 0, 0)
    orig_ea = ea

    values = []

    # Find previous PUSH
    while orig_ea - ea < 0x1000:
        if idc.print_insn_mnem(ea) == "push":
            values.append([MUSIC_IDX, 11, idc.get_operand_value(ea, 0), ea])
            break

        ea = idc.prev_head(ea)

    # Find next CALL
    ea = orig_ea
    call_ea = None
    while ea - orig_ea < 0x1000:
        if idc.print_insn_mnem(ea) == "call":
            call_ea = idc.get_operand_value(ea, 0)
            break

        ea = idc.next_head(ea)

    if call_ea is None:
        print("Couldn't find call, can't finish")
        exit(1)

    ea = idc.find_func_end(call_ea)
    lea_values = []
    if new:
        lea_orders = [11, 11, 10, 10, 9, 9]
    else:
        lea_orders = [11, 10, 9]
    while ea >= call_ea:
        if idc.print_insn_mnem(ea) == "lea" and idc.print_operand(ea, 1).startswith('[ebx+'):
            lea_values.append([MUSIC_IDX, lea_orders[len(lea_values)], idc.get_operand_value(ea, 1), ea])

        # It is probably possible to pull a lot more from here
        if new and len(lea_values) == 6:
            break
        elif not new and len(lea_values) == 3:
            break

        ea = idc.prev_head(ea)

    if new:
        return lea_values[-1::-2] + values
    else:
        return lea_values[::-1] + values


# These all reference the first entry in their respective tables
music_table_addr = find_binary_xref("00 83 7C 83 62 83 76 83 58 00", 1, 0, 0)
chart_table_addr = find_binary_xref("00 70 6F 70 6E 31 00 00", 1, 0, 1)
style_table_addr = find_binary("01 00 00 00 FF 54 0C 00 1A 00 00 00 11 00 00 00", 0, 2)
flavor_table_addr = find_binary("00 82 BB 82 EA 82 A2 82 AF 81 5B 00 00 00 82 A4 82", 1, 0)
chara_table_addr = find_binary_xref("00 62 61 6D 62 5F 31 61 00", 1, 0, 0)

# Modify the entry sizes as required
buffer_addrs = [
    # entry type, table address, entry size
    [MUSIC_IDX, music_table_addr, 0xac],
    [CHART_IDX, chart_table_addr, 0x20], # Probably won't change?
    [STYLE_IDX, style_table_addr, 0x10], # Unlikely to change
    [FLAVOR_IDX, flavor_table_addr, 0x60],
    [CHARA_IDX, chara_table_addr, 0x4C],
]

limit_info_list = [
    # buffer_addr + (buffer_entry_size * limit) should give you the very end of the array (after the last entry)
    [MUSIC_IDX, get_table_size_by_xref(*buffer_addrs[MUSIC_IDX][1:])],
    [CHART_IDX, get_table_size_by_xref(*buffer_addrs[CHART_IDX][1:])],
    [STYLE_IDX, get_table_size_by_xref(*buffer_addrs[STYLE_IDX][1:])],
    [FLAVOR_IDX, get_table_size_by_xref(*buffer_addrs[FLAVOR_IDX][1:])],
    [CHARA_IDX, get_table_size_by_xref(*buffer_addrs[CHARA_IDX][1:])],
]

update_patches = [
    [MUSIC_IDX, 0, limit_info_list[MUSIC_IDX][1] - 1],
    [MUSIC_IDX, 0, limit_info_list[MUSIC_IDX][1]],
    [CHART_IDX, 0, limit_info_list[CHART_IDX][1]],
    [CHART_IDX, 0, limit_info_list[CHART_IDX][1] - 1],
    [CHARA_IDX, 0, limit_info_list[CHARA_IDX][1]],
    [FLAVOR_IDX, 0, limit_info_list[FLAVOR_IDX][1] - 1],
    [FLAVOR_IDX, 0, limit_info_list[FLAVOR_IDX][1]],

    # These values may change in a future patch, but they worked for Usaneko and Peace for now.
    # These could possibly be done using something similar to the find_weird_update_patches code.
    [MUSIC_IDX, 1, 0x1BD0 - (1780 - limit_info_list[MUSIC_IDX][1]) * 4],
    [MUSIC_IDX, 1, 0x1Bcf - (1780 - limit_info_list[MUSIC_IDX][1]) * 4],
    [MUSIC_IDX, 2, 0xA6E0 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x18],
    [MUSIC_IDX, 3, 0x29B7 - (1780 - limit_info_list[MUSIC_IDX][1]) * 6],
    [MUSIC_IDX, 4, 0x3E944 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x90],

    [MUSIC_IDX, 4, 0x3E948 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x90],
    [MUSIC_IDX, 5, 0x1F4F4 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x48],
    [MUSIC_IDX, 5, 0x1F4C0 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x48],
    [MUSIC_IDX, 5, 0x1F4F0 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x48],
    [MUSIC_IDX, 6, 0x7D3D8 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x120],
    [MUSIC_IDX, 6, 0x7D3D4 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x120],
    [MUSIC_IDX, 7, 0x1D8E58 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x440],
    [MUSIC_IDX, 7, 0x1D9188 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x440],
    [MUSIC_IDX, 8, 0x5370 - (1780 - limit_info_list[MUSIC_IDX][1]) * 0x0c],
    [FLAVOR_IDX, 8, limit_info_list[FLAVOR_IDX][1] * 0x0c],
    [FLAVOR_IDX, 8, limit_info_list[FLAVOR_IDX][1] * 0x0c + 4],
]

hook_addrs = [
    [0, find_binary("8B C6 E8 ?? ?? ?? ?? 83 F8 ?? 7D ?? 56 8A C3 E8 ?? ?? ?? ?? 83 C4 04 3D ?? ?? ?? ?? 7D ??", 0, 0)],
    [1, find_binary("83 F8 ?? 0F 9C C0 E8", 0, 0)],
]

TARGETS = {
    MUSIC_IDX: 'music',
    CHART_IDX: 'chart',
    STYLE_IDX: 'style',
    FLAVOR_IDX: 'flavor',
    CHARA_IDX: 'chara'
}

print("<?xml version='1.0' encoding='shift-jis'?>")
print("<patches>")

print("\t<limits>")
for limit_info in limit_info_list:
    patch_target, limit_value = limit_info
    if TARGETS[patch_target] == "music":
        music_limit = limit_value
    print('\t\t<%s __type="u32">%d</%s>' % (TARGETS[patch_target], limit_value, TARGETS[patch_target]))
print("\t</limits>")

print("\t<buffer_base_addrs>")
for buffer_info in buffer_addrs:
    patch_target, buffer_addr, entry_size = buffer_info
    print('\t\t<%s __type="str">0x%x</%s>' % (TARGETS[patch_target], buffer_addr, TARGETS[patch_target]))
print("\t</buffer_base_addrs>")

print("\t<buffers_patch_addrs>")
for buffer_info in buffer_addrs:
    patch_target, search_value_base, entry_size = buffer_info

    for search_value in range(search_value_base, search_value_base + entry_size + 1):
        raw_search_value = bytearray(struct.pack("<I", search_value))

        for xref in idautils.XrefsTo(search_value):
            ea = xref.frm

            # Find extact bytes to be patched
            raw_bytes = bytearray([idc.get_wide_byte(ea + i) for i in range(0x10)])

            if raw_search_value not in raw_bytes:
                print('\t\t<!-- Couldn\t find raw bytes: ' + idc.GetDisasm(ea) + ' -->')
                continue

            if ea + raw_bytes.index(raw_search_value) in OFFSET_BLACKLIST:
                continue

#            print('\t\t<!-- ' + idc.GetDisasm(ea) + ' -->')
            print('\t\t<%s __type="str">0x%x</%s>' % (TARGETS[patch_target], ea + raw_bytes.index(raw_search_value), TARGETS[patch_target]))
#            print("")

# This is a hack for Usaneko.
# Usaneko's code is dumb.
# If it doesn't find *this* address it won't stop the loop.
random_lv7 = find_binary_xref("83 89 83 93 83 5F 83 80 20 4C 76 20 37 00 00 00", 0, 0, 0)
random_lv7_xrefs = idautils.XrefsTo(random_lv7) if random_lv7 is not None else []
for x in random_lv7_xrefs:
    ea = x.frm
    raw_bytes = bytearray([idc.get_wide_byte(ea + i) for i in range(0x10)])
    raw_search_value = bytearray(struct.pack("<I", random_lv7))

    if ea + raw_bytes.index(raw_search_value) in OFFSET_BLACKLIST:
        continue

#    print('\t\t<!-- ' + idc.GetDisasm(ea) + ' -->')
    print('\t\t<%s __type="str">0x%x</%s>' % (TARGETS[MUSIC_IDX], ea + raw_bytes.index(raw_search_value), TARGETS[MUSIC_IDX]))

print("\t</buffers_patch_addrs>")

print("\t<other_patches>")
for patch_info in update_patches:
    patch_target, patch_type, search_value = patch_info
    raw_search_value = bytearray(struct.pack("<I", search_value))

    ea = 0
    while ea != idc.BADADDR:
        (ea, n) = idc.find_imm(ea, idc.SEARCH_DOWN, search_value)
        if ea != idc.BADADDR:
            if "%X" % search_value not in idc.GetDisasm(ea):
                continue

            if idc.print_insn_mnem(ea) == "dd" or idc.GetDisasm(ea).strip().startswith("dd "):
                # Skip non-code bits
                continue

            if "NumberOfBytesWritten" in idc.GetDisasm(ea):
                # Skip known bad parts
                continue

            # Find extact bytes to be patched
            raw_bytes = bytearray([idc.get_wide_byte(ea + i) for i in range(0x10)])

            if raw_search_value not in raw_bytes:
                continue

            if ea + raw_bytes.index(raw_search_value) in OFFSET_BLACKLIST:
                continue

#            print('\t\t<!-- ' + idc.GetDisasm(ea) + ' -->')
            print('\t\t<%s __type="str" method="%d" expected="0x%x">0x%x</%s>' % (TARGETS[patch_target], patch_type, search_value, ea + raw_bytes.index(raw_search_value), TARGETS[patch_target]))
#            print("")

update_patches_weird = find_weird_update_patches(music_limit)
for patch_info in update_patches_weird:
    patch_target, patch_type, search_value, ea = patch_info
    raw_search_value = bytearray(struct.pack("<I", search_value))

    # Find extact bytes to be patched
    raw_bytes = bytearray([idc.get_wide_byte(ea + i) for i in range(0x10)])

    if raw_search_value not in raw_bytes:
        print('\t\t<!-- Couldn\t find raw bytes: ' + idc.GetDisasm(ea) + ' -->')
        continue

    if ea + raw_bytes.index(raw_search_value) in OFFSET_BLACKLIST:
        continue

#    print('\t\t<!-- ' + idc.GetDisasm(ea) + ' -->')
    print('\t\t<%s __type="str" method="%d" expected="0x%x">0x%x</%s>' % (TARGETS[patch_target], patch_type, search_value, ea + raw_bytes.index(raw_search_value), TARGETS[patch_target]))
#    print("")

print("\t</other_patches>")

print("\t<hook_addrs>")
for hook_info in hook_addrs:
    hook_type, offset = hook_info

    if offset is None:
        continue

    if hook_type == 1:
        offset = idc.next_head(offset)
        offset = idc.next_head(offset)

#    print('\t\t<!-- ' + idc.GetDisasm(offset) + ' -->')
    print('\t\t<offset __type="str" method="%d">0x%x</offset>' % (hook_type, offset))
#    print("")

print("\t</hook_addrs>")

print("</patches>")
