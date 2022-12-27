import argparse
import json
import pymem
import time


def patch(title):
    for p in patches["data"][title]["patches"]:
        rva = int(p["rva"], 16)
        off = bytes.fromhex(p["off"])
        on = bytes.fromhex(p["on"])
        length = len(on)

        if pm.read_bytes(game.lpBaseOfDll + rva, length) == off:
            pm.write_bytes(game.lpBaseOfDll + rva, on, length)
            state = "ENABLED"
        elif pm.read_bytes(game.lpBaseOfDll + rva, length) == on:
            pm.write_bytes(game.lpBaseOfDll + rva, off, length)
            state = "DISABLED"
        else:
            state = "FAILED"

    print(state, title)


def patch_union(title, choice):
    p = patches["data"][title]["patches"]
    rva = int(p["rva"], 16)
    on = bytes.fromhex(p[choice])
    length = len(on)

    pm.write_bytes(game.lpBaseOfDll + rva, on, length)

    print("ENABLED", title, "to", choice)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="game.json", help="patch list")
    parser.add_argument("--launcher", default="bootstrap", help="bootstrap, launcher, spice")
    parser.add_argument("--delay", default=0, help="may be required at boot", type=float)
    args = parser.parse_args()

    with open(args.json, "r") as f:
        patches = json.load(f)

    exe = (args.launcher + ".exe" if not args.launcher.endswith(".exe") else args.launcher)
    dll = patches["info"]["file"]

    while True:
        try:
            pm = pymem.Pymem(exe)
            break
        except pymem.exception.ProcessNotFound:
            time.sleep(0.1)
    if args.delay != 0:
        time.sleep(args.delay)

    game = pymem.process.module_from_name(pm.process_handle, dll)

    for p in patches["data"]:
        # whitelist
        if p not in [
            "",
        ]:
            continue
        title = p
        patch_type = patches["data"][p]["type"]

        if patch_type == "default":
            patch(title)
        elif patch_type == "union":
            patch_union(title, choice)
        # elif patch_type == "number":
        #     patch_number(title, choice)

    pm.close_process()
