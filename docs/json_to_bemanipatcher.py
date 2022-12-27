import json
from pathlib import Path


def json_to_bemanipatcher(json_prefix, out_name):
    def formatted(value):
        return "[%s]" % ", ".join(
            map(
                str,
                ["0x" + (value[i : i + 2].upper()) for i in range(0, len(value), 2)],
            )
        )

    dates = []
    out = []
    for j in Path(".").glob(f"{json_prefix}*.json"):
        # DDR and GITADORA can conflict
        if json_prefix == "game" and str(j).startswith("gamemdx"):
            continue
        with open(j, "r") as f:
            patches = json.load(f)

        title = patches["info"]["title"]
        dll = patches["info"]["file"]
        d = patches["info"]["datecode"]
        if len(d) == 10 and d.isdigit():
            d = "-".join([d[:4], d[4:6], d[6:8], d[8:]])
            date = d[:-3] if d[-3:] == "-00" else d
        else:
            date = d

        header = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>{title} DLL Modder</title>
    <link rel="stylesheet" href="css/style.css" />
    <script type="text/javascript" src="js/dllpatcher.js"></script>
    <script type="text/javascript">
        window.addEventListener("load", function () {{
            new PatchContainer(["""

        footer = f"""
            ]);
        }});
    </script>
  </head>
  <body>
    <h1>{title} DLL Modder</h1>
  </body>
</html>"""

        out.append(f'new Patcher("{dll}", "{date}", [')

        for k in patches["data"]:
            # print(k)
            tip = patches["data"][k]["tooltip"]
            v = patches["data"][k]["patches"]
            if patches["data"][k]["type"] == "default":
                out.append("    {")
                out.append(f'        name: "{k}",')
                if tip is not None:
                    out.append(f'        tooltip: "{tip}",')
                if len(v) == 1:
                    out.append(
                        f"        patches: [{{ offset: {v[0]['offset']}, off: {formatted(v[0]['off'])}, on: {formatted(v[0]['on'])} }}],"
                    )
                    out.append(("    },"))
                else:
                    out.append(f"        patches: [")
                    for x in v:
                        out.append(
                            f"            {{ offset: {x['offset']}, off: {formatted(x['off'])}, on: {formatted(x['on'])} }},"
                        )
                    out.append("        ]")
                    out.append("    },")
            elif patches["data"][k]["type"] == "union":
                out.append("    {")
                out.append('        type : "union",')
                out.append(f'        name : "{k}",')
                out.append(f"        offset : {v['offset']},")
                out.append("        patches : [")
                for x in v:
                    if x not in ("offset", "rva"):
                        out.append("            {")
                        out.append(f'                name : "{x}",')
                        out.append(f"                patch : {formatted(v[x])},")
                        out.append("            },")
                out.append("        ]")
                out.append("    },")
            elif patches["data"][k]["type"] == "number":
                out.append("    {")
                out.append('        type : "number",')
                out.append(f'        name : "{k}",')
                out.append(f"        offset : {v['offset']},")
                out.append(f"        size : {v['size']},")
                out.append(f"        min : {v['min']},")
                out.append(f"        max : {v['max']},")
                out.append("    },")
        out.append("]),")
        dates.append(date)

    out.insert(0, header)
    out.append(footer)

    with open(f"{out_name}.html", "w", newline="\n") as f:
        out = "\n                ".join(map(str, out))
        f.write("".join([s for s in out.strip().splitlines(True) if s.strip()]))
        print(f"{out_name}.html", dates)


if __name__ == "__main__":
    json_to_bemanipatcher("game", "gitadora")
