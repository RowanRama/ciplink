"""
Converts a Studio 5000 L5X export into a ciplink-sim controller configuration (JSON).

    python tools/sim/l5x_to_config.py project.L5X -o controller.json [--revision 33.11]
        [--product-name 1756-SIM/A] [--product-code 166] [--serial c0ffee01] [--keyswitch "REMOTE RUN"]
        [--aoi-locals-readable]

Takes the data types (UDTs, string types, AOIs with their parameters and local tags), the controller and program
tags with their values (each tag's raw memory image, the ``<Data>`` element without a format), the programs and
their routines, and the tasks.  Alias tags and InOut AOI parameters (references, not data) are left out, and I/O
module tags only exist in a full project export with their module types, which this does not convert.  The
simulator computes each type's layout itself and refuses a tag whose raw image does not fit it, so a project
that loads has the controller's layouts.

``--aoi-locals-readable`` lets clients read an AOI's local tags (older firmware did, e.g. v20).
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET

ENABLE = {"EnableIn", "EnableOut"}


def dims(text):
    return [int(d) for d in (text or "").replace(",", " ").split() if int(d)]


def member(name, data_type, dim=0, access="Read/Write", local=False):
    out = {"name": name, "type": "BOOL" if data_type == "BIT" else data_type}
    if dim:
        out["dim"] = dim
    if local:
        out["local"] = True
    if access and access != "Read/Write":
        out["external_access"] = access
    return out


def data_type(element):
    name = element.get("Name")
    members = element.find("Members")
    if element.get("Family") == "StringFamily":
        length = next(int(m.get("Dimension")) for m in members if m.get("Name") == "DATA")
        return {"name": name, "string": length}
    out = []
    for m in members:
        hidden_host = m.get("Hidden") == "true" and m.get("Name", "").startswith("ZZZZZZZZZZ")
        if not hidden_host:  # the simulator lays out the BOOL hosts itself
            out.append(member(m.get("Name"), m.get("DataType"), int(m.get("Dimension") or 0),
                              m.get("ExternalAccess")))
    return {"name": name, "members": out}


def aoi(element):
    out = []
    for p in element.findall("Parameters/Parameter"):
        if p.get("Name") in ENABLE or p.get("Usage") == "InOut":  # InOut parameters are references
            continue
        dim = dims(p.get("Dimension") or p.get("Dimensions"))
        out.append(member(p.get("Name"), p.get("DataType"), dim[0] if dim else 0, p.get("ExternalAccess")))
    for t in element.findall("LocalTags/LocalTag"):
        dim = dims(t.get("Dimension") or t.get("Dimensions"))
        out.append(member(t.get("Name"), t.get("DataType"), dim[0] if dim else 0, t.get("ExternalAccess"),
                          local=True))
    return {"name": element.get("Name"), "aoi": True, "members": out}


def tags(parent, skipped):
    out = []
    for t in parent.findall("Tags/Tag"):
        if t.get("TagType") == "Alias":
            skipped.append(t.get("Name"))
            continue
        tag = {"name": t.get("Name"), "type": t.get("DataType")}
        if dims(t.get("Dimensions")):
            tag["dims"] = dims(t.get("Dimensions"))
        access = t.get("ExternalAccess", "Read/Write")
        if t.get("Constant") == "true" and access == "Read/Write":
            access = "Read Only"  # a constant is not writable
        if access != "Read/Write":
            tag["external_access"] = access
        raw = next((d.text for d in t.findall("Data") if d.get("Format") is None and d.text), None)
        if raw:
            tag["raw"] = " ".join(raw.split())
        out.append(tag)
    return out


def convert(path, revision="20.19", product_name=None, product_code=None, serial="c0ffee01",
            keyswitch="REMOTE RUN", aoi_locals_readable=False):
    root = ET.parse(path).getroot()
    controller = root.find("Controller")
    skipped = []
    major, minor = (int(x) for x in revision.split("."))
    config = {
        "kind": "logix",
        "identity": {
            "revision": [major, minor],
            "serial": serial,
            "product_name": product_name or controller.get("ProcessorType") or "1756-SIM/A",
            "keyswitch": keyswitch,
        },
        "program_name": controller.get("Name"),
        "types": [data_type(d) for d in controller.findall("DataTypes/DataType")]
                 + [aoi(a) for a in controller.findall("AddOnInstructionDefinitions/AddOnInstructionDefinition")],
        "tags": tags(controller, skipped),
        "programs": [
            {"name": p.get("Name"), "routines": [r.get("Name") for r in p.findall("Routines/Routine")],
             "tags": tags(p, skipped)}
            for p in controller.findall("Programs/Program")
        ],
        "tasks": [{"name": t.get("Name")} for t in controller.findall("Tasks/Task")],
    }
    if product_code is not None:
        config["identity"]["product_code"] = product_code
    if aoi_locals_readable:
        config["aoi_locals_refused"] = False
    return config, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("l5x")
    parser.add_argument("-o", "--output", help="output file, standard output if omitted")
    parser.add_argument("--revision", default="20.19", help="major.minor firmware revision, e.g. 33.11")
    parser.add_argument("--product-name")
    parser.add_argument("--product-code", type=int)
    parser.add_argument("--serial", default="c0ffee01")
    parser.add_argument("--keyswitch", default="REMOTE RUN")
    parser.add_argument("--aoi-locals-readable", action="store_true")
    args = parser.parse_args()
    config, skipped = convert(args.l5x, args.revision, args.product_name, args.product_code, args.serial,
                              args.keyswitch, args.aoi_locals_readable)
    if skipped:
        print(f"left out {len(skipped)} alias tags: {', '.join(skipped)}", file=sys.stderr)
    text = json.dumps(config, indent=1)
    if args.output:
        with open(args.output, "w", newline="\n") as f:
            f.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
