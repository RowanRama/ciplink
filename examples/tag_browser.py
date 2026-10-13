"""PLC tag browser: enter a PLC IP (or routing path) and browse every tag with live values and descriptions.

Run from the repository root:  python -m examples.tag_browser [ip]

Uploads controller and program tag definitions, then:
- re-reads the values of the rows on screen every second (expand UDTs, arrays and integers
  for their members, elements and bits)
- reads tag descriptions in the background using the bundled metadata credentials (see
  LogixDriver.authenticate_metadata); member, element and bit descriptions are read when expanded
Select a row for its full value and definition; select a folder for the controller's details.
"""

import ctypes
import math
import queue
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from contextlib import suppress
from tkinter import ttk

from pycomm3 import LogixDriver

MAX_ELEMENTS = 200  # array elements read and shown per array tag
DESC_CHUNK = 20  # descriptions read per worker job, so value reads can run in between
REFRESH_MS = 1000  # how often the values of the rows on screen are re-read
INT_BITS = {"SINT": 8, "INT": 16, "DINT": 32, "LINT": 64, "USINT": 8, "UINT": 16, "UDINT": 32, "ULINT": 64}


def type_and_dims(d):
    """Data type name and array dimensions of a tag or UDT member; BOOL arrays are stored as DWORDs."""
    name = d["data_type_name"]
    dims = list(d["dimensions"][:d["dim"]]) if "dim" in d else ([d["array"]] if d.get("array") else [])
    if name == "DWORD" and dims:
        name, dims = "BOOL", [dims[0] * 32] + dims[1:]
    return name, dims


def type_text(d):
    name, dims = type_and_dims(d)
    return name + (f"[{','.join(map(str, dims))}]" if dims else "")


def element_def(d):
    """Definition of one element of an array tag or member."""
    element = {k: v for k, v in d.items() if k not in ("dim", "dimensions", "array")}
    if type_and_dims(d)[0] == "BOOL":
        element.update(data_type="BOOL", data_type_name="BOOL", tag_type="atomic")
    return element


def is_struct(d):
    return d["tag_type"] == "struct" and "string" not in d["data_type"]


def bit_count(d):
    """Number of bits of an integer tag, member or element (0 for anything else)."""
    return 0 if type_and_dims(d)[1] else INT_BITS.get(d["data_type_name"], 0)


def read_path(name, d):
    """Read request for a whole base tag; arrays are read up to MAX_ELEMENTS."""
    dims = type_and_dims(d)[1]
    if not dims:
        return name
    return f"{name}[{','.join('0' * len(dims))}]{{{min(math.prod(dims), MAX_ELEMENTS)}}}"


def index_text(i, dims):
    """'[i]' or '[i,j]' label of flat element index i in an array with these dimensions."""
    index = []
    for size in reversed(dims[1:]):
        i, rest = divmod(i, size)
        index.insert(0, rest)
    return f"[{','.join(map(str, [i] + index))}]"


def flat(v):
    """BOOL arrays inside UDTs decode as lists of 32-bit words; flatten them to bits."""
    return [bit for word in v for bit in word] if isinstance(v, list) and v and isinstance(v[0], list) else v


def short(v):
    """A value as shown in the Value column, Studio 5000 style."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, float):
        s = f"{v:.7g}"
        return s if any(c in s for c in ".en") else s + ".0"
    if isinstance(v, str):
        return "'" + v.rstrip("\x00").replace("\r", "$R").replace("\n", "$N") + "'"
    if isinstance(v, (dict, list)):
        return "{...}"
    return str(v)


def text(v):
    if isinstance(v, dict):
        return ", ".join(f"{k}={text(x)}" for k, x in v.items())
    if isinstance(v, (list, tuple)):
        return ", ".join(map(text, v))
    return str(v)


def tag_order(name):
    """Controller tags first, then program tags grouped by program."""
    return name.startswith("Program:"), name.lower()


def definition(d):
    """The tag definition without the parsed type objects, plus the UDT template for structs."""
    view = {k: v for k, v in d.items() if k not in ("type_class", "data_type")}
    if d["tag_type"] == "struct":
        view["template"] = d["data_type"]["template"]
        view["members"] = d["data_type"]["attributes"]
    return view


class TagBrowser:
    def __init__(self, root, path=""):
        self.root = root
        self.plc = None
        self.gen = 0  # bumped on each connect so stale background jobs stop
        self.tags, self.info, self.desc, self.desc_err = {}, {}, {}, {}
        self.values = {}  # base tag -> (value, error) from its last read
        self.nodes, self.path_iid = {}, {}  # tree row -> {path, base, keys, def}; path -> tree row
        self.desc_enabled, self.desc_requested, self.desc_done, self.desc_total = False, set(), 0, 0
        self.selected = None
        self.refreshing = False
        self.tag_status = ""
        self._filter_job = None
        self.jobs, self.ui = queue.Queue(), queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

        self.px = root.winfo_fpixels("1i") / 96  # pixel sizes below are for 100% display scaling
        px = lambda n: int(n * self.px)
        root.title("PLC Tag Browser")
        root.geometry(f"{min(px(1400), root.winfo_screenwidth() - 60)}x{min(px(820), root.winfo_screenheight() - 100)}")
        self._style()

        top = ttk.Frame(root, padding=(px(12), px(10), px(12), px(4)))
        top.pack(fill="x")
        ttk.Label(top, text="PLC").pack(side="left")
        self.path_var = tk.StringVar(value=path)
        entry = ttk.Entry(top, textvariable=self.path_var, width=26)
        entry.pack(side="left", padx=(px(6), px(6)), ipady=px(2))
        entry.bind("<Return>", lambda _: self.connect())
        self.connect_btn = ttk.Button(top, text="Connect", width=10, command=self.connect)
        self.connect_btn.pack(side="left")
        ttk.Label(top, text="Filter").pack(side="left", padx=(px(24), px(6)))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._schedule_filter())
        ttk.Entry(top, textvariable=self.filter_var, width=32).pack(side="left", ipady=px(2))

        self.info_var = tk.StringVar(value="Not connected")
        ttk.Label(root, textvariable=self.info_var, style="Muted.TLabel",
                  padding=(px(12), 0, px(12), px(6))).pack(fill="x")
        self.status_var = tk.StringVar(
            value="Enter the PLC IP (add /slot for a ControlLogix not in slot 0) and press Connect.")
        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel",
                  padding=(px(12), px(4))).pack(side="bottom", fill="x")

        panes = ttk.Panedwindow(root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=px(12))
        left = ttk.Frame(panes)
        self.tree = ttk.Treeview(left, columns=("value", "type", "desc"), selectmode="browse")
        for col, heading, width, stretch in (("#0", "Name", 280, False), ("value", "Value", 170, False),
                                             ("type", "Data Type", 150, False), ("desc", "Description", 320, True)):
            self.tree.heading(col, text=heading, anchor="w")
            self.tree.column(col, width=px(width), minwidth=px(60), stretch=stretch)
        self.tree.tag_configure("folder", font=self.fonts["bold"], background="#e8edf4")
        self.tree.tag_configure("odd", background="#f5f7fa")
        self.tree.tag_configure("note", foreground="#8a8f98")
        scroll = ttk.Scrollbar(left, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<<TreeviewClose>>", lambda _: self.root.after_idle(self._restripe))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        right = ttk.Frame(panes)
        self.details = tk.Text(right, wrap="word", width=46, relief="flat", highlightthickness=0,
                               background="white", padx=px(16), pady=px(12), tabs=(px(170),),
                               font=self.fonts["normal"], cursor="arrow")
        for tag, options in (("title", {"font": self.fonts["title"], "spacing3": px(2)}),
                             ("muted", {"foreground": "#8a8f98"}),
                             ("section", {"font": self.fonts["section"], "foreground": "#5b6472",
                                          "spacing1": px(14), "spacing3": px(4)}),
                             ("label", {"foreground": "#5b6472"}),
                             ("value", {"font": self.fonts["mono"], "lmargin2": px(170)}),  # wrap under the value
                             ("big", {"font": self.fonts["big"]}),
                             ("error", {"foreground": "#b42318"})):
            self.details.tag_configure(tag, **options)
        details_scroll = ttk.Scrollbar(right, command=self.details.yview)
        self.details.configure(yscrollcommand=details_scroll.set)
        details_scroll.pack(side="right", fill="y")
        self.details.pack(fill="both", expand=True)
        panes.add(left, weight=3)
        panes.add(right, weight=1)

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_ui()
        self._refresh_tick()
        if path:
            self.connect()

    def _style(self):
        family = "Segoe UI" if "Segoe UI" in tkfont.families() else "TkDefaultFont"
        for name in ("TkDefaultFont", "TkTextFont", "TkHeadingFont"):
            tkfont.nametofont(name).configure(family=family, size=10)
        self.fonts = {
            "normal": tkfont.Font(family=family, size=10),
            "bold": tkfont.Font(family=family, size=10, weight="bold"),
            "title": tkfont.Font(family=family, size=14, weight="bold"),
            "section": tkfont.Font(family=family, size=8, weight="bold"),
            "mono": tkfont.Font(family="Consolas", size=10),
            "big": tkfont.Font(family="Consolas", size=16),
        }
        style = ttk.Style()
        style.configure("Treeview", rowheight=int(26 * self.px))
        style.configure("Treeview.Heading", font=self.fonts["bold"], padding=(int(4 * self.px), int(4 * self.px)))
        style.configure("Muted.TLabel", foreground="#5b6472")

    # -- threading: the driver is only used from the worker thread, Tk only from the UI thread

    def _worker(self):
        while True:
            job = self.jobs.get()
            try:
                job()
            except Exception as error:
                self.post(self.status_var.set, f"Error: {error}")

    def post(self, fn, *args):
        """Queue a UI update from the worker thread (Tk is not thread-safe)."""
        self.ui.put((fn, args))

    def _poll_ui(self):
        with suppress(queue.Empty):
            while True:
                fn, args = self.ui.get_nowait()
                fn(*args)
        self._poll_job = self.root.after(50, self._poll_ui)

    # -- connecting, descriptions and values

    def connect(self):
        path = self.path_var.get().strip()
        if not path:
            return
        self.gen += 1
        gen = self.gen
        self.tags, self.info, self.desc, self.desc_err, self.values = {}, {}, {}, {}, {}
        self.desc_enabled, self.desc_requested, self.desc_done, self.desc_total = False, set(), 0, 0
        self._build_tree()
        self._render()
        self.info_var.set("Not connected")
        self.status_var.set(f"Connecting to {path} and uploading tags...")
        self.connect_btn.state(["disabled"])
        self.jobs.put(lambda: self._connect(path, gen))

    def _connect(self, path, gen):
        try:
            if self.plc:
                with suppress(Exception):
                    self.plc.close()
                self.plc = None
            plc = LogixDriver(path)  # uploads controller and program tag definitions on open
            plc.open()
            self.plc = plc
            self.post(self._show_tags, plc.info, plc.tags)
            auth = plc.authenticate_metadata()  # descriptions need an authenticated connection
            if not auth:
                self.post(self._set_desc_status, f"descriptions unavailable: {auth.error}")
                return
            self.post(self._enable_descriptions, gen)
        finally:
            self.post(self.connect_btn.state, ["!disabled"])

    def _show_tags(self, info, tags):
        self.info, self.tags = info, tags
        rev = info.get("revision", {})
        self.info_var.set(f"{info.get('product_name')}   ·   v{rev.get('major')}.{rev.get('minor')}   ·   "
                          f"{info.get('keyswitch')}   ·   {info.get('name')}   ·   SN {info.get('serial')}")
        programs = sum(name.startswith("Program:") for name in tags)
        self.tag_status = f"{len(tags)} tags ({len(tags) - programs} controller, {programs} program)"
        self._set_desc_status("reading descriptions...")
        self._build_tree()

    def _enable_descriptions(self, gen):
        if gen == self.gen:
            self.desc_enabled = True
            self._queue_descriptions(sorted(self.tags, key=tag_order))

    def _queue_descriptions(self, paths):
        """Read the descriptions of these tags, members or elements in the background."""
        paths = [path for path in paths if path not in self.desc_requested]
        if self.desc_enabled and paths:
            self.desc_requested.update(paths)
            self.desc_total += len(paths)
            gen = self.gen
            self.jobs.put(lambda: self._load_descriptions(gen, paths, 0))

    def _load_descriptions(self, gen, paths, start):
        if gen != self.gen:
            return
        found, errors = {}, {}
        chunk = paths[start:start + DESC_CHUNK]
        for path in chunk:
            result = self.plc.get_tag_description(path)
            if result:
                found[path] = result.value
            elif not str(result.error).startswith("No description returned"):
                errors[path] = str(result.error)
        self.post(self._apply_descriptions, gen, found, errors, len(chunk))
        if start + DESC_CHUNK < len(paths):
            self.jobs.put(lambda: self._load_descriptions(gen, paths, start + DESC_CHUNK))

    def _apply_descriptions(self, gen, found, errors, count):
        if gen != self.gen:
            return
        self.desc.update(found)
        self.desc_err.update(errors)
        self.desc_done += count
        for path in found:
            if path in self.path_iid:
                iid = self.path_iid[path]
                self.tree.set(iid, "desc", self._desc_cell(self.tree.parent(iid), path))
        node = self.nodes.get(self.selected)
        if node and (node["path"] in found or node["path"] in errors):
            self._render(keep_scroll=True)
        progress = "done" if self.desc_done == self.desc_total else f"{self.desc_done}/{self.desc_total}"
        self._set_desc_status(f"descriptions {progress}: {len(self.desc)} found, {len(self.desc_err)} errors")

    def _set_desc_status(self, status):
        self.status_var.set(f"{self.tag_status}   |   {status}")

    def _refresh_tick(self):
        """Every REFRESH_MS, re-read the base tags of the rows on screen."""
        if self.tags and not self.refreshing:
            bases = dict.fromkeys(self.nodes[i]["base"] for i in self._visible_rows() if i in self.nodes)
            if bases:
                self.refreshing = True
                requests, gen = [(b, read_path(b, self.tags[b])) for b in bases], self.gen
                self.jobs.put(lambda: self._read_values(gen, requests))
        self._refresh_job = self.root.after(REFRESH_MS, self._refresh_tick)

    def _read_values(self, gen, requests):
        try:
            if gen != self.gen:
                return
            results = self.plc.read(*(path for _, path in requests))
            if len(requests) == 1:
                results = [results]
            values = {base: (r.value, None) if r else (None, str(r.error)) for (base, _), r in zip(requests, results)}
            self.post(self._apply_values, gen, values)
        finally:
            self.post(setattr, self, "refreshing", False)

    def _apply_values(self, gen, values):
        if gen != self.gen:
            return
        self.values.update(values)
        for iid in self._visible_rows():
            node = self.nodes.get(iid)
            if node and node["base"] in values:
                self.tree.set(iid, "value", self._cell(node))
        node = self.nodes.get(self.selected)
        if node and node["base"] in values:
            self._render(keep_scroll=True)

    def _value(self, node):
        """(value, error) of a row, taken from its base tag's last read."""
        value, error = self.values.get(node["base"], (None, None))
        for key in node["keys"]:
            try:
                value = flat(value)[key]
            except (KeyError, IndexError, TypeError):
                return None, error
        if node["bit"] is not None:
            return (bool(value >> node["bit"] & 1) if isinstance(value, int) else None), error
        return flat(value), error

    def _cell(self, node):
        value, error = self._value(node)
        return "(error)" if error else short(value)

    # -- tree

    def _visible_rows(self):
        step = max(1, int(13 * self.px))
        rows = (self.tree.identify_row(y) for y in range(0, self.tree.winfo_height(), step))
        return list(dict.fromkeys(row for row in rows if row))

    def _schedule_filter(self):
        if self._filter_job:
            self.root.after_cancel(self._filter_job)
        self._filter_job = self.root.after(250, self._build_tree)

    def _build_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.nodes.clear()
        self.path_iid.clear()
        self.selected = None
        query = self.filter_var.get().strip().lower()
        folders = {}
        for name in sorted(self.tags, key=tag_order):
            d = self.tags[name]
            if query and not any(query in s.lower() for s in (name, type_text(d), self.desc.get(name, ""))):
                continue
            scope, short_name = name.split(".", 1) if name.startswith("Program:") else ("", name)
            if scope not in folders:
                folders[scope] = self.tree.insert("", "end", text=scope or "Controller Tags",
                                                  open=bool(query) or not scope)
            self._insert(folders[scope], short_name, name, name, (), d)
        self._restripe()

    def _insert(self, parent, label, path, base, keys, d, bit=None):
        node = {"path": path, "base": base, "keys": keys, "def": d, "bit": bit}
        desc = self._desc_cell(parent, path)
        iid = self.tree.insert(parent, "end", text=label, values=(self._cell(node), type_text(d), desc))
        self.nodes[iid] = node
        self.path_iid[path] = iid
        if type_and_dims(d)[1] or is_struct(d) or bit_count(d):
            self.tree.insert(iid, "end")  # placeholder; elements/members/bits are added when expanded
        return iid

    def _desc_cell(self, parent, path):
        """Description column text; blank when a row only passes through its parent row's description."""
        desc = self.desc.get(path, "")
        owner = self.nodes.get(parent)
        return "" if owner and desc == self.desc.get(owner["path"]) else desc.replace("\n", " ")

    def _on_open(self, _):
        iid = self.tree.focus()
        children = self.tree.get_children(iid)
        if children and children[0] not in self.nodes:
            self.tree.delete(children[0])
            node = self.nodes[iid]
            d = node["def"]
            dims = type_and_dims(d)[1]
            if dims:
                element, count = element_def(d), math.prod(dims)
                for i in range(min(count, MAX_ELEMENTS)):
                    index = index_text(i, dims)
                    self._insert(iid, index, node["path"] + index, node["base"], node["keys"] + (i,), element)
                if count > MAX_ELEMENTS:
                    self.tree.insert(iid, "end", text=f"... {count - MAX_ELEMENTS} more elements not shown")
            elif is_struct(d):
                data_type = d["data_type"]
                for member in data_type["attributes"]:
                    self._insert(iid, member, f"{node['path']}.{member}", node["base"], node["keys"] + (member,),
                                 data_type["internal_tags"][member])
            else:  # an integer: one BOOL row per bit
                for bit in range(bit_count(d)):
                    bit_def = {"data_type": "BOOL", "data_type_name": "BOOL", "tag_type": "atomic", "bit": bit}
                    self._insert(iid, f".{bit}", f"{node['path']}.{bit}", node["base"], node["keys"], bit_def, bit)
            self._queue_descriptions([self.nodes[c]["path"] for c in self.tree.get_children(iid) if c in self.nodes])
        self.root.after_idle(self._restripe)

    def _restripe(self):
        """Zebra-stripe the rows shown; expanding or collapsing changes which rows are odd."""
        def walk(parent, row):
            for iid in self.tree.get_children(parent):
                if parent == "":
                    tags = ("folder",)
                else:
                    tags = ("odd",) if row % 2 else ()
                    if iid not in self.nodes:
                        tags += ("note",)
                self.tree.item(iid, tags=tags)
                row += 1
                if self.tree.item(iid, "open"):
                    row = walk(iid, row)
            return row
        walk("", 0)

    def _on_select(self, _):
        selection = self.tree.selection()
        self.selected = selection[0] if selection else None
        self._render()

    # -- details pane

    def _render(self, keep_scroll=False):
        top = self.details.yview()[0]
        self.details.delete("1.0", "end")
        node = self.nodes.get(self.selected)
        if node:
            self._render_node(node)
        elif self.info and self.selected and self.tree.parent(self.selected) == "":  # a scope folder
            self._render_info()
        if keep_scroll:
            self.details.yview_moveto(top)

    def _render_node(self, node):
        t, d, base = self.details, node["def"], node["base"]
        value, error = self._value(node)
        t.insert("end", node["path"] + "\n", "title")
        desc = self.desc.get(node["path"])
        t.insert("end", (desc or "No description") + "\n", () if desc else "muted")

        self._section("Value")
        if error:
            t.insert("end", error + "\n", "error")
        elif isinstance(value, (dict, list)):
            dims = type_and_dims(d)[1] or [len(value)]
            items = value.items() if isinstance(value, dict) else ((index_text(i, dims), v) for i, v in enumerate(value))
            for key, v in items:
                self._row(key, short(v))
            if isinstance(value, list) and math.prod(dims) > len(value):
                t.insert("end", f"first {len(value)} of {math.prod(dims)} elements\n", "muted")
        elif value is None:
            t.insert("end", "reading...\n", "muted")
        else:
            t.insert("end", (repr(value) if isinstance(value, float) else short(value)) + "\n", "big")

        self._section("Properties")
        self._row("Data type", type_text(d))
        self._row("Scope", base.split(".", 1)[0] if base.startswith("Program:") else "Controller")
        self._row("External access", self.tags[base]["external_access"])
        if node["path"] in self.desc_err:
            self._row("Description error", self.desc_err[node["path"]])
        for key, v in definition(d).items():  # dims are already in the data type
            if key not in ("tag_name", "data_type_name", "external_access", "dim", "dimensions"):
                self._row(key.replace("_", " ").capitalize(), ("Yes" if v else "No") if key == "alias" else text(v))

    def _render_info(self):
        t, info = self.details, self.info
        t.insert("end", f"{info.get('product_name')}\n", "title")
        t.insert("end", f"{info.get('vendor')}\n", "muted")
        self._section("Controller")
        for key, v in info.items():
            if key == "revision":
                v = f"{v.get('major')}.{v.get('minor')}"
            if key not in ("programs", "tasks", "modules", "status", "vendor"):
                self._row(key.replace("_", " ").capitalize(), text(v))
        self._section("Programs")
        for name, program in info.get("programs", {}).items():
            self._row(name, ", ".join(program["routines"]))
        self._section("Tasks")
        for name, task in info.get("tasks", {}).items():
            self._row(name, f"instance {task['instance_id']}")
        self._section("I/O modules")
        for name, module in info.get("modules", {}).items():
            slots = [f"slot {n}: {'/'.join(s['types'])}" for n, s in module.get("slots", {}).items()]
            self._row(name, ", ".join(slots + ["/".join(module.get("types", []))]).strip(", "))

    def _section(self, title):
        self.details.insert("end", title.upper() + "\n", "section")

    def _row(self, label, value):
        self.details.insert("end", f"{label}\t", "label")
        self.details.insert("end", f"{value}\n", "value")

    def _on_close(self):
        self.gen += 1  # stop queued background jobs
        self.root.after_cancel(self._poll_job)
        self.root.after_cancel(self._refresh_job)
        if self.plc:
            with suppress(Exception):
                self.plc.close()
        self.root.destroy()


def main():
    with suppress(Exception):
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on scaled Windows displays
    root = tk.Tk()
    TagBrowser(root, sys.argv[1] if len(sys.argv) > 1 else "")
    root.mainloop()


if __name__ == "__main__":
    main()
