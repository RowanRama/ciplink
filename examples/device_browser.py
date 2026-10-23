"""Device browser in the style of RSWho (FactoryTalk Linx): find EtherNet/IP devices and browse through them.

Run from the repository root:  python -m examples.device_browser [address ...]

- Discover broadcasts ListIdentity on every network adapter and lists each EtherNet/IP device that answers.
- Add browses an address that discovery cannot reach, or a device behind a bridge, e.g. 10.0.0.5 or
  10.0.0.5/bp/2/enet/192.168.1.10 (the address of the EtherNet/IP module, then a route through it).
- Expand a device for its ports (backplane, EtherNet/IP, ControlNet, DeviceNet...), a port for the modules in
  each slot or the nodes on the network, and a module for its own ports, and so on down the routes.
  An EtherNet/IP port is scanned through the module: every address of its subnet (at most a /24) is asked for
  its identity, WORKERS at a time, and the devices that answer are listed as they are found.
- Select a row for its identity and the connection path to use with LogixDriver or CIPDriver.
  F5 browses the selected row again.
"""

import ctypes
import queue
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from contextlib import suppress
from tkinter import ttk

from ciplink import CIPDriver

LOADING = "Browsing..."
WORKERS = 32  # connections probing a port at once; each missing device costs the bridge's ~4 s timeout


def label(identity):
    return identity.get("product_name", "") if identity else ""


def address_key(address):
    """Slots and nodes sort as numbers, IP addresses by their numbers."""
    return tuple(int(part) for part in address.split(".") if part.isdigit())


def prefix_length(netmask):
    return bin(int.from_bytes(bytes(int(part) for part in netmask.split(".")), "big")).count("1")


def connection_path(ip, route):
    return f"{ip}/{route}" if route else ip


class DeviceBrowser:
    def __init__(self, root, addresses=()):
        self.root = root
        self.drivers, self.drivers_lock = {}, threading.Lock()  # ip -> open CIPDriver
        self.rows = {}  # tree row -> {"kind": "device"|"port"|"node", "ip", "route", "identity", "port", ...}
        self.loaded = set()  # rows whose children were browsed
        self.jobs, self.ui = queue.Queue(), queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

        self.px = root.winfo_fpixels("1i") / 96  # pixel sizes below are for 100% display scaling
        px = lambda n: int(n * self.px)
        root.title("Device Browser")
        root.geometry(f"{min(px(1100), root.winfo_screenwidth() - 60)}x{min(px(720), root.winfo_screenheight() - 100)}")
        self._style()

        top = ttk.Frame(root, padding=(px(12), px(10), px(12), px(8)))
        top.pack(fill="x")
        self.discover_btn = ttk.Button(top, text="Discover", width=10, command=self.discover)
        self.discover_btn.pack(side="left")
        ttk.Label(top, text="Address").pack(side="left", padx=(px(24), px(6)))
        self.address_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.address_var, width=40)
        entry.pack(side="left", padx=(0, px(6)), ipady=px(2))
        entry.bind("<Return>", lambda _: self.add())
        ttk.Button(top, text="Add", width=10, command=self.add).pack(side="left")

        self.status_var = tk.StringVar(value="Discover the devices on your networks, or Add one by address.")
        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel",
                  padding=(px(12), px(4))).pack(side="bottom", fill="x")

        panes = ttk.Panedwindow(root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=px(12))
        left = ttk.Frame(panes)
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse")
        self.tree.column("#0", width=px(560))
        self.tree.tag_configure("network", font=self.fonts["bold"])
        self.tree.tag_configure("port", foreground="#1f4e8c")
        self.tree.tag_configure("note", foreground="#8a8f98")
        scroll = ttk.Scrollbar(left, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewOpen>>", self._on_open)
        self.tree.bind("<<TreeviewSelect>>", lambda _: self._render())
        self.tree.bind("<F5>", lambda _: self._reload())
        self.network = self.tree.insert("", "end", text="EtherNet/IP", open=True, tags=("network",))

        right = ttk.Frame(panes)
        self.details = tk.Text(right, wrap="word", width=44, relief="flat", highlightthickness=0,
                               background="white", padx=px(16), pady=px(12), tabs=(px(150),),
                               font=self.fonts["normal"])
        for tag, options in (("title", {"font": self.fonts["title"], "spacing3": px(2)}),
                             ("muted", {"foreground": "#8a8f98"}),
                             ("section", {"font": self.fonts["section"], "foreground": "#5b6472",
                                          "spacing1": px(14), "spacing3": px(4)}),
                             ("label", {"foreground": "#5b6472"}),
                             ("value", {"font": self.fonts["mono"], "lmargin2": px(150)}),
                             ("error", {"foreground": "#b42318"})):
            self.details.tag_configure(tag, **options)
        self.details.pack(fill="both", expand=True)
        panes.add(left, weight=3)
        panes.add(right, weight=2)

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_ui()
        for address in addresses:
            self.add(address)

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
        }
        style = ttk.Style()
        style.configure("Treeview", rowheight=int(26 * self.px))
        style.configure("Muted.TLabel", foreground="#5b6472")

    # -- threading: the drivers are only used from the worker thread, Tk only from the UI thread

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

    def driver(self, ip):
        """The open driver of the device at ip (not on the UI thread); reopened after a connection error."""
        with self.drivers_lock:
            drv = self.drivers.get(ip)
            if drv is None or not drv.connected:
                drv = CIPDriver(ip)
                drv.open()
                self.drivers[ip] = drv
            return drv

    # -- adding devices

    def discover(self):
        self.discover_btn.state(["disabled"])
        self.status_var.set("Discovering EtherNet/IP devices...")
        self.jobs.put(self._discover)

    def _discover(self):
        try:
            devices = CIPDriver.discover()
            self.post(self._add_discovered, devices)
        finally:
            self.post(self.discover_btn.state, ["!disabled"])

    def _add_discovered(self, devices):
        known = {(self.rows[iid]["ip"], self.rows[iid]["route"]) for iid in self.tree.get_children(self.network)}
        for device in sorted(devices, key=lambda d: tuple(map(int, d["ip_address"].split(".")))):
            if (device["ip_address"], "") not in known:
                known.add((device["ip_address"], ""))
                self._device_row(device["ip_address"], "", device)
        self.status_var.set(f"Discovery found {len(devices)} device(s).")

    def add(self, address=None):
        address = (address or self.address_var.get()).strip().replace("\\", "/").strip("/")
        if not address:
            return
        ip, _, route = address.partition("/")
        iid = self._device_row(ip, route, None)
        self.tree.selection_set(iid)
        self.status_var.set(f"Reading the identity of {address}...")
        self.jobs.put(lambda: self._identify(iid, ip, route))

    def _identify(self, iid, ip, route):
        try:
            identity, error = self.driver(ip).get_identity(route), None
        except Exception as e:
            identity, error = None, str(e)
        self.post(self._set_identity, iid, identity, error)

    def _set_identity(self, iid, identity, error):
        if not self.tree.exists(iid):
            return
        row = self.rows[iid]
        row.update(identity=identity, error=error)
        self.tree.item(iid, text=self._device_text(row))
        self.status_var.set(error or f"{connection_path(row['ip'], row['route'])}: {label(identity)}")
        self._render()

    def _device_text(self, row):
        name = label(row["identity"]) or ("not reachable" if row.get("error") else "")
        return f"{connection_path(row['ip'], row['route'])}   {name}"

    def _device_row(self, ip, route, identity):
        row = {"kind": "device", "ip": ip, "route": route, "identity": identity}
        iid = self.tree.insert(self.network, "end")
        self.rows[iid] = row
        self.tree.item(iid, text=self._device_text(row))
        self.tree.insert(iid, "end", text=LOADING, tags=("note",))
        return iid

    # -- browsing: a device or module lists its ports, a port its slots or nodes

    def _on_open(self, _event):
        iid = self.tree.focus()
        if iid in self.rows and iid not in self.loaded:
            self._browse(iid)

    def _reload(self):
        iid = self.tree.focus()
        if iid in self.rows:
            self._browse(iid)
            self.tree.item(iid, open=True)

    def _browse(self, iid):
        """Browse a row's children again; jobs of an earlier browse of the row see a newer gen and stop."""
        self.loaded.add(iid)
        self.tree.delete(*self.tree.get_children(iid))
        self.tree.insert(iid, "end", text=LOADING, tags=("note",))
        row = self.rows[iid]
        row["gen"] = gen = row.get("gen", 0) + 1
        if row["kind"] == "port":
            self._browse_port(iid, row, gen)
        else:
            self.jobs.put(lambda: self._load_ports(iid, row, gen))

    def _load_ports(self, iid, row, gen):
        try:
            ports, error = self.driver(row["ip"]).get_ports(row["route"]), None
        except Exception as e:
            ports, error = [], str(e)
        self.post(self._show_ports, iid, row, gen, ports, error)

    def _show_ports(self, iid, row, gen, ports, error):
        if row["gen"] != gen or not self.tree.exists(iid):
            return
        self.tree.delete(*self.tree.get_children(iid))
        if error:
            self.tree.insert(iid, "end", text=f"Error: {error}", tags=("note",))
        elif not ports:
            self.tree.insert(iid, "end", text="No ports to browse", tags=("note",))
        for port in ports:
            name = port["name"] if port["name"] and port["name"] != port["type_name"] else ""
            subnet = f"   {port['ip']}/{prefix_length(port['netmask'])}" if port["ip"] else ""
            text = f"{name + ', ' if name else ''}{port['type_name']}{subnet}   (port {port['number']})"
            child = self.tree.insert(iid, "end", text=text, tags=("port",))
            self.rows[child] = {"kind": "port", "ip": row["ip"], "route": row["route"], "port": port,
                                "identity": row["identity"]}
            self.tree.insert(child, "end", text=LOADING, tags=("note",))

    def _browse_port(self, iid, row, gen):
        port = row["port"]
        if not port["nodes"]:
            self.tree.delete(*self.tree.get_children(iid))
            example = connection_path(row["ip"], row["route"]) + f"/{port['number']}/<address>"
            self.tree.insert(iid, "end", text=f"The port has no address to scan from: Add {example}",
                             tags=("note",))
            return
        row["scan"] = {"done": 0, "found": 0, "total": len(port["nodes"])}
        self._scan_progress(iid, row)
        threading.Thread(target=self._scan, args=(iid, row, gen), daemon=True).start()

    def _scan(self, iid, row, gen):
        """Probe every address of a port on a thread of its own, so other rows keep browsing meanwhile."""
        nodes = None
        try:
            nodes = self.driver(row["ip"]).iter_port(row["route"], row["port"], workers=WORKERS)
            for node in nodes:
                if row["gen"] != gen:
                    break  # browsed again or closed: closing the iterator drops the pending probes
                self.post(self._show_node, iid, row, gen, node)
        except Exception as error:
            self.post(self.status_var.set, f"Error: {error}")
        finally:
            if nodes is not None:
                nodes.close()

    def _scan_progress(self, iid, row):
        scan, port = row["scan"], row["port"]
        where = f"{port['type_name']} port {port['number']}" + (f" ({port['ip']})" if port["ip"] else "")
        text = f"{scan['done']} of {scan['total']} addresses, {scan['found']} found"
        children = self.tree.get_children(iid)
        if scan["done"] < scan["total"]:
            self.status_var.set(f"Browsing {where}: {text}...")
            if children and self.tree.item(children[-1], "text").startswith(LOADING):
                self.tree.item(children[-1], text=f"{LOADING} {text}")
            return
        self.status_var.set(f"Browsed {where}: {text}.")
        if children and self.tree.item(children[-1], "text").startswith(LOADING):
            self.tree.delete(children[-1])
            if not scan["found"]:
                self.tree.insert(iid, "end", text="No device answered", tags=("note",))

    def _show_node(self, iid, row, gen, node):
        if row["gen"] != gen or not self.tree.exists(iid):
            return
        scan = row["scan"]
        found = node["identity"] is not None
        scan["done"] += 1
        scan["found"] += found
        if found or row["port"]["type"] != 4:  # a network lists only the devices that answered, a chassis every slot
            key = address_key(node["address"])
            rows = [c for c in self.tree.get_children(iid) if self.rows.get(c, {}).get("kind") == "node"]
            index = sum(address_key(self.rows[c]["address"]) < key for c in rows)
            address = f"{int(node['address']):02d}" if node["address"].isdigit() else node["address"]
            child = self.tree.insert(iid, index, text=f"{address}   {label(node['identity']) if found else 'Empty'}",
                                     tags=() if found else ("note",))
            self.rows[child] = {"kind": "node", "ip": row["ip"], "route": node["route"], "address": node["address"],
                                "identity": node["identity"], "error": node["error"]}
            if found:
                self.tree.insert(child, "end", text=LOADING, tags=("note",))
            else:
                self.loaded.add(child)
        self._scan_progress(iid, row)

    # -- details

    def _render(self):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        selection = self.tree.selection()
        row = self.rows.get(selection[0]) if selection else None
        if row is None:
            self.details.insert("end", "EtherNet/IP\n", "title")
            self.details.insert("end", "Devices found by discovery or added by address.\n", "muted")
        elif row["kind"] == "port":
            port = row["port"]
            self.details.insert("end", f"{port['type_name']}\n", "title")
            self.details.insert("end", f"Port {port['number']} of {label(row['identity']) or row['ip']}\n", "muted")
            self._section("Port")
            self._row("Name", port["name"] or "-")
            self._row("Type", port["type"])
            self._row("This device's address", port["address"] or "-")
            nodes = port["nodes"]
            self._row("IP address", f"{port['ip']} / {port['netmask']}" if port["ip"] else "-")
            self._row("Scans", f"{nodes[0]} to {nodes[-1]} ({len(nodes)} addresses)" if nodes else "-")
            self._row("Route through it", connection_path(row["ip"], row["route"]) + f"/{port['number']}/<address>")
        else:
            identity = row["identity"]
            self.details.insert("end", (label(identity) or "No identity") + "\n", "title")
            self.details.insert("end", connection_path(row["ip"], row["route"]) + "\n", "muted")
            self._section("Connection path")
            self._row("Path", connection_path(row["ip"], row["route"]))
            if row.get("error"):
                self.details.insert("end", f"\n{row['error']}\n", "error")
            if identity:
                self._section("Identity")
                rev = identity.get("revision", {})
                for name, value in (("Vendor", identity.get("vendor")), ("Product type", identity.get("product_type")),
                                    ("Product code", identity.get("product_code")),
                                    ("Revision", f"{rev.get('major')}.{rev.get('minor')}"),
                                    ("Serial", identity.get("serial")),
                                    ("Status", (identity.get("status") or b"").hex()),
                                    ("IP address", identity.get("ip_address")), ("State", identity.get("state"))):
                    if value is not None:
                        self._row(name, value)
        self.details.configure(state="disabled")

    def _section(self, title):
        self.details.insert("end", title.upper() + "\n", "section")

    def _row(self, label, value):
        self.details.insert("end", f"{label}\t", "label")
        self.details.insert("end", f"{value}\n", "value")

    def _on_close(self):
        self.root.after_cancel(self._poll_job)
        for row in self.rows.values():
            row["gen"] = row.get("gen", 0) + 1  # stop running scans
        for drv in self.drivers.values():
            with suppress(Exception):
                drv.close()
        self.root.destroy()


def main():
    with suppress(Exception):
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on scaled Windows displays
    root = tk.Tk()
    DeviceBrowser(root, sys.argv[1:])
    root.mainloop()


if __name__ == "__main__":
    main()
