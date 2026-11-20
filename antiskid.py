
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Any

from antiskid_core import (
    APP_VERSION, CollectionBundle, CollectionNote, ForensicEvent,
    collect_baseline, collect_system_info, collect_usb_history,
    collect_windows_event_logs, scan_directory,
)
from antiskid_reports import export_csv_report, export_html_report

BG = "#211d26"
PANEL = "#302b35"
PANEL_DARK = "#25212a"
PANEL_LIGHT = "#403a46"
BORDER = "#716a79"
TEXT = "#eeeaf2"
MUTED = "#b8b0bf"
ACCENT = "#cbbfda"
GREEN = "#91bd9b"
AMBER = "#d6b66f"
RED = "#d77b7b"
FONT = ("Consolas", 9)
FONT_BOLD = ("Consolas", 9, "bold")
FONT_TITLE = ("Consolas", 18, "bold")

class AntiSkidApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"AntiSkid {APP_VERSION} — Digital Forensics")
        self.configure(bg=BG)
        self.geometry("1280x820")
        self.minsize(1040, 680)
        self.option_add("*Font", FONT)
        self.bundle = CollectionBundle()
        self.file_records: list[dict[str, Any]] = []
        self.task_queue: queue.Queue = queue.Queue()
        self.busy = False
        self.case_name = tk.StringVar(value="Local endpoint triage")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="READY // No collection has been started.")
        self._closing = False
        self._maximized = False
        self._drag_origin: tuple[int, int] | None = None
        self._configure_styles()
        # The built-in menu row is deliberately removed. Windows receives a
        # custom in-app title strip so no white native caption/menu remains.
        self.configure(menu="")
        self._build_shell()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if os.name == "nt":
            self.after(90, self._remove_native_caption)
        self.after(120, self._poll_queue)
        self.show_page("Overview")
        self._refresh_all()
        if os.name != "nt":
            self.status_var.set("PORTABLE MODE // Windows-only evidence sources are unavailable on this OS.")

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Anti.Treeview", background=PANEL_DARK, foreground=TEXT,
            fieldbackground=PANEL_DARK, bordercolor=BORDER,
            rowheight=25, font=FONT,
        )
        style.configure(
            "Anti.Treeview.Heading", background=PANEL_LIGHT,
            foreground=TEXT, relief="raised", borderwidth=2,
            font=FONT_BOLD, padding=(7, 6),
        )
        style.map(
            "Anti.Treeview",
            background=[("selected", "#51475d")],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Anti.TNotebook", background=BG, borderwidth=2, tabmargins=(3, 3, 3, 0)
        )
        style.configure(
            "Anti.TNotebook.Tab", background=PANEL, foreground=MUTED,
            padding=(12, 7), borderwidth=2, font=FONT_BOLD,
        )
        style.map(
            "Anti.TNotebook.Tab",
            background=[("selected", PANEL_LIGHT)],
            foreground=[("selected", TEXT)],
        )
        style.configure("Anti.Vertical.TScrollbar", background=PANEL_LIGHT, troughcolor=PANEL_DARK, bordercolor=BORDER, arrowsize=13)
        style.configure("Anti.Horizontal.TScrollbar", background=PANEL_LIGHT, troughcolor=PANEL_DARK, bordercolor=BORDER, arrowsize=13)

    def _remove_native_caption(self) -> None:
        """Hide the Windows title bar while preserving a normal taskbar window."""
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes
            hwnd = wintypes.HWND(self.winfo_id())
            user32 = ctypes.windll.user32
            GWL_STYLE = -16
            WS_CAPTION = 0x00C00000
            SWP_NOSIZE = 0x0001
            SWP_NOMOVE = 0x0002
            SWP_NOZORDER = 0x0004
            SWP_FRAMECHANGED = 0x0020
            get_long = user32.GetWindowLongW
            get_long.argtypes = (wintypes.HWND, ctypes.c_int)
            get_long.restype = ctypes.c_long
            set_long = user32.SetWindowLongW
            set_long.argtypes = (wintypes.HWND, ctypes.c_int, ctypes.c_long)
            set_long.restype = ctypes.c_long
            set_pos = user32.SetWindowPos
            set_pos.argtypes = (
                wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                ctypes.c_int, ctypes.c_int, wintypes.UINT,
            )
            set_pos.restype = wintypes.BOOL
            style = get_long(hwnd, GWL_STYLE)
            set_long(hwnd, GWL_STYLE, style & ~WS_CAPTION)
            if not set_pos(
                hwnd, None, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
            ):
                raise ctypes.WinError()
        except Exception as exc:
            self.status_var.set(f"WINDOW STYLE WARNING // Native caption could not be hidden: {exc}")

    def _start_window_drag(self, event: tk.Event) -> None:
        try:
            if self.state() == "zoomed":
                return
            self._drag_origin = (event.x_root - self.winfo_x(), event.y_root - self.winfo_y())
        except tk.TclError:
            self._drag_origin = None

    def _move_window_drag(self, event: tk.Event) -> None:
        if self._drag_origin is None or self.state() == "zoomed":
            return
        x = event.x_root - self._drag_origin[0]
        y = event.y_root - self._drag_origin[1]
        self.geometry(f"+{x}+{y}")

    def _toggle_maximize(self) -> None:
        try:
            if self.state() == "zoomed":
                self.state("normal")
                self.geometry("1280x820")
            else:
                self.state("zoomed")
        except tk.TclError as exc:
            self.status_var.set(f"WINDOW CONTROL WARNING // {exc}")

    def _on_close(self) -> None:
        if self.busy:
            should_close = messagebox.askyesno(
                "AntiSkid is collecting",
                "A collection task is still running. Close AntiSkid and discard its unfinished in-memory results?",
                parent=self,
            )
            if not should_close:
                return
        self._closing = True
        try:
            self.destroy()
        except tk.TclError:
            pass

    def _retro_button(self, parent: tk.Widget, text: str, command, *, width: int = 14, accent: bool = False) -> tk.Button:
        bg = "#46404e" if accent else PANEL
        return tk.Button(
            parent, text=text, command=command, width=width,
            bg=bg, fg=TEXT, activebackground="#5a5065",
            activeforeground="#ffffff", relief="raised", bd=3,
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT, padx=6, pady=5,
            font=FONT_BOLD, cursor="hand2",
        )

    def _panel(self, parent: tk.Widget, *, padx: int = 8, pady: int = 8) -> tk.Frame:
        frame = tk.Frame(
            parent, bg=PANEL, bd=3, relief="ridge",
            highlightthickness=1, highlightbackground=BORDER,
        )
        frame.pack_propagate(True)
        return frame

    def _label(self, parent: tk.Widget, text: str, *, size: int = 9, color: str = TEXT, bold: bool = False, **kwargs) -> tk.Label:
        return tk.Label(
            parent, text=text, bg=kwargs.pop("bg", PANEL), fg=color,
            font=("Consolas", size, "bold" if bold else "normal"),
            anchor=kwargs.pop("anchor", "w"), **kwargs,
        )

    def _build_shell(self) -> None:
        top = tk.Frame(self, bg=PANEL_DARK, bd=3, relief="raised")
        top.pack(fill="x", padx=8, pady=(8, 5))
        window_controls = tk.Frame(top, bg=PANEL_DARK)
        window_controls.pack(side="right", padx=(5, 8), pady=6)
        minimize = self._retro_button(window_controls, "_", self.iconify, width=3)
        minimize.pack(side="left", padx=2)
        maximize = self._retro_button(window_controls, "□", self._toggle_maximize, width=3)
        maximize.pack(side="left", padx=2)
        close = tk.Button(
            window_controls, text="X", command=self._on_close, width=3,
            bg="#713b45", fg="#ffffff", activebackground="#944b57",
            activeforeground="#ffffff", relief="raised", bd=3,
            highlightthickness=1, highlightbackground=BORDER,
            font=FONT_BOLD, cursor="hand2",
        )
        close.pack(side="left", padx=2)
        brand = tk.Frame(top, bg=PANEL_DARK)
        brand.pack(side="left", padx=10, pady=6)
        self._label(brand, "ANTISKID", size=17, color=ACCENT, bold=True, bg=PANEL_DARK).pack(anchor="w")
        self._label(brand, "DIGITAL FORENSICS // LOCAL ENDPOINT TRIAGE", size=8, color=MUTED, bg=PANEL_DARK).pack(anchor="w")
        for drag_widget in (top, brand):
            drag_widget.bind("<ButtonPress-1>", self._start_window_drag)
            drag_widget.bind("<B1-Motion>", self._move_window_drag)
        for child in brand.winfo_children():
            child.bind("<ButtonPress-1>", self._start_window_drag)
            child.bind("<B1-Motion>", self._move_window_drag)
            child.bind("<Double-Button-1>", lambda _event: self._toggle_maximize())
        controls = tk.Frame(top, bg=PANEL_DARK)
        controls.pack(side="right", padx=8, pady=7)
        self.btn_collect = self._retro_button(controls, "COLLECT ALL", self.collect_all, accent=True, width=13)
        self.btn_collect.pack(side="left", padx=3)
        self.btn_usb = self._retro_button(controls, "USB HISTORY", self.collect_usb, width=13)
        self.btn_usb.pack(side="left", padx=3)
        self.btn_logs = self._retro_button(controls, "EVENT LOGS", self.collect_logs, width=12)
        self.btn_logs.pack(side="left", padx=3)
        self.btn_scan = self._retro_button(controls, "SCAN FOLDER", self.scan_folder, width=13)
        self.btn_scan.pack(side="left", padx=3)

        case_bar = tk.Frame(self, bg=BG)
        case_bar.pack(fill="x", padx=10, pady=(0, 5))
        self._label(case_bar, "CASE LABEL:", color=ACCENT, bg=BG, bold=True).pack(side="left")
        case_entry = tk.Entry(
            case_bar, textvariable=self.case_name, bg=PANEL_DARK, fg=TEXT,
            insertbackground=TEXT, relief="sunken", bd=2, width=38,
            font=FONT,
        )
        case_entry.pack(side="left", padx=7, ipady=3)
        case_actions = tk.Frame(case_bar, bg=BG)
        case_actions.pack(side="right")
        self.btn_export_html = self._retro_button(case_actions, "EXPORT HTML", self.export_html, width=12)
        self.btn_export_html.pack(side="left", padx=2)
        self.btn_export_csv = self._retro_button(case_actions, "EXPORT CSV", self.export_csv, width=11)
        self.btn_export_csv.pack(side="left", padx=2)
        self.btn_clear = self._retro_button(case_actions, "CLEAR SESSION", self.clear_session, width=13)
        self.btn_clear.pack(side="left", padx=2)
        self.btn_notes = self._retro_button(case_actions, "GUIDE", self.show_notes, width=7)
        self.btn_notes.pack(side="left", padx=2)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 5))
        self.sidebar = tk.Frame(body, bg=PANEL_DARK, bd=3, relief="ridge", width=176)
        self.sidebar.pack(side="left", fill="y", padx=(0, 7))
        self.sidebar.pack_propagate(False)
        self._label(self.sidebar, "WORKSPACE", size=10, color=ACCENT, bold=True, bg=PANEL_DARK).pack(anchor="w", padx=10, pady=(12, 7))
        self.nav_buttons: dict[str, tk.Button] = {}
        for name in ("Overview", "USB History", "Event Logs", "File Triage", "Timeline", "Collection Notes"):
            btn = self._retro_button(self.sidebar, name.upper(), lambda page=name: self.show_page(page), width=17)
            btn.pack(fill="x", padx=7, pady=3)
            self.nav_buttons[name] = btn
        tk.Frame(self.sidebar, bg=BORDER, height=2).pack(fill="x", padx=8, pady=10)
        self._label(self.sidebar, "EVIDENCE SOURCES", color=ACCENT, bold=True, bg=PANEL_DARK).pack(anchor="w", padx=10)
        for line in ("[1] SYSTEM PROFILE", "[2] USB REGISTRY", "[3] WINDOWS LOGS", "[4] FILE METADATA"):
            self._label(self.sidebar, line, size=8, color=MUTED, bg=PANEL_DARK).pack(anchor="w", padx=10, pady=3)
        self._label(self.sidebar, "ANTI SKID / 0.2.0", size=8, color=ACCENT, bg=PANEL_DARK, bold=True).pack(side="bottom", pady=10)

        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)
        self.page_title = self._label(self.content, "OVERVIEW", size=13, color=ACCENT, bold=True, bg=BG)
        self.page_title.pack(fill="x", padx=3, pady=(2, 7))
        self.page_container = tk.Frame(self.content, bg=BG)
        self.page_container.pack(fill="both", expand=True)
        self.pages: dict[str, tk.Frame] = {}
        self._build_pages()

        status = tk.Frame(self, bg=PANEL_DARK, bd=2, relief="sunken")
        status.pack(fill="x", padx=8, pady=(0, 8))
        self._label(status, "STATUS >", bg=PANEL_DARK, color=ACCENT, bold=True).pack(side="left", padx=8, pady=4)
        self.status_label = self._label(status, "", bg=PANEL_DARK, color=GREEN)
        self.status_label.pack(side="left", fill="x", expand=True, pady=4)
        self.status_label.configure(textvariable=self.status_var)
        self._label(status, f"ANTISKID {APP_VERSION}", bg=PANEL_DARK, color=MUTED).pack(side="right", padx=8)

    def _build_pages(self) -> None:
        for name in ("Overview", "USB History", "Event Logs", "File Triage", "Timeline", "Collection Notes"):
            frame = tk.Frame(self.page_container, bg=BG)
            self.pages[name] = frame

        # Overview
        overview = self.pages["Overview"]
        cards = tk.Frame(overview, bg=BG)
        cards.pack(fill="x", pady=(0, 8))
        self.metric_vars = {
            "events": tk.StringVar(value="0"),
            "usb": tk.StringVar(value="0"),
            "findings": tk.StringVar(value="0"),
            "high": tk.StringVar(value="0"),
        }
        for key, title in (("events", "TIMELINE EVENTS"), ("usb", "USB ARTIFACTS"), ("findings", "FILE FINDINGS"), ("high", "HIGH / CRITICAL")):
            card = tk.Frame(cards, bg=PANEL, bd=3, relief="ridge", padx=10, pady=7)
            card.pack(side="left", fill="both", expand=True, padx=(0, 6))
            self._label(card, title, size=8, color=MUTED, bg=PANEL, bold=True).pack(anchor="w")
            self._label(card, "", size=21, color=ACCENT, bg=PANEL, bold=True, textvariable=self.metric_vars[key]).pack(anchor="w", pady=(4, 0))
        lower = tk.Frame(overview, bg=BG)
        lower.pack(fill="both", expand=True)
        system_panel = self._panel(lower)
        system_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))
        self._label(system_panel, "SYSTEM PROFILE", color=ACCENT, bold=True).pack(anchor="w", padx=10, pady=(9, 5))
        self.system_text = tk.Text(system_panel, bg=PANEL_DARK, fg=TEXT, insertbackground=TEXT, relief="sunken", bd=2, wrap="word", height=13, font=FONT)
        self.system_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        right = tk.Frame(lower, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        info_panel = self._panel(right)
        info_panel.pack(fill="both", expand=True, pady=(0, 5))
        self._label(info_panel, "COLLECTION SUMMARY", color=ACCENT, bold=True).pack(anchor="w", padx=10, pady=(9, 4))
        self.summary_text = tk.Text(info_panel, bg=PANEL_DARK, fg=TEXT, insertbackground=TEXT, relief="sunken", bd=2, wrap="word", height=7, font=FONT)
        self.summary_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        note_panel = self._panel(right)
        note_panel.pack(fill="x")
        self._label(note_panel, "INTERPRETATION", color=AMBER, bold=True).pack(anchor="w", padx=10, pady=(8, 2))
        self._label(note_panel, "Indicators are leads, not proof. Preserve originals.", size=8, color=MUTED, wraplength=410).pack(anchor="w", padx=10, pady=(0, 8))

        self.usb_tree = self._tree_page(self.pages["USB History"], "USB DEVICE AND SETUPAPI ARTIFACTS", [
            ("timestamp", "Registry timestamp / time", 175),
            ("title", "Device / artifact", 235),
            ("source", "Source", 140),
            ("details", "Details", 520),
        ])
        self.events_tree = self._tree_page(self.pages["Event Logs"], "WINDOWS EVENT LOG SNAPSHOT", [
            ("timestamp", "Timestamp", 170),
            ("severity", "Level", 80),
            ("category", "Log", 170),
            ("title", "Event", 250),
            ("details", "Message", 420),
        ])
        self.files_tree = self._tree_page(self.pages["File Triage"], "FILE INVENTORY & TRIAGE INDICATORS — HEURISTIC ONLY", [
            ("severity", "Risk", 75),
            ("name", "File name", 185),
            ("path", "Full path", 340),
            ("signature", "Detected type", 205),
            ("size", "Bytes", 90),
            ("sha256", "SHA-256 / status", 230),
            ("reason", "Indicators / read errors", 360),
        ])
        timeline_holder = self.pages["Timeline"]
        filter_bar = tk.Frame(timeline_holder, bg=BG)
        filter_bar.pack(fill="x", pady=(0, 6))
        self._label(filter_bar, "FILTER:", bg=BG, color=ACCENT, bold=True).pack(side="left")
        search = tk.Entry(filter_bar, textvariable=self.search_var, bg=PANEL_DARK, fg=TEXT, insertbackground=TEXT, relief="sunken", bd=2, width=35)
        search.pack(side="left", padx=7, ipady=3)
        self._retro_button(filter_bar, "APPLY FILTER", self.refresh_timeline, width=13).pack(side="left", padx=3)
        self._retro_button(filter_bar, "CLEAR", lambda: (self.search_var.set(""), self.refresh_timeline()), width=8).pack(side="left", padx=3)
        self.timeline_tree = self._make_tree(timeline_holder, [
            ("timestamp", "Timestamp", 170),
            ("severity", "Level", 80),
            ("category", "Category", 150),
            ("source", "Source", 145),
            ("title", "Event", 260),
            ("details", "Details", 430),
        ])
        self.pages["Collection Notes"].pack_propagate(False)
        self.notes_tree = self._tree_page(self.pages["Collection Notes"], "SOURCE STATUS / ACCESS LIMITATIONS", [
            ("source", "Source", 190), ("status", "Status", 120), ("message", "Notes", 800)
        ])

    def _tree_page(self, parent: tk.Widget, title: str, columns: list[tuple[str, str, int]]) -> ttk.Treeview:
        self._label(parent, title, color=ACCENT, bold=True, bg=BG).pack(anchor="w", pady=(0, 6))
        return self._make_tree(parent, columns)

    def _make_tree(self, parent: tk.Widget, columns: list[tuple[str, str, int]]) -> ttk.Treeview:
        ids = [item[0] for item in columns]
        holder = tk.Frame(parent, bg=BG, bd=2, relief="ridge")
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=ids, show="headings", style="Anti.Treeview")
        for key, label, width in columns:
            tree.heading(key, text=label)
            tree.column(key, width=width, minwidth=65, stretch=True, anchor="w")
        yscroll = ttk.Scrollbar(holder, orient="vertical", command=tree.yview, style="Anti.Vertical.TScrollbar")
        xscroll = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview, style="Anti.Horizontal.TScrollbar")
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        tree.tag_configure("High", foreground=RED)
        tree.tag_configure("Critical", foreground=RED)
        tree.tag_configure("Medium", foreground=AMBER)
        tree.tag_configure("Low", foreground=GREEN)
        tree.tag_configure("Info", foreground=MUTED)
        tree.bind("<Double-1>", lambda _e, t=tree: self._show_selected_detail(t))
        return tree

    def show_page(self, name: str) -> None:
        for frame in self.pages.values():
            frame.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self.page_title.configure(text=f"// {name.upper()}")
        for key, button in self.nav_buttons.items():
            button.configure(bg="#51475d" if key == name else PANEL, relief="sunken" if key == name else "raised")

    def _set_busy(self, busy: bool, status: str = "") -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in (
            self.btn_collect, self.btn_usb, self.btn_logs, self.btn_scan,
            self.btn_export_html, self.btn_export_csv, self.btn_clear,
        ):
            button.configure(state=state)
        if status:
            self.status_var.set(status)

    def _run_worker(self, title: str, func) -> None:
        if self.busy:
            return
        self._set_busy(True, f"WORKING // {title}")
        def worker():
            try:
                result = func()
                self.task_queue.put(("success", title, result))
            except Exception as exc:
                self.task_queue.put(("error", title, f"{type(exc).__name__}: {exc}"))
        threading.Thread(target=worker, name="AntiSkidWorker", daemon=True).start()

    def _poll_queue(self) -> None:
        if self._closing:
            return
        try:
            while True:
                kind, title, payload = self.task_queue.get_nowait()
                self._set_busy(False)
                if kind == "error":
                    self.status_var.set(f"ERROR // {title}: {payload}")
                    messagebox.showerror("AntiSkid — collection error", str(payload), parent=self)
                else:
                    self._apply_result(title, payload)
        except queue.Empty:
            pass
        except tk.TclError:
            return
        if not self._closing:
            self.after(120, self._poll_queue)

    def _apply_result(self, title: str, payload: Any) -> None:
        if title == "Baseline collection":
            self.bundle = payload
            self.file_records = []
        elif title == "USB history":
            events, notes = payload
            self.bundle.usb_events = events
            self.bundle.notes = [n for n in self.bundle.notes if n.source not in {x.source for x in notes}] + notes
        elif title == "Windows event logs":
            events, notes = payload
            self.bundle.log_events = events
            self.bundle.notes = [n for n in self.bundle.notes if n.source not in {x.source for x in notes}] + notes
        elif title.startswith("Folder scan:"):
            findings, records, errors = payload
            self.bundle.findings = findings
            self.file_records = records
            self.bundle.notes = [n for n in self.bundle.notes if n.source != "File scan"]
            self.bundle.notes.append(CollectionNote("File scan", "OK" if not errors else "Partial", f"{len(records)} files inspected; {len(findings)} heuristic findings; " + "; ".join(errors[:12])))
        self._refresh_all()
        self.status_var.set(f"COMPLETE // {title}. Review Collection Notes for partial access and limitations.")

    def collect_all(self) -> None:
        self._run_worker("Baseline collection", collect_baseline)

    def collect_usb(self) -> None:
        self._run_worker("USB history", collect_usb_history)

    def collect_logs(self) -> None:
        self._run_worker("Windows event logs", collect_windows_event_logs)

    def scan_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select a folder for read-only file triage")
        if not folder:
            return
        self._run_worker(
            f"Folder scan: {folder}",
            lambda: scan_directory(folder, max_files=2000, max_depth=8,
                                   max_hash_bytes=512 * 1024 * 1024,
                                   max_total_hash_bytes=2 * 1024 * 1024 * 1024),
        )

    def export_html(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export AntiSkid HTML report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html")],
            initialfile="AntiSkid_Report.html",
        )
        if not path:
            return
        try:
            protected = [item.get("path", "") for item in self.file_records if item.get("path")]
            exported = export_html_report(
                self.bundle, path, self.case_name.get(), self.file_records,
                protected_paths=protected,
            )
            self.status_var.set(f"REPORT SAVED // {exported}")
            messagebox.showinfo("AntiSkid", f"HTML report saved:\n{exported}", parent=self)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Report export failed", str(exc), parent=self)

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export AntiSkid CSV timeline",
            defaultextension=".csv",
            filetypes=[("CSV timeline", "*.csv")],
            initialfile="AntiSkid_Timeline.csv",
        )
        if not path:
            return
        try:
            protected = [item.get("path", "") for item in self.file_records if item.get("path")]
            exported = export_csv_report(self.bundle, path, protected_paths=protected)
            self.status_var.set(f"CSV SAVED // {exported}")
            messagebox.showinfo("AntiSkid", f"CSV exported:\n{exported}", parent=self)
        except (OSError, ValueError) as exc:
            messagebox.showerror("CSV export failed", str(exc), parent=self)

    def clear_session(self) -> None:
        if not messagebox.askyesno("Clear session", "Clear collected results from this AntiSkid session? Original system evidence will not be changed.", parent=self):
            return
        self.bundle = CollectionBundle()
        self.file_records = []
        self._refresh_all()
        self.status_var.set("SESSION CLEARED // No original system evidence was changed.")

    def _refresh_all(self) -> None:
        self._refresh_system()
        self._refresh_usb()
        self._refresh_logs()
        self._refresh_files()
        self.refresh_timeline()
        self._refresh_notes()
        self.metric_vars["events"].set(str(len(self.bundle.timeline())))
        self.metric_vars["usb"].set(str(len(self.bundle.usb_events)))
        self.metric_vars["findings"].set(str(len(self.bundle.findings)))
        self.metric_vars["high"].set(str(sum(1 for f in self.bundle.findings if f.severity in {"High", "Critical"})))

    def _refresh_system(self) -> None:
        info = self.bundle.system_info or collect_system_info()
        self.system_text.configure(state="normal")
        self.system_text.delete("1.0", "end")
        for key, value in info.items():
            self.system_text.insert("end", f"{key:<19} : {value}\n")
        self.system_text.configure(state="disabled")
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        if not self.bundle.system_info and not self.bundle.usb_events and not self.bundle.log_events and not self.bundle.findings:
            self.summary_text.insert("end", "No evidence collection has been started.\n\nUse COLLECT ALL to acquire the baseline sources, or choose a specific collector from the toolbar.")
        else:
            self.summary_text.insert("end", f"USB artifacts       : {len(self.bundle.usb_events)}\n")
            self.summary_text.insert("end", f"Windows log events  : {len(self.bundle.log_events)}\n")
            self.summary_text.insert("end", f"File findings       : {len(self.bundle.findings)}\n")
            self.summary_text.insert("end", f"File inventory      : {len(self.file_records)}\n")
            self.summary_text.insert("end", f"Collection notes    : {len(self.bundle.notes)}\n\n")
            self.summary_text.insert("end", "Evidence sources may be unavailable due to permissions, disabled audit policies, log retention, or missing artifacts.")
        self.summary_text.configure(state="disabled")

    def _clear_tree(self, tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def _refresh_usb(self) -> None:
        self._clear_tree(self.usb_tree)
        for event in self.bundle.usb_events:
            self.usb_tree.insert("", "end", values=(event.timestamp, event.title, event.source, event.details), tags=(event.severity,))

    def _refresh_logs(self) -> None:
        self._clear_tree(self.events_tree)
        for event in self.bundle.log_events:
            self.events_tree.insert("", "end", values=(event.timestamp, event.severity, event.category, event.title, event.details), tags=(event.severity,))

    def _refresh_files(self) -> None:
        self._clear_tree(self.files_tree)
        by_path: dict[str, list[Any]] = {}
        for finding in self.bundle.findings:
            by_path.setdefault(finding.path, []).append(finding)

        if self.file_records:
            for record in self.file_records:
                path = str(record.get("path", ""))
                indicators = by_path.get(path, [])
                highest = min(
                    (f.severity for f in indicators),
                    key=lambda value: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(value, 5),
                    default="Info",
                ) if indicators else "Info"
                reasons = [f"{f.title}: {f.reason}" for f in indicators]
                if record.get("error"):
                    reasons.append(f"READ ERROR: {record['error']}")
                if not reasons:
                    reasons.append("No configured heuristic indicator; this is not a clean-file verdict.")
                hash_display = record.get("sha256") or record.get("hash_status", "Not calculated")
                integrity = record.get("hash_integrity", "")
                if integrity:
                    hash_display = f"{hash_display} | {integrity}"
                self.files_tree.insert(
                    "", "end",
                    values=(highest, record.get("name", ""), path,
                            record.get("signature", ""), record.get("size", 0),
                            hash_display, " | ".join(reasons)),
                    tags=(highest,),
                )
        else:
            for finding in self.bundle.findings:
                self.files_tree.insert(
                    "", "end",
                    values=(finding.severity, Path(finding.path).name, finding.path,
                            "Finding", finding.size, finding.sha256 or "Not calculated",
                            f"{finding.title}: {finding.reason}"),
                    tags=(finding.severity,),
                )

    def refresh_timeline(self) -> None:
        if not hasattr(self, "timeline_tree"):
            return
        self._clear_tree(self.timeline_tree)
        query = self.search_var.get().strip().casefold()
        for event in self.bundle.timeline():
            haystack = " ".join((event.timestamp, event.category, event.source, event.title, event.details, event.severity)).casefold()
            if query and query not in haystack:
                continue
            self.timeline_tree.insert("", "end", values=(
                event.timestamp, event.severity, event.category, event.source, event.title, event.details
            ), tags=(event.severity,))

    def _refresh_notes(self) -> None:
        self._clear_tree(self.notes_tree)
        for note in self.bundle.notes:
            severity = "High" if note.status.lower() in {"error", "access denied"} else ("Medium" if note.status.lower() in {"partial", "warning", "timeout"} else "Info")
            self.notes_tree.insert("", "end", values=(note.source, note.status, note.message), tags=(severity,))

    def _show_selected_detail(self, tree: ttk.Treeview) -> None:
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0], "values")
        text = "\n\n".join(str(value) for value in values)
        detail = tk.Toplevel(self)
        detail.title("Evidence detail")
        detail.configure(bg=BG)
        detail.geometry("760x380")
        box = tk.Text(detail, bg=PANEL_DARK, fg=TEXT, insertbackground=TEXT, wrap="word", relief="sunken", bd=3, font=FONT)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.insert("1.0", text)
        box.configure(state="disabled")
        self._retro_button(detail, "CLOSE", detail.destroy, width=10).pack(pady=(0, 10))

    def about(self) -> None:
        messagebox.showinfo(
            "About AntiSkid",
            f"AntiSkid {APP_VERSION}\nDigital Forensics / Endpoint Triage\n\nA local, read-only first-response helper. It does not execute samples or modify original evidence.",
            parent=self,
        )

    def show_notes(self) -> None:
        messagebox.showwarning(
            "Evidence handling",
            "For serious investigations, stop using the affected device, preserve original media, document custody, and use a validated forensic acquisition process. AntiSkid is not a write-blocker, full disk imager, or certified forensic suite.",
            parent=self,
        )

if __name__ == "__main__":
    app = AntiSkidApp()
    app.mainloop()
