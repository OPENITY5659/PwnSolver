#!/usr/bin/env python3
"""
PHPUnser GUI — Paste PHP source code and get deserialization exploit solutions.
Portable, self-contained GUI application built with tkinter.
"""
import sys
import os
import re
import textwrap
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Ensure engine is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator
from engine.serializer import php_serialize, php_object


class PHPUnserGUI:
    """Main GUI application window."""

    TITLE = "PHPUnser — PHP Deserialization Auto-Exploitation GUI"
    WIDTH = 1100
    HEIGHT = 750

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(self.TITLE)
        self.root.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.root.minsize(900, 600)

        self.analyzer = PHPSourceAnalyzer()
        self.generator = PayloadGenerator()

        self._setup_styles()
        self._build_ui()
        self._center_window()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 10), padding=6)
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('TLabelframe.Label', font=('Segoe UI', 10, 'bold'))
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))

    def _build_ui(self):
        # Main container with padding
        main = ttk.Frame(self.root, padding="10")
        main.pack(fill=tk.BOTH, expand=True)

        # ── Title bar ──
        title_frame = ttk.Frame(main)
        title_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(title_frame, text="PHPUnser",
                  font=('Consolas', 18, 'bold')).pack(side=tk.LEFT)
        ttk.Label(title_frame, text="PHP Deserialization Auto-Exploitation GUI",
                  font=('Segoe UI', 9), foreground='gray').pack(side=tk.LEFT, padx=10)

        # ── Top panel: URL + Fetch ──
        url_frame = ttk.Frame(main)
        url_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(url_frame, text="URL (optional):").pack(side=tk.LEFT)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=60, font=('Consolas', 10))
        url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.fetch_btn = ttk.Button(url_frame, text="Fetch & Analyze",
                                     command=self._fetch_from_url, style='Accent.TButton')
        self.fetch_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(url_frame, text="Clear", command=self._clear).pack(side=tk.LEFT)

        # ── Middle: PanedWindow (input | output) ──
        pw = ttk.PanedWindow(main, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True, pady=5)

        # LEFT PANEL — Source Code Input
        left_frame = ttk.LabelFrame(pw, text=" PHP Source Code ", padding="5")
        pw.add(left_frame, weight=1)

        self.source_text = scrolledtext.ScrolledText(
            left_frame, wrap=tk.NONE, font=('Consolas', 11),
            bg='#1e1e1e', fg='#d4d4d4', insertbackground='white',
            relief=tk.FLAT, borderwidth=2
        )
        self.source_text.pack(fill=tk.BOTH, expand=True)
        # Placeholder
        self.source_text.insert('1.0', '<?php\n// Paste PHP source code here, then click Analyze\n\n')
        self._placeholder_active = True
        self.source_text.bind('<FocusIn>', self._on_focus_in)
        self.source_text.bind('<FocusOut>', self._on_focus_out)

        btn_bar = ttk.Frame(left_frame)
        btn_bar.pack(fill=tk.X, pady=(5, 0))
        self.analyze_btn = ttk.Button(btn_bar, text="▶  Analyze & Generate Payloads",
                                       command=self._analyze, style='Accent.TButton')
        self.analyze_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # RIGHT PANEL — Results
        right_frame = ttk.LabelFrame(pw, text=" Results ", padding="5")
        pw.add(right_frame, weight=1)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Analysis Summary
        self.analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text="Analysis")
        self.analysis_text = scrolledtext.ScrolledText(
            self.analysis_tab, wrap=tk.WORD, font=('Consolas', 10),
            bg='#252526', fg='#d4d4d4', state=tk.DISABLED
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True)

        # Tab 2: Payloads
        self.payloads_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.payloads_tab, text="Payloads")
        self.payloads_frame = ttk.Frame(self.payloads_tab)
        self.payloads_frame.pack(fill=tk.BOTH, expand=True)
        self.payloads_canvas = tk.Canvas(self.payloads_frame, bg='#252526', highlightthickness=0)
        self.payloads_scrollbar = ttk.Scrollbar(self.payloads_frame, orient=tk.VERTICAL,
                                                  command=self.payloads_canvas.yview)
        self.payloads_inner = ttk.Frame(self.payloads_canvas)
        self.payloads_inner.bind('<Configure>',
            lambda e: self.payloads_canvas.configure(scrollregion=self.payloads_canvas.bbox('all')))
        self.payloads_canvas.create_window((0, 0), window=self.payloads_inner, anchor='nw')
        self.payloads_canvas.configure(yscrollcommand=self.payloads_scrollbar.set)
        self.payloads_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.payloads_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 3: Raw Serialized
        self.raw_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.raw_tab, text="Raw")
        self.raw_text = scrolledtext.ScrolledText(
            self.raw_tab, wrap=tk.WORD, font=('Consolas', 10),
            bg='#252526', fg='#d4d4d4', state=tk.DISABLED
        )
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Ready. Paste PHP code and click Analyze, or enter URL and click Fetch.")
        status_bar = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN,
                               font=('Segoe UI', 8), padding=(5, 2))
        status_bar.pack(fill=tk.X, pady=(5, 0))

    def _on_focus_in(self, event):
        if self._placeholder_active:
            self.source_text.delete('1.0', tk.END)
            self._placeholder_active = False

    def _on_focus_out(self, event):
        if not self.source_text.get('1.0', tk.END).strip():
            self.source_text.insert('1.0', '<?php\n// Paste PHP source code here\n\n')
            self._placeholder_active = True

    def _fetch_from_url(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please enter a URL to fetch source from.")
            return
        self.status_var.set(f"Fetching {url}...")
        self.root.update()
        try:
            from engine.http_client import HTTPClient
            client = HTTPClient()
            source = client.fetch_source(url)
            client.close()
            if source and len(source) > 10:
                self.source_text.delete('1.0', tk.END)
                self.source_text.insert('1.0', source)
                self._placeholder_active = False
                self.status_var.set(f"Fetched {len(source)} bytes from {url}")
                self._analyze()
            else:
                messagebox.showerror("Fetch Failed", f"Could not extract PHP source from:\n{url}")
                self.status_var.set("Fetch failed.")
        except Exception as e:
            messagebox.showerror("Fetch Error", str(e))
            self.status_var.set(f"Error: {e}")

    def _analyze(self):
        source = self.source_text.get('1.0', tk.END).strip()
        if not source or source.startswith('<?php\n// Paste'):
            messagebox.showwarning("No Source", "Please enter or fetch PHP source code first.")
            return

        self.status_var.set("Analyzing...")
        self._clear_outputs()
        self.root.update()

        try:
            result = self.analyzer.analyze(source)
            payloads = self.generator.generate(result)

            self._display_analysis(result)
            self._display_payloads(payloads)
            self._display_raw(payloads)
            self.notebook.select(1)  # Switch to Payloads tab
            self.status_var.set(
                f"Done. {len(result.classes)} classes, {len(payloads)} payloads, strategy={result.strategy}"
            )
        except Exception as e:
            messagebox.showerror("Analysis Error", str(e))
            self.status_var.set(f"Error: {e}")

    def _display_analysis(self, result):
        lines = []
        lines.append("═══ PHP Source Analysis ═══\n")
        lines.append(f"Strategy: {result.strategy.upper()}\n")

        if result.classes:
            lines.append(f"\n── Classes ({len(result.classes)}) ──")
            for cls in result.classes:
                lines.append(f"\n  class {cls.name}")
                if cls.parent:
                    lines.append(f"    extends {cls.parent}")
                if cls.properties:
                    lines.append(f"    Properties:")
                    for p in cls.properties:
                        dv = f' = {p.default_value}' if p.default_value else ''
                        lines.append(f"      [{p.visibility}] ${p.name}{dv}")
                if cls.methods:
                    magic = [m for m in cls.methods if m.is_magic]
                    regular = [m for m in cls.methods if not m.is_magic]
                    if magic:
                        lines.append(f"    Magic Methods: {', '.join(m.name for m in magic)}")
                    if regular:
                        lines.append(f"    Methods: {', '.join(m.name for m in regular)}")
        else:
            lines.append("\n  (no classes detected)")

        if result.sinks:
            lines.append(f"\n── Sinks ({len(result.sinks)}) ──")
            for s in result.sinks:
                lines.append(f"  [{s.type}] {s.context[:80]}")

        if result.inputs:
            lines.append(f"\n── HTTP Inputs ({len(result.inputs)}) ──")
            for i in result.inputs:
                flags = []
                if i.used_in_sink: flags.append('sink')
                if i.used_in_eval: flags.append('eval')
                if i.used_in_unserialize: flags.append('unserialize')
                flag_str = f" ({', '.join(flags)})" if flags else ""
                lines.append(f"  {i.method}['{i.name}']{flag_str}")

        if result.flag_conditions:
            lines.append(f"\n── Flag Conditions ({len(result.flag_conditions)}) ──")
            for fc in result.flag_conditions:
                lines.append(f"  [{fc.condition_type}] {fc.condition_code[:100]}")

        self.analysis_text.configure(state=tk.NORMAL)
        self.analysis_text.delete('1.0', tk.END)
        self.analysis_text.insert('1.0', '\n'.join(lines))
        self.analysis_text.configure(state=tk.DISABLED)

    def _display_payloads(self, payloads):
        for widget in self.payloads_inner.winfo_children():
            widget.destroy()

        if not payloads:
            ttk.Label(self.payloads_inner, text="  No payloads generated.",
                      font=('Segoe UI', 10)).pack(pady=20)
            return

        ttk.Label(self.payloads_inner,
                  text=f"  {len(payloads)} payload(s) generated",
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=2)

        for i, p in enumerate(payloads):
            frame = ttk.LabelFrame(self.payloads_inner,
                                   text=f"  #{i+1}  [{p.strategy}]  {p.http_method}",
                                   padding="5")
            frame.pack(fill=tk.X, padx=5, pady=3)

            desc_label = ttk.Label(frame, text=p.description, wraplength=400,
                                   font=('Segoe UI', 9, 'italic'))
            desc_label.pack(anchor='w')

            if p.serialized_string:
                ser_frame = ttk.Frame(frame)
                ser_frame.pack(fill=tk.X, pady=3)
                ser_text = scrolledtext.ScrolledText(
                    ser_frame, height=3, wrap=tk.WORD,
                    font=('Consolas', 9), bg='#1e1e1e', fg='#ce9178'
                )
                ser_text.insert('1.0', p.serialized_string)
                ser_text.configure(state=tk.DISABLED)
                ser_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
                ttk.Button(ser_frame, text="Copy", width=6,
                           command=lambda s=p.serialized_string: self._copy_to_clipboard(s)
                           ).pack(side=tk.LEFT, padx=3)

                # Also show curl command
                curl = p.get_curl_command()
                curl_label = ttk.Label(frame, text=curl, wraplength=400,
                                       font=('Consolas', 8), foreground='gray')
                curl_label.pack(anchor='w', pady=(2, 0))

            if p.raw_code:
                code_frame = ttk.Frame(frame)
                code_frame.pack(fill=tk.X, pady=3)
                code_text = scrolledtext.ScrolledText(
                    code_frame, height=2, wrap=tk.WORD,
                    font=('Consolas', 9), bg='#1e1e1e', fg='#6a9955'
                )
                code_text.insert('1.0', p.raw_code)
                code_text.configure(state=tk.DISABLED)
                code_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
                ttk.Button(code_frame, text="Copy", width=6,
                           command=lambda s=p.raw_code: self._copy_to_clipboard(s)
                           ).pack(side=tk.LEFT, padx=3)

            if p.params:
                ttk.Label(frame, text=f"GET params: {p.params}",
                          font=('Consolas', 8), foreground='gray').pack(anchor='w')

    def _display_raw(self, payloads):
        lines = []
        for i, p in enumerate(payloads):
            if p.serialized_string:
                lines.append(f"# Payload {i+1} [{p.strategy}] {p.description}")
                lines.append(p.serialized_string)
                lines.append("")
        self.raw_text.configure(state=tk.NORMAL)
        self.raw_text.delete('1.0', tk.END)
        self.raw_text.insert('1.0', '\n'.join(lines) if lines else "(no serialized payloads)")
        self.raw_text.configure(state=tk.DISABLED)

    def _clear_outputs(self):
        self.analysis_text.configure(state=tk.NORMAL)
        self.analysis_text.delete('1.0', tk.END)
        self.analysis_text.configure(state=tk.DISABLED)
        for w in self.payloads_inner.winfo_children():
            w.destroy()
        self.raw_text.configure(state=tk.NORMAL)
        self.raw_text.delete('1.0', tk.END)
        self.raw_text.configure(state=tk.DISABLED)

    def _clear(self):
        self.source_text.delete('1.0', tk.END)
        self.url_var.set('')
        self._clear_outputs()
        self.status_var.set("Cleared.")

    def _copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Copied to clipboard!")

    def _center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f'+{x}+{y}')


def main():
    root = tk.Tk()
    app = PHPUnserGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
