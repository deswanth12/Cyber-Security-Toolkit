import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
from tkinter import ttk, filedialog
import csv, sqlite3, threading, socket, ssl, base64, random, string, ipaddress
import subprocess, platform, datetime, json

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib import rcParams

from password_checker import check_password
from scanner import scan_common_ports
from hash_generator import generate_md5, generate_sha256
from checker import check_url
from database import save_activity, get_history, get_stats


# ══════════════════════════════════════════════
#  WINDOW & THEME
# ══════════════════════════════════════════════

root = tb.Window(themename="cyborg")
root.title("Cyber Security Toolkit  •  v2.0")
root.geometry("1440x860")
root.minsize(1220, 720)

ACCENT      = "#00bfff"
DANGER_COL  = "#ff4757"
SUCCESS_COL = "#2ed573"
WARN_COL    = "#ffa502"
MUTED       = "#8a9ab5"
BG_CARD     = "#1e2533"
FONT_TITLE  = ("Consolas", 26, "bold")
FONT_SUB    = ("Consolas", 13)
FONT_SMALL  = ("Consolas", 10)

rcParams.update({
    "figure.facecolor": "#151b27", "axes.facecolor": "#1e2533",
    "axes.edgecolor": "#2e3a50",   "axes.labelcolor": "#c8d3e8",
    "xtick.color": "#8a9ab5",      "ytick.color": "#8a9ab5",
    "text.color": "#c8d3e8",       "grid.color": "#2e3a50",
})


# ══════════════════════════════════════════════
#  LAYOUT
# ══════════════════════════════════════════════

sidebar   = tb.Frame(root, width=250, style="dark.TFrame")
sidebar.pack(side=LEFT, fill=Y)
sidebar.pack_propagate(False)

main_area = tb.Frame(root, style="TFrame")
main_area.pack(side=RIGHT, fill=BOTH, expand=True)


# ══════════════════════════════════════════════
#  STATUS BAR
# ══════════════════════════════════════════════

status_frame = tb.Frame(root, height=28)
status_frame.pack(side=BOTTOM, fill=X)
status_frame.pack_propagate(False)

status_dot  = tb.Label(status_frame, text="●", foreground=SUCCESS_COL, font=("Consolas", 11))
status_dot.pack(side=LEFT, padx=(12, 4), pady=2)
status_text = tb.Label(status_frame, text="System Ready", font=FONT_SMALL, foreground=MUTED)
status_text.pack(side=LEFT, pady=2)
tb.Label(status_frame, text="Cyber Security Toolkit v2.0  |  Developed by Deswanth",
         font=FONT_SMALL, foreground=MUTED).pack(side=RIGHT, padx=16)

def set_status(msg, color=SUCCESS_COL):
    status_dot.config(foreground=color)
    status_text.config(text=msg)
    root.after(4000, lambda: (status_dot.config(foreground=SUCCESS_COL),
                               status_text.config(text="System Ready")))


# ══════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════

tb.Label(sidebar, text="🛡", font=("Segoe UI Emoji", 38)).pack(pady=(20, 2))
tb.Label(sidebar, text="CYBER TOOLKIT", font=("Consolas", 12, "bold"), foreground=ACCENT).pack()
tb.Label(sidebar, text="Security Analysis Suite", font=FONT_SMALL, foreground=MUTED).pack(pady=(0,4))
ttk.Separator(sidebar).pack(fill="x", padx=14, pady=8)

# Scrollable sidebar nav
nav_canvas = tb.Canvas(sidebar, highlightthickness=0)
nav_scroll = ttk.Scrollbar(sidebar, orient="vertical", command=nav_canvas.yview)
nav_inner  = tb.Frame(nav_canvas)
nav_inner.bind("<Configure>", lambda e: nav_canvas.configure(scrollregion=nav_canvas.bbox("all")))
nav_canvas.create_window((0, 0), window=nav_inner, anchor="nw")
nav_canvas.configure(yscrollcommand=nav_scroll.set)
nav_canvas.pack(side=LEFT, fill=BOTH, expand=True)

NAV_ITEMS = [
    ("── OVERVIEW ──",           None,                    None),
    ("⬛  Dashboard",             "show_dashboard",        "info-outline"),
    ("── TOOLS ──",              None,                    None),
    ("🔑  Password Analyzer",    "show_password",         "success-outline"),
    ("🔐  Password Generator",   "show_password_gen",     "success-outline"),
    ("📡  Port Scanner",         "show_scanner",          "warning-outline"),
    ("🔗  URL Inspector",        "show_url_checker",      "primary-outline"),
    ("#   Hash Generator",       "show_hash_generator",   "secondary-outline"),
    ("── NETWORK ──",            None,                    None),
    ("🌐  DNS Lookup",           "show_dns_lookup",       "info-outline"),
    ("🔒  SSL Checker",          "show_ssl_checker",      "success-outline"),
    ("📍  IP Geolocation",       "show_ip_geo",           "warning-outline"),
    ("📶  Ping Tool",            "show_ping",             "primary-outline"),
    ("🔢  Subnet Calculator",    "show_subnet",           "secondary-outline"),
    ("── ENCODE ──",             None,                    None),
    ("🔤  Cipher Tool",          "show_cipher",           "dark-outline"),
    ("── DATA ──",               None,                    None),
    ("📋  History",              "show_history",          "dark-outline"),
    ("📊  Analytics",            "show_analytics",        "info-outline"),
    ("⚙   Settings",             "show_settings",         "warning-outline"),
    ("ℹ   About",                "show_about",            "secondary-outline"),
]

for lbl, fn, style in NAV_ITEMS:
    if fn is None:
        tb.Label(nav_inner, text=lbl, font=("Consolas", 8, "bold"),
                 foreground="#4a5a72").pack(anchor=W, padx=16, pady=(10, 2))
    else:
        tb.Button(nav_inner, text=lbl, width=28, bootstyle=style,
                  command=lambda f=fn: globals()[f]()
                  ).pack(fill="x", padx=10, pady=2)

ttk.Separator(nav_inner).pack(fill="x", padx=14, pady=8)
tb.Label(nav_inner, text="Activity saved to SQLite", font=FONT_SMALL,
         foreground=MUTED, wraplength=200, justify=CENTER).pack(padx=10, pady=(0,10))


# ══════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════

def clear_main():
    for w in main_area.winfo_children():
        w.destroy()

def page_header(title, subtitle=""):
    hdr = tb.Frame(main_area)
    hdr.pack(fill=X, padx=30, pady=(24, 4))
    tb.Label(hdr, text=title, font=FONT_TITLE, foreground=ACCENT).pack(anchor=W)
    if subtitle:
        tb.Label(hdr, text=subtitle, font=FONT_SMALL, foreground=MUTED).pack(anchor=W)
    ttk.Separator(main_area).pack(fill=X, padx=30, pady=(6, 0))

def stat_card(parent, title, value, col, row, color=ACCENT):
    card = tb.Frame(parent, padding=16, style="dark.TFrame")
    card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
    parent.columnconfigure(col, weight=1)
    tb.Label(card, text=str(value), font=("Consolas", 28, "bold"), foreground=color).pack(anchor=W)
    tb.Label(card, text=title, font=FONT_SMALL, foreground=MUTED).pack(anchor=W, pady=(2,0))
    bar = tb.Frame(card, height=3)
    bar.pack(fill=X, side=BOTTOM, pady=(6,0))
    bar.configure(style="info.TFrame")

def toast(msg, kind="success"):
    colors = {"success": SUCCESS_COL, "error": DANGER_COL, "warn": WARN_COL}
    fg = colors.get(kind, SUCCESS_COL)
    popup = tb.Toplevel(root)
    popup.overrideredirect(True)
    popup.attributes("-alpha", 0.92)
    popup.configure(background="#1a2135")
    rx = root.winfo_x() + root.winfo_width() - 370
    ry = root.winfo_y() + root.winfo_height() - 80
    popup.geometry(f"350x50+{rx}+{ry}")
    tb.Label(popup, text=f"  ●  {msg}", font=FONT_SUB, foreground=fg,
             background="#1a2135").pack(expand=True, fill=BOTH, padx=14)
    root.after(2800, popup.destroy)

def make_text_box(parent, height=16):
    box = tb.Text(parent, font=("Consolas", 11), height=height,
                  background=BG_CARD, foreground="#c8d3e8",
                  relief="flat", padx=12, pady=10, state="disabled")
    box.pack(fill=BOTH, expand=True, padx=30, pady=10)
    box.tag_config("ok",     foreground=SUCCESS_COL)
    box.tag_config("warn",   foreground=WARN_COL)
    box.tag_config("err",    foreground=DANGER_COL)
    box.tag_config("head",   foreground=ACCENT, font=("Consolas",11,"bold"))
    box.tag_config("muted",  foreground=MUTED)
    box.tag_config("key",    foreground="#a29bfe", font=("Consolas",11,"bold"))
    return box

def twrite(box, text, tag="normal"):
    box.config(state="normal")
    box.insert(END, text, tag)
    box.see(END)
    box.config(state="disabled")

def tclear(box):
    box.config(state="normal")
    box.delete("1.0", END)
    box.config(state="disabled")

def input_row(parent, label, width=40, placeholder=""):
    tb.Label(parent, text=label, font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    row = tb.Frame(parent)
    row.pack(fill=X, pady=(4, 14))
    entry = tb.Entry(row, font=("Consolas", 13), width=width)
    entry.pack(side=LEFT, ipady=6)
    if placeholder:
        entry.insert(0, placeholder)
        entry.config(foreground=MUTED)
        def on_focus_in(e):
            if entry.get() == placeholder:
                entry.delete(0, END)
                entry.config(foreground="#c8d3e8")
        def on_focus_out(e):
            if not entry.get():
                entry.insert(0, placeholder)
                entry.config(foreground=MUTED)
        entry.bind("<FocusIn>",  on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
    return entry, row


# ══════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════

def show_dashboard():
    clear_main()
    set_status("Dashboard loaded")
    stats = get_stats()
    page_header("Dashboard", "Overview of all toolkit activity")

    cards_frame = tb.Frame(main_area)
    cards_frame.pack(fill=X, padx=30, pady=16)

    card_data = [
        ("Total Activities",  stats["total"],     ACCENT),
        ("Passwords Checked", stats["passwords"], SUCCESS_COL),
        ("Port Scans",        stats["ports"],     WARN_COL),
        ("URLs Inspected",    stats["urls"],      "#a29bfe"),
        ("Hashes Generated",  stats["hashes"],   MUTED),
    ]
    for i, (title, val, color) in enumerate(card_data):
        stat_card(cards_frame, title, val, col=i, row=0, color=color)

    # Quick actions
    qa = tb.Frame(main_area)
    qa.pack(fill=X, padx=30, pady=(8,0))
    tb.Label(qa, text="Quick Actions", font=("Consolas",12,"bold"), foreground=MUTED).pack(anchor=W, pady=(0,6))
    btn_row = tb.Frame(qa)
    btn_row.pack(fill=X)
    quick = [
        ("🔑 Password",    "show_password",       "success"),
        ("🔐 Generator",   "show_password_gen",   "success"),
        ("📡 Port Scan",   "show_scanner",        "warning"),
        ("🔗 URL Check",   "show_url_checker",    "primary"),
        ("🌐 DNS Lookup",  "show_dns_lookup",     "info"),
        ("🔒 SSL Check",   "show_ssl_checker",    "success"),
        ("📍 IP Geo",      "show_ip_geo",         "warning"),
        ("📶 Ping",        "show_ping",           "primary"),
    ]
    for label, fn, style in quick:
        tb.Button(btn_row, text=label, bootstyle=style,
                  command=lambda f=fn: globals()[f](),
                  padding=(10,6)).pack(side=LEFT, padx=(0,6))

    # Recent activity
    tb.Label(main_area, text="Recent Activity", font=("Consolas",12,"bold"),
             foreground=MUTED).pack(anchor=W, padx=30, pady=(20,6))
    pf = tb.Frame(main_area)
    pf.pack(fill=X, padx=30)
    cols = ("Tool", "Result", "Date")
    pt = ttk.Treeview(pf, columns=cols, show="headings", height=5)
    for c in cols:
        pt.heading(c, text=c)
    pt.column("Tool",   width=160)
    pt.column("Result", width=400)
    pt.column("Date",   width=160)
    pt.pack(fill=X)
    for row in get_history()[-5:]:
        pt.insert("", END, values=(row[1], row[2], row[3]))


# ══════════════════════════════════════════════
#  PASSWORD ANALYZER
# ══════════════════════════════════════════════

STRENGTH_COLORS = ["#ff4757","#ff6b81","#ffa502","#2ed573","#1e90ff"]
STRENGTH_LABELS = ["Very Weak","Weak","Fair","Strong","Very Strong"]

def show_password():
    clear_main()
    set_status("Password Analyzer ready")
    page_header("Password Analyzer", "Evaluate the strength of any password")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)

    tb.Label(form, text="Enter Password", font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    erow = tb.Frame(form)
    erow.pack(fill=X, pady=(6,0))

    pw_var   = tb.StringVar()
    show_var = tb.BooleanVar(value=False)
    pw_entry = tb.Entry(erow, textvariable=pw_var, show="●", font=("Consolas",14), width=44)
    pw_entry.pack(side=LEFT, ipady=6)
    pw_entry.focus()

    def toggle_vis():
        pw_entry.config(show="" if show_var.get() else "●")
    tb.Checkbutton(erow, text="Show", variable=show_var, bootstyle="info-round-toggle",
                   command=toggle_vis).pack(side=LEFT, padx=12)

    mf = tb.Frame(form)
    mf.pack(fill=X, pady=(18,0))
    tb.Label(mf, text="Strength", font=FONT_SMALL, foreground=MUTED).pack(anchor=W)
    brow = tb.Frame(mf)
    brow.pack(fill=X, pady=(4,0))
    bars = []
    for _ in range(5):
        seg = tb.Frame(brow, height=8, width=82)
        seg.pack(side=LEFT, padx=2)
        bars.append(seg)
    sl = tb.Label(mf, text="—", font=FONT_SUB, foreground=MUTED)
    sl.pack(anchor=W, pady=(6,0))

    rb = tb.Frame(main_area, padding=22, style="dark.TFrame")
    rb.pack(fill=X, padx=30, pady=14)
    rl = tb.Label(rb, text="Awaiting analysis…", font=FONT_SUB, foreground=MUTED,
                  wraplength=700, justify=LEFT)
    rl.pack(anchor=W)

    def update_meter(score, color):
        for i, bar in enumerate(bars):
            bar.configure(background=color if i < score else "#2e3a50")

    def analyze():
        pw = pw_var.get()
        if not pw:
            toast("Enter a password first", "warn"); return
        result = check_password(pw)
        save_activity("Password Analyzer", result)
        low = result.lower()
        if   "very strong" in low: score, color = 5, STRENGTH_COLORS[4]
        elif "strong"      in low: score, color = 4, STRENGTH_COLORS[3]
        elif "fair"        in low: score, color = 3, STRENGTH_COLORS[2]
        elif "weak"        in low and "very" not in low: score, color = 2, STRENGTH_COLORS[1]
        else:                      score, color = 1, STRENGTH_COLORS[0]
        update_meter(score, color)
        sl.config(text=STRENGTH_LABELS[score-1], foreground=color)
        rl.config(text=result, foreground="#c8d3e8")
        set_status(f"Password analyzed — {STRENGTH_LABELS[score-1]}", color)
        toast(f"Analysis complete: {STRENGTH_LABELS[score-1]}",
              "success" if score>=4 else "warn" if score==3 else "error")

    tb.Button(form, text="  Analyze  ", bootstyle="success",
              command=analyze, padding=(14,8)).pack(anchor=W, pady=(14,0))


# ══════════════════════════════════════════════
#  PASSWORD GENERATOR  (NEW)
# ══════════════════════════════════════════════

def show_password_gen():
    clear_main()
    set_status("Password Generator ready")
    page_header("Password Generator", "Generate cryptographically strong random passwords")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)

    # Options grid
    opt_frame = tb.Frame(form, style="dark.TFrame", padding=16)
    opt_frame.pack(fill=X, pady=(0,16))

    length_var  = tb.IntVar(value=16)
    upper_var   = tb.BooleanVar(value=True)
    lower_var   = tb.BooleanVar(value=True)
    digit_var   = tb.BooleanVar(value=True)
    symbol_var  = tb.BooleanVar(value=True)
    ambig_var   = tb.BooleanVar(value=False)
    count_var   = tb.IntVar(value=5)

    def opt_label(parent, text, row, col):
        tb.Label(parent, text=text, font=FONT_SMALL, foreground=MUTED).grid(
            row=row, column=col, sticky=W, padx=(0,8), pady=4)

    opt_label(opt_frame, "Length",           0, 0)
    ls = tb.Scale(opt_frame, from_=4, to=64, variable=length_var, orient=HORIZONTAL, length=200,
                  bootstyle="info", command=lambda v: lv.config(text=f"{int(float(v))} chars"))
    ls.grid(row=0, column=1, sticky=W, pady=4)
    lv = tb.Label(opt_frame, text="16 chars", font=FONT_SMALL, foreground=ACCENT)
    lv.grid(row=0, column=2, sticky=W, padx=10)

    opt_label(opt_frame, "Count",            1, 0)
    cs = tb.Scale(opt_frame, from_=1, to=20, variable=count_var, orient=HORIZONTAL, length=200,
                  bootstyle="secondary", command=lambda v: cv.config(text=f"{int(float(v))} passwords"))
    cs.grid(row=1, column=1, sticky=W, pady=4)
    cv = tb.Label(opt_frame, text="5 passwords", font=FONT_SMALL, foreground=MUTED)
    cv.grid(row=1, column=2, sticky=W, padx=10)

    opt_label(opt_frame, "Include",          2, 0)
    checks = tb.Frame(opt_frame)
    checks.grid(row=2, column=1, columnspan=2, sticky=W, pady=4)
    for text, var in [("A-Z", upper_var), ("a-z", lower_var),
                      ("0-9", digit_var), ("!@#$", symbol_var), ("No ambiguous", ambig_var)]:
        tb.Checkbutton(checks, text=text, variable=var, bootstyle="info-round-toggle").pack(
            side=LEFT, padx=(0,14))

    out_box = make_text_box(main_area, height=12)

    def generate():
        chars = ""
        if upper_var.get():  chars += string.ascii_uppercase
        if lower_var.get():  chars += string.ascii_lowercase
        if digit_var.get():  chars += string.digits
        if symbol_var.get(): chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if not chars:
            toast("Select at least one character type", "warn"); return
        if ambig_var.get():
            for c in "0O1lI":
                chars = chars.replace(c, "")
        length = length_var.get()
        count  = count_var.get()
        tclear(out_box)
        twrite(out_box, f"  Generated {count} passwords — {length} characters each\n", "head")
        twrite(out_box, f"  {'─'*60}\n", "muted")
        passwords = []
        for i in range(count):
            pw = "".join(random.SystemRandom().choice(chars) for _ in range(length))
            passwords.append(pw)
            twrite(out_box, f"  {i+1:>2}.  {pw}\n", "ok")
        save_activity("Password Generator", f"Generated {count} passwords ({length} chars)")
        set_status("Passwords generated", SUCCESS_COL)
        toast(f"{count} passwords generated", "success")

    def copy_all():
        data = out_box.get("1.0", END).strip()
        if data:
            root.clipboard_clear()
            root.clipboard_append(data)
            toast("All passwords copied to clipboard", "success")

    btn_row = tb.Frame(form)
    btn_row.pack(anchor=W, pady=(0,0))
    tb.Button(btn_row, text="  Generate  ", bootstyle="success",
              command=generate, padding=(14,8)).pack(side=LEFT, padx=(0,10))
    tb.Button(btn_row, text="  Copy All  ", bootstyle="secondary-outline",
              command=copy_all, padding=(14,8)).pack(side=LEFT)


# ══════════════════════════════════════════════
#  PORT SCANNER
# ══════════════════════════════════════════════

def show_scanner():
    clear_main()
    set_status("Port Scanner ready")
    page_header("Port Scanner", "Scan common ports on a host or IP address")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    tb.Label(form, text="Target Host / IP", font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    row = tb.Frame(form)
    row.pack(fill=X, pady=(6,0))
    host_entry = tb.Entry(row, font=("Consolas",14), width=44)
    host_entry.pack(side=LEFT, ipady=6)
    host_entry.focus()

    progress = tb.Progressbar(main_area, mode="indeterminate", bootstyle="info-striped")
    result_box = make_text_box(main_area, height=18)

    def scan():
        host = host_entry.get().strip()
        if not host:
            toast("Enter a host or IP", "warn"); return
        tclear(result_box)
        progress.pack(fill=X, padx=30, pady=(0,6))
        progress.start(12)
        set_status(f"Scanning {host}…", WARN_COL)

        def _run():
            try:
                ports = scan_common_ports(host)
                save_activity("Port Scanner", str(ports))
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                root.after(0, lambda: twrite(result_box, f"  Scan results → {host}\n", "head"))
                root.after(0, lambda: twrite(result_box, f"  {'─'*54}\n", "muted"))
                if isinstance(ports, list):
                    if ports:
                        for p in ports:
                            root.after(0, lambda pp=p: twrite(result_box, f"  ✔  Port {pp:>5}  OPEN\n", "ok"))
                    else:
                        root.after(0, lambda: twrite(result_box, "  No open ports found.\n", "muted"))
                else:
                    root.after(0, lambda: twrite(result_box, str(ports)+"\n"))
                root.after(0, lambda: set_status(f"Scan complete — {host}", SUCCESS_COL))
                root.after(0, lambda: toast(f"Scan complete for {host}", "success"))
            except Exception as e:
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                root.after(0, lambda: twrite(result_box, f"  Error: {e}\n", "err"))
                root.after(0, lambda: set_status("Scan failed", DANGER_COL))
                root.after(0, lambda: toast(str(e), "error"))

        threading.Thread(target=_run, daemon=True).start()

    tb.Button(row, text="  Start Scan  ", bootstyle="warning",
              command=scan, padding=(14,6)).pack(side=LEFT, padx=12)


# ══════════════════════════════════════════════
#  URL INSPECTOR
# ══════════════════════════════════════════════

def show_url_checker():
    clear_main()
    set_status("URL Inspector ready")
    page_header("URL Inspector", "Analyze the safety and status of a URL")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    tb.Label(form, text="Target URL", font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    row = tb.Frame(form)
    row.pack(fill=X, pady=(6,0))
    url_entry = tb.Entry(row, font=("Consolas",14), width=55)
    url_entry.pack(side=LEFT, ipady=6)
    url_entry.focus()

    rc = tb.Frame(main_area, padding=22, style="dark.TFrame")
    rc.pack(fill=X, padx=30, pady=14)
    icon_lbl = tb.Label(rc, text="🔗", font=("Segoe UI Emoji",28))
    icon_lbl.pack(side=LEFT, padx=(0,16))
    info_col = tb.Frame(rc)
    info_col.pack(side=LEFT, fill=X, expand=True)
    sl2 = tb.Label(info_col, text="Awaiting URL…", font=("Consolas",15,"bold"), foreground=MUTED)
    sl2.pack(anchor=W)
    dl = tb.Label(info_col, text="", font=FONT_SMALL, foreground=MUTED)
    dl.pack(anchor=W, pady=(4,0))

    def inspect():
        url = url_entry.get().strip()
        if not url:
            toast("Enter a URL first", "warn"); return
        sl2.config(text="Inspecting…", foreground=WARN_COL)
        set_status(f"Inspecting {url[:60]}…", WARN_COL)
        def _run():
            result = check_url(url)
            save_activity("URL Inspector", result)
            low = result.lower()
            if any(k in low for k in ("safe","ok","200","reachable")):
                color, ico = SUCCESS_COL, "✔"
            elif any(k in low for k in ("danger","malicious","phish")):
                color, ico = DANGER_COL, "✘"
            else:
                color, ico = WARN_COL, "⚠"
            root.after(0, lambda: sl2.config(text=f"{ico}  {result}", foreground=color))
            root.after(0, lambda: dl.config(text=url))
            root.after(0, lambda: set_status(f"URL inspected — {result}", color))
            root.after(0, lambda: toast(result, "success" if color==SUCCESS_COL
                                         else "error" if color==DANGER_COL else "warn"))
        threading.Thread(target=_run, daemon=True).start()

    tb.Button(row, text="  Inspect  ", bootstyle="primary",
              command=inspect, padding=(14,6)).pack(side=LEFT, padx=12)


# ══════════════════════════════════════════════
#  HASH GENERATOR
# ══════════════════════════════════════════════

def show_hash_generator():
    clear_main()
    set_status("Hash Generator ready")
    page_header("Hash Generator", "Compute MD5 and SHA-256 checksums for any file")

    drop = tb.Frame(main_area, padding=30)
    drop.pack(fill=X)
    fv = tb.StringVar(value="No file selected")
    tb.Label(drop, textvariable=fv, font=FONT_SMALL, foreground=MUTED).pack(anchor=W, pady=(0,10))

    rf = tb.Frame(main_area, padding=(30,0))
    rf.pack(fill=X)

    def hash_row(parent, algo, value):
        row = tb.Frame(parent, padding=(14,10), style="dark.TFrame")
        row.pack(fill=X, pady=4)
        tb.Label(row, text=algo, font=("Consolas",11,"bold"), foreground=ACCENT, width=10).pack(side=LEFT)
        val_var = tb.StringVar(value=value)
        tb.Entry(row, textvariable=val_var, font=("Consolas",12), state="readonly",
                 width=72, readonlybackground=BG_CARD, foreground="#c8d3e8").pack(side=LEFT, ipady=5)
        tb.Button(row, text="Copy", bootstyle="secondary-outline",
                  command=lambda: [root.clipboard_clear(), root.clipboard_append(value),
                                   toast(f"{algo} copied!", "success")],
                  padding=(8,4)).pack(side=LEFT, padx=8)

    progress = tb.Progressbar(main_area, mode="indeterminate", bootstyle="success-striped")

    def choose_file():
        path = filedialog.askopenfilename()
        if not path: return
        fv.set(f"File: {path}")
        for w in rf.winfo_children(): w.destroy()
        progress.pack(fill=X, padx=30, pady=4)
        progress.start(12)
        set_status("Generating hashes…", WARN_COL)
        def _run():
            md5 = generate_md5(path)
            sha = generate_sha256(path)
            save_activity("Hash Generator", path)
            root.after(0, progress.stop)
            root.after(0, progress.pack_forget)
            root.after(0, lambda: hash_row(rf, "MD5",    md5))
            root.after(0, lambda: hash_row(rf, "SHA-256", sha))
            root.after(0, lambda: set_status("Hashes generated", SUCCESS_COL))
            root.after(0, lambda: toast("Hashes ready", "success"))
        threading.Thread(target=_run, daemon=True).start()

    tb.Button(drop, text="  Choose File  ", bootstyle="success",
              command=choose_file, padding=(14,8)).pack(anchor=W)


# ══════════════════════════════════════════════
#  DNS LOOKUP  (NEW)
# ══════════════════════════════════════════════

def show_dns_lookup():
    clear_main()
    set_status("DNS Lookup ready")
    page_header("DNS Lookup", "Query A, MX, NS, TXT, CNAME, and PTR records for any domain")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    host_entry, row = input_row(form, "Domain / IP Address", width=44, placeholder="e.g. google.com")

    # Record type selector
    type_var = tb.StringVar(value="ALL")
    type_frame = tb.Frame(form)
    type_frame.pack(anchor=W, pady=(0,10))
    tb.Label(type_frame, text="Record types:", font=FONT_SMALL, foreground=MUTED).pack(side=LEFT, padx=(0,8))
    for rtype in ["ALL", "A", "MX", "NS", "TXT", "CNAME", "PTR"]:
        tb.Radiobutton(type_frame, text=rtype, variable=type_var, value=rtype,
                       bootstyle="info").pack(side=LEFT, padx=4)

    progress = tb.Progressbar(main_area, mode="indeterminate", bootstyle="info-striped")
    result_box = make_text_box(main_area, height=16)

    def lookup():
        domain = host_entry.get().strip()
        if not domain or domain == "e.g. google.com":
            toast("Enter a domain first", "warn"); return
        tclear(result_box)
        progress.pack(fill=X, padx=30, pady=(0,6))
        progress.start(12)
        set_status(f"Looking up {domain}…", WARN_COL)

        def _run():
            results = []
            rtype = type_var.get()
            try:
                # A record
                if rtype in ("ALL","A"):
                    try:
                        a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
                        ips = list(set(r[4][0] for r in a_records))
                        for ip in ips:
                            results.append(("A", ip))
                    except: pass

                # AAAA record
                if rtype in ("ALL","A"):
                    try:
                        aaaa = socket.getaddrinfo(domain, None, socket.AF_INET6)
                        ipv6s = list(set(r[4][0] for r in aaaa))
                        for ip in ipv6s:
                            results.append(("AAAA", ip))
                    except: pass

                # PTR reverse lookup (if IP given)
                if rtype in ("ALL","PTR"):
                    try:
                        ptr = socket.gethostbyaddr(domain)[0]
                        results.append(("PTR", ptr))
                    except: pass

                # MX via subprocess (nslookup/dig not portable; use basic socket fallback)
                if rtype in ("ALL","MX"):
                    try:
                        import subprocess
                        r = subprocess.run(
                            ["nslookup", "-type=MX", domain],
                            capture_output=True, text=True, timeout=5
                        )
                        for line in r.stdout.splitlines():
                            if "mail exchanger" in line.lower() or "MX preference" in line:
                                results.append(("MX", line.strip()))
                    except: pass

                # Fallback info
                if not results:
                    results.append(("INFO", "No records found (install dnspython for full DNS support)"))

            except Exception as e:
                results.append(("ERROR", str(e)))

            def _render():
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                twrite(result_box, f"  DNS records for  {domain}\n", "head")
                twrite(result_box, f"  {'─'*56}\n", "muted")
                for rtype_str, value in results:
                    twrite(result_box, f"  ", "muted")
                    twrite(result_box, f"  {rtype_str:<8}", "key")
                    twrite(result_box, f"  {value}\n")
                save_activity("DNS Lookup", f"{domain}: {len(results)} records")
                set_status(f"DNS lookup complete — {domain}", SUCCESS_COL)
                toast(f"Found {len(results)} DNS records", "success")

            root.after(0, _render)

        threading.Thread(target=_run, daemon=True).start()

    tb.Button(row, text="  Lookup  ", bootstyle="info",
              command=lookup, padding=(14,6)).pack(side=LEFT, padx=12)


# ══════════════════════════════════════════════
#  SSL CERTIFICATE CHECKER  (NEW)
# ══════════════════════════════════════════════

def show_ssl_checker():
    clear_main()
    set_status("SSL Checker ready")
    page_header("SSL Certificate Checker", "Verify TLS/SSL certificates — expiry, issuer, and cipher suite")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    host_entry, row = input_row(form, "Hostname", width=44, placeholder="e.g. google.com")

    port_label = tb.Label(row, text="Port:", font=FONT_SMALL, foreground=MUTED)
    port_label.pack(side=LEFT, padx=(18,6))
    port_entry = tb.Entry(row, font=("Consolas",13), width=7)
    port_entry.pack(side=LEFT, ipady=6)
    port_entry.insert(0, "443")

    progress = tb.Progressbar(main_area, mode="indeterminate", bootstyle="success-striped")
    result_box = make_text_box(main_area, height=16)

    def check_ssl():
        host = host_entry.get().strip()
        if not host or host == "e.g. google.com":
            toast("Enter a hostname", "warn"); return
        try:
            port = int(port_entry.get().strip() or "443")
        except ValueError:
            toast("Invalid port number", "error"); return

        tclear(result_box)
        progress.pack(fill=X, padx=30, pady=(0,6))
        progress.start(12)
        set_status(f"Checking SSL for {host}:{port}…", WARN_COL)

        def _run():
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.create_connection((host, port), timeout=8),
                                     server_hostname=host) as s:
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    version = s.version()

                # Parse expiry
                not_after_str = cert.get("notAfter", "")
                not_before_str = cert.get("notBefore", "")
                try:
                    fmt = "%b %d %H:%M:%S %Y %Z"
                    expiry  = datetime.datetime.strptime(not_after_str,  fmt)
                    issued  = datetime.datetime.strptime(not_before_str, fmt)
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    exp_status = f"{days_left} days remaining"
                    exp_tag  = "ok" if days_left > 30 else "warn" if days_left > 0 else "err"
                except:
                    expiry = not_after_str; issued = not_before_str
                    exp_status = ""; exp_tag = "ok"; days_left = None

                # Extract subject/issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                san     = cert.get("subjectAltName", [])
                san_str = ", ".join(v for _, v in san[:6])
                if len(san) > 6: san_str += f"  … +{len(san)-6} more"

                def _render():
                    root.after(0, progress.stop)
                    root.after(0, progress.pack_forget)
                    twrite(result_box, f"  SSL Certificate — {host}:{port}\n", "head")
                    twrite(result_box, f"  {'─'*56}\n", "muted")

                    rows_data = [
                        ("Subject",     subject.get("commonName", "N/A"), "ok" if days_left and days_left>30 else "warn"),
                        ("Issuer",      issuer.get("organizationName", issuer.get("commonName","N/A")), ""),
                        ("Issued",      str(issued)[:19], "muted"),
                        ("Expires",     f"{str(expiry)[:19]}  ({exp_status})", exp_tag),
                        ("TLS version", version or "N/A", "ok"),
                        ("Cipher",      cipher[0] if cipher else "N/A", ""),
                        ("SANs",        san_str or "None", "muted"),
                    ]
                    for label, value, tag in rows_data:
                        twrite(result_box, f"  {'':2}")
                        twrite(result_box, f"  {label:<14}", "key")
                        twrite(result_box, f"  {value}\n", tag or None)

                    save_activity("SSL Checker", f"{host}: valid, expires {str(expiry)[:10]}")
                    set_status(f"SSL valid — {days_left or '?'} days remaining", SUCCESS_COL)
                    toast("SSL certificate is valid", "success")

                root.after(0, _render)

            except ssl.SSLCertVerificationError as e:
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                root.after(0, lambda: twrite(result_box, f"  ✘  Certificate INVALID\n  {e}\n", "err"))
                root.after(0, lambda: set_status("SSL verification failed", DANGER_COL))
                root.after(0, lambda: toast("Certificate invalid!", "error"))
            except Exception as e:
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                root.after(0, lambda: twrite(result_box, f"  Error: {e}\n", "err"))
                root.after(0, lambda: set_status("SSL check failed", DANGER_COL))
                root.after(0, lambda: toast(str(e), "error"))

        threading.Thread(target=_run, daemon=True).start()

    tb.Button(row, text="  Check SSL  ", bootstyle="success",
              command=check_ssl, padding=(14,6)).pack(side=LEFT, padx=12)


# ══════════════════════════════════════════════
#  IP GEOLOCATION  (NEW)
# ══════════════════════════════════════════════

def show_ip_geo():
    clear_main()
    set_status("IP Geolocation ready")
    page_header("IP Geolocation", "Look up geographic and network information for any IP address")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    ip_entry, row = input_row(form, "IP Address or Domain", width=44, placeholder="e.g. 8.8.8.8")

    progress = tb.Progressbar(main_area, mode="indeterminate", bootstyle="warning-striped")
    result_box = make_text_box(main_area, height=16)

    def lookup_ip():
        ip = ip_entry.get().strip()
        if not ip or ip == "e.g. 8.8.8.8":
            toast("Enter an IP address", "warn"); return
        tclear(result_box)
        progress.pack(fill=X, padx=30, pady=(0,6))
        progress.start(12)
        set_status(f"Looking up {ip}…", WARN_COL)

        def _run():
            try:
                import urllib.request
                # resolve domain → IP first
                try:
                    resolved = socket.gethostbyname(ip)
                except: resolved = ip

                url = f"http://ip-api.com/json/{resolved}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,reverse,mobile,proxy,hosting"
                with urllib.request.urlopen(url, timeout=8) as resp:
                    data = json.loads(resp.read().decode())

                def _render():
                    root.after(0, progress.stop)
                    root.after(0, progress.pack_forget)
                    if data.get("status") == "success":
                        twrite(result_box, f"  Geolocation for  {data['query']}\n", "head")
                        twrite(result_box, f"  {'─'*56}\n", "muted")
                        rows_data = [
                            ("IP",          data.get("query","—")),
                            ("Country",     data.get("country","—")),
                            ("Region",      data.get("regionName","—")),
                            ("City",        data.get("city","—")),
                            ("ZIP",         data.get("zip","—")),
                            ("Coordinates", f"{data.get('lat','—')}, {data.get('lon','—')}"),
                            ("ISP",         data.get("isp","—")),
                            ("Org",         data.get("org","—")),
                            ("AS",          data.get("as","—")),
                            ("Reverse DNS", data.get("reverse","—")),
                            ("Mobile",      str(data.get("mobile","—"))),
                            ("Proxy/VPN",   str(data.get("proxy","—"))),
                            ("Hosting",     str(data.get("hosting","—"))),
                        ]
                        for label, value in rows_data:
                            twrite(result_box, f"  {'':2}")
                            twrite(result_box, f"  {label:<14}", "key")
                            twrite(result_box, f"  {value}\n")
                        save_activity("IP Geolocation", f"{data['query']}: {data.get('city','')}, {data.get('country','')}")
                        set_status(f"Geolocation found — {data.get('city','')}, {data.get('country','')}", SUCCESS_COL)
                        toast("Geolocation retrieved", "success")
                    else:
                        twrite(result_box, f"  Error: {data.get('message','Unknown error')}\n", "err")
                        set_status("Geolocation failed", DANGER_COL)
                        toast("Could not geolocate IP", "error")

                root.after(0, _render)

            except Exception as e:
                root.after(0, progress.stop)
                root.after(0, progress.pack_forget)
                root.after(0, lambda: twrite(result_box, f"  Error: {e}\n", "err"))
                root.after(0, lambda: set_status("Geolocation failed", DANGER_COL))
                root.after(0, lambda: toast(str(e), "error"))

        threading.Thread(target=_run, daemon=True).start()

    tb.Button(row, text="  Lookup  ", bootstyle="warning",
              command=lookup_ip, padding=(14,6)).pack(side=LEFT, padx=12)


# ══════════════════════════════════════════════
#  PING TOOL  (NEW)
# ══════════════════════════════════════════════

def show_ping():
    clear_main()
    set_status("Ping Tool ready")
    page_header("Ping Tool", "Measure latency and packet loss to any host")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    host_entry, row = input_row(form, "Target Host / IP", width=44, placeholder="e.g. 8.8.8.8")

    count_var = tb.IntVar(value=4)
    tb.Label(row, text="Packets:", font=FONT_SMALL, foreground=MUTED).pack(side=LEFT, padx=(18,6))
    tb.Spinbox(row, from_=1, to=20, textvariable=count_var, width=5,
               font=("Consolas",12)).pack(side=LEFT)

    progress = tb.Progressbar(main_area, mode="determinate", bootstyle="primary-striped")
    result_box = make_text_box(main_area, height=16)
    running = [False]

    def ping():
        host = host_entry.get().strip()
        if not host or host == "e.g. 8.8.8.8":
            toast("Enter a host", "warn"); return
        tclear(result_box)
        count = count_var.get()
        progress.config(value=0, maximum=count)
        progress.pack(fill=X, padx=30, pady=(0,6))
        set_status(f"Pinging {host}…", WARN_COL)
        running[0] = True

        def _run():
            system = platform.system().lower()
            flag = "-n" if system == "windows" else "-c"
            times = []
            twrite(result_box, f"  Pinging {host}  ({count} packets)\n", "head")
            twrite(result_box, f"  {'─'*54}\n", "muted")
            for i in range(count):
                if not running[0]: break
                try:
                    cmd = ["ping", flag, "1", host]
                    if system != "windows":
                        cmd += ["-W", "3"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                    output = r.stdout + r.stderr
                    # parse time
                    import re
                    m = re.search(r"time[=<]([\d.]+)", output, re.IGNORECASE)
                    if m:
                        ms = float(m.group(1))
                        times.append(ms)
                        root.after(0, lambda _i=i, _ms=ms:
                            twrite(result_box, f"  [{_i+1:>2}/{count}]  ✔  {_ms:.1f} ms\n", "ok"))
                    else:
                        root.after(0, lambda _i=i:
                            twrite(result_box, f"  [{_i+1:>2}/{count}]  ✘  Request timed out\n", "err"))
                    root.after(0, lambda _i=i: progress.config(value=_i+1))
                except Exception as e:
                    root.after(0, lambda: twrite(result_box, f"  Error: {e}\n", "err"))

            def _summary():
                root.after(0, progress.pack_forget)
                if times:
                    sent = count
                    recv = len(times)
                    loss = round((sent-recv)/sent*100)
                    twrite(result_box, f"\n  {'─'*54}\n", "muted")
                    twrite(result_box, f"  Packets: sent={sent}  received={recv}  lost={sent-recv}  ({loss}% loss)\n", "warn" if loss>0 else "ok")
                    twrite(result_box, f"  RTT min={min(times):.1f}ms  avg={sum(times)/len(times):.1f}ms  max={max(times):.1f}ms\n", "ok")
                    save_activity("Ping", f"{host}: avg={sum(times)/len(times):.1f}ms loss={loss}%")
                    set_status(f"Ping complete — {host}", SUCCESS_COL)
                    toast(f"Ping done: avg {sum(times)/len(times):.1f} ms, {loss}% loss",
                          "success" if loss==0 else "warn")
                else:
                    twrite(result_box, "\n  All packets lost.\n", "err")
                    set_status("Ping failed", DANGER_COL)
                    toast("Host unreachable", "error")

            root.after(0, _summary)

        threading.Thread(target=_run, daemon=True).start()

    def stop_ping():
        running[0] = False
        toast("Ping stopped", "warn")
        set_status("Ping stopped", WARN_COL)

    tb.Button(row, text="  Start Ping  ", bootstyle="primary",
              command=ping, padding=(14,6)).pack(side=LEFT, padx=12)
    tb.Button(row, text="  Stop  ", bootstyle="danger-outline",
              command=stop_ping, padding=(14,6)).pack(side=LEFT, padx=(0,4))


# ══════════════════════════════════════════════
#  SUBNET CALCULATOR  (NEW)
# ══════════════════════════════════════════════

def show_subnet():
    clear_main()
    set_status("Subnet Calculator ready")
    page_header("Subnet Calculator", "Calculate network address, broadcast, host range, and usable hosts from CIDR notation")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)
    cidr_entry, row = input_row(form, "IP Address / CIDR", width=30, placeholder="e.g. 192.168.1.0/24")

    result_box = make_text_box(main_area, height=18)

    def calculate():
        cidr = cidr_entry.get().strip()
        if not cidr or cidr == "e.g. 192.168.1.0/24":
            toast("Enter a CIDR address", "warn"); return
        tclear(result_box)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            first_host = str(hosts[0])  if hosts else "N/A"
            last_host  = str(hosts[-1]) if hosts else "N/A"

            rows_data = [
                ("CIDR",           str(net)),
                ("Network",        str(net.network_address)),
                ("Broadcast",      str(net.broadcast_address)),
                ("Subnet Mask",    str(net.netmask)),
                ("Wildcard Mask",  str(net.hostmask)),
                ("Prefix Length",  f"/{net.prefixlen}"),
                ("IP Version",     f"IPv{net.version}"),
                ("First Host",     first_host),
                ("Last Host",      last_host),
                ("Usable Hosts",   f"{net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses:,}"),
                ("Total Addresses",f"{net.num_addresses:,}"),
                ("Is Private",     str(net.is_private)),
                ("Is Global",      str(net.is_global)),
            ]

            twrite(result_box, f"  Subnet Analysis  ─  {cidr}\n", "head")
            twrite(result_box, f"  {'─'*56}\n", "muted")
            for label, value in rows_data:
                twrite(result_box, f"  {'':2}")
                twrite(result_box, f"  {label:<18}", "key")
                twrite(result_box, f"  {value}\n")

            # Show first 8 + last host as sample
            if len(hosts) > 1:
                twrite(result_box, f"\n  {'─'*56}\n", "muted")
                twrite(result_box, f"  Sample hosts\n", "head")
                for h in hosts[:8]:
                    twrite(result_box, f"    {str(h)}\n", "ok")
                if len(hosts) > 8:
                    twrite(result_box, f"    … {len(hosts)-8} more hosts …\n", "muted")
                    twrite(result_box, f"    {str(hosts[-1])}\n", "ok")

            save_activity("Subnet Calculator", str(net))
            set_status(f"Subnet calculated — {net}", SUCCESS_COL)
            toast(f"{net.num_addresses:,} addresses, {max(0,net.num_addresses-2):,} usable", "success")

        except ValueError as e:
            twrite(result_box, f"  Invalid CIDR notation: {e}\n", "err")
            toast("Invalid CIDR notation", "error")

    tb.Button(row, text="  Calculate  ", bootstyle="secondary",
              command=calculate, padding=(14,6)).pack(side=LEFT, padx=12)

    # Quick reference
    qr = tb.Frame(main_area, padding=(30,0))
    qr.pack(fill=X)
    tb.Label(qr, text="Common subnet quick reference", font=("Consolas",11,"bold"),
             foreground=MUTED).pack(anchor=W, pady=(6,6))
    common = [
        ("/8",  "255.0.0.0",     "16,777,214"),
        ("/16", "255.255.0.0",   "65,534"),
        ("/24", "255.255.255.0", "254"),
        ("/25", "255.255.255.128","126"),
        ("/28", "255.255.255.240","14"),
        ("/30", "255.255.255.252","2"),
    ]
    for c, mask, hosts_n in common:
        row2 = tb.Frame(qr)
        row2.pack(fill=X, pady=2)
        tb.Label(row2, text=c,       font=("Consolas",11,"bold"), foreground=ACCENT, width=6).pack(side=LEFT)
        tb.Label(row2, text=mask,    font=FONT_SMALL, foreground="#c8d3e8", width=20).pack(side=LEFT)
        tb.Label(row2, text=f"{hosts_n} usable hosts", font=FONT_SMALL, foreground=MUTED).pack(side=LEFT)


# ══════════════════════════════════════════════
#  CIPHER / ENCODE TOOL  (NEW)
# ══════════════════════════════════════════════

def show_cipher():
    clear_main()
    set_status("Cipher Tool ready")
    page_header("Cipher & Encoder Tool", "Encode, decode, and encrypt text using classic algorithms")

    form = tb.Frame(main_area, padding=30)
    form.pack(fill=X)

    tb.Label(form, text="Input Text", font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    input_box = tb.Text(form, font=("Consolas",12), height=5,
                        background=BG_CARD, foreground="#c8d3e8",
                        relief="flat", padx=10, pady=8)
    input_box.pack(fill=X, pady=(4,10))

    # Controls row
    ctrl = tb.Frame(form)
    ctrl.pack(fill=X, pady=(0,10))

    algo_var = tb.StringVar(value="Base64 Encode")
    algo_cb  = ttk.Combobox(ctrl, textvariable=algo_var, font=("Consolas",11),
                             width=26, state="readonly")
    algo_cb["values"] = [
        "Base64 Encode", "Base64 Decode",
        "ROT13",
        "Caesar Cipher (Shift +3)", "Caesar Decipher (Shift +3)",
        "Hex Encode", "Hex Decode",
        "URL Encode", "URL Decode",
        "Binary Encode", "Reverse Text",
        "Count Characters",
    ]
    algo_cb.pack(side=LEFT, padx=(0,10), ipady=4)

    shift_var   = tb.IntVar(value=3)
    shift_label = tb.Label(ctrl, text="Shift:", font=FONT_SMALL, foreground=MUTED)
    shift_spin  = tb.Spinbox(ctrl, from_=1, to=25, textvariable=shift_var, width=4,
                              font=("Consolas",12))

    def on_algo_change(*_):
        if "Caesar" in algo_var.get():
            shift_label.pack(side=LEFT, padx=(0,4))
            shift_spin.pack(side=LEFT)
        else:
            shift_label.pack_forget()
            shift_spin.pack_forget()

    algo_cb.bind("<<ComboboxSelected>>", on_algo_change)

    tb.Label(form, text="Output", font=FONT_SUB, foreground=MUTED).pack(anchor=W)
    output_box = tb.Text(form, font=("Consolas",12), height=5,
                         background=BG_CARD, foreground=SUCCESS_COL,
                         relief="flat", padx=10, pady=8)
    output_box.pack(fill=X, pady=(4,0))

    def run_cipher():
        text = input_box.get("1.0", END).rstrip("\n")
        algo = algo_var.get()
        shift = shift_var.get()
        try:
            if   algo == "Base64 Encode":  out = base64.b64encode(text.encode()).decode()
            elif algo == "Base64 Decode":  out = base64.b64decode(text.encode()).decode("utf-8","replace")
            elif algo == "ROT13":          out = text.translate(str.maketrans(
                                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                                 "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
            elif algo.startswith("Caesar Cipher"):
                out = "".join(
                    chr((ord(c)-65+shift)%26+65) if c.isupper() else
                    chr((ord(c)-97+shift)%26+97) if c.islower() else c
                    for c in text)
            elif algo.startswith("Caesar Decipher"):
                out = "".join(
                    chr((ord(c)-65-shift)%26+65) if c.isupper() else
                    chr((ord(c)-97-shift)%26+97) if c.islower() else c
                    for c in text)
            elif algo == "Hex Encode":     out = text.encode().hex()
            elif algo == "Hex Decode":     out = bytes.fromhex(text.strip()).decode("utf-8","replace")
            elif algo == "URL Encode":
                import urllib.parse
                out = urllib.parse.quote(text)
            elif algo == "URL Decode":
                import urllib.parse
                out = urllib.parse.unquote(text)
            elif algo == "Binary Encode":  out = " ".join(f"{ord(c):08b}" for c in text)
            elif algo == "Reverse Text":   out = text[::-1]
            elif algo == "Count Characters":
                out = (f"Length:     {len(text)}\n"
                       f"Words:      {len(text.split())}\n"
                       f"Lines:      {text.count(chr(10))+1}\n"
                       f"Digits:     {sum(c.isdigit() for c in text)}\n"
                       f"Uppercase:  {sum(c.isupper() for c in text)}\n"
                       f"Lowercase:  {sum(c.islower() for c in text)}\n"
                       f"Symbols:    {sum(not c.isalnum() and not c.isspace() for c in text)}")
            else:
                out = text

            output_box.config(state="normal")
            output_box.delete("1.0", END)
            output_box.insert("1.0", out)
            output_box.config(state="disabled")

            save_activity("Cipher Tool", f"{algo} ({len(text)} chars)")
            set_status(f"{algo} complete", SUCCESS_COL)
            toast(f"{algo} applied", "success")

        except Exception as e:
            output_box.config(state="normal")
            output_box.delete("1.0", END)
            output_box.insert("1.0", f"Error: {e}")
            output_box.config(state="disabled")
            toast(str(e), "error")

    def swap_io():
        out = output_box.get("1.0", END).strip()
        if out:
            input_box.delete("1.0", END)
            input_box.insert("1.0", out)
            output_box.config(state="normal")
            output_box.delete("1.0", END)
            output_box.config(state="disabled")

    def copy_out():
        out = output_box.get("1.0", END).strip()
        if out:
            root.clipboard_clear()
            root.clipboard_append(out)
            toast("Output copied to clipboard", "success")

    btn_row = tb.Frame(form)
    btn_row.pack(anchor=W, pady=(12,0))
    tb.Button(btn_row, text="  Run  ", bootstyle="dark",
              command=run_cipher, padding=(14,8)).pack(side=LEFT, padx=(0,10))
    tb.Button(btn_row, text="↕ Swap", bootstyle="secondary-outline",
              command=swap_io, padding=(10,8)).pack(side=LEFT, padx=(0,10))
    tb.Button(btn_row, text="Copy Output", bootstyle="info-outline",
              command=copy_out, padding=(10,8)).pack(side=LEFT)


# ══════════════════════════════════════════════
#  HISTORY
# ══════════════════════════════════════════════

def export_csv():
    data = get_history()
    with open("security_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ID","Tool","Result","Date"])
        w.writerows(data)
    toast("Exported to security_report.csv", "success")
    set_status("CSV exported", SUCCESS_COL)

def show_history():
    clear_main()
    set_status("History loaded")
    page_header("Activity History", "Full log of all toolkit operations")

    btn_row = tb.Frame(main_area, padding=(30,14,30,0))
    btn_row.pack(fill=X)
    search_var = tb.StringVar()
    tb.Label(btn_row, text="Search:", font=FONT_SMALL, foreground=MUTED).pack(side=LEFT, padx=(0,6))
    search_entry = tb.Entry(btn_row, textvariable=search_var, font=("Consolas",11), width=32)
    search_entry.pack(side=LEFT, ipady=4)
    tb.Button(btn_row, text="  Export CSV  ", bootstyle="success-outline",
              command=export_csv, padding=(10,4)).pack(side=RIGHT)

    tf = tb.Frame(main_area)
    tf.pack(fill=BOTH, expand=True, padx=30, pady=10)
    style = ttk.Style()
    style.configure("Treeview", rowheight=30, font=("Consolas",10))
    style.configure("Treeview.Heading", font=("Consolas",10,"bold"))

    cols = ("ID","Tool","Result","Date")
    tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
    tree.heading("ID",     text="#")
    tree.heading("Tool",   text="Tool")
    tree.heading("Result", text="Result")
    tree.heading("Date",   text="Timestamp")
    tree.column("ID",     width=55,  anchor=CENTER)
    tree.column("Tool",   width=180)
    tree.column("Result", width=420)
    tree.column("Date",   width=165)
    tree.tag_configure("odd",  background="#161d2c")
    tree.tag_configure("even", background=BG_CARD)

    sb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side=LEFT, fill=BOTH, expand=True)
    sb.pack(side=RIGHT, fill=Y)

    all_data = get_history()

    def load_data(rows):
        for item in tree.get_children(): tree.delete(item)
        for i, row in enumerate(rows):
            tree.insert("", END, values=(row[0],row[1],row[2],row[3]),
                        tags=("even" if i%2==0 else "odd",))

    def on_search(*_):
        q = search_var.get().lower()
        load_data([r for r in all_data if q in str(r).lower()])

    search_var.trace_add("write", on_search)
    load_data(all_data)


# ══════════════════════════════════════════════
#  ANALYTICS
# ══════════════════════════════════════════════

def show_analytics():
    clear_main()
    set_status("Analytics loaded")
    page_header("Analytics", "Visual breakdown of all toolkit usage")

    stats = get_stats()
    all_history = get_history()

    labels = ["Passwords","Port Scans","URLs","Hashes","DNS","SSL","IP Geo","Ping","Subnet","Cipher","PW Gen"]
    colors = [SUCCESS_COL, WARN_COL, "#a29bfe", MUTED, ACCENT,
              "#2ed573","#ffa502","#ff6b81","#74b9ff","#fd79a8","#00cec9"]

    # Count from history
    tool_names = ["Password Analyzer","Port Scanner","URL Inspector","Hash Generator",
                  "DNS Lookup","SSL Checker","IP Geolocation","Ping","Subnet Calculator",
                  "Cipher Tool","Password Generator"]
    values = []
    for tool in tool_names:
        count = sum(1 for row in all_history if tool.lower() in str(row[1]).lower())
        values.append(count)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12,5))
    fig.patch.set_facecolor("#151b27")

    bars = ax1.bar(labels, values, color=colors, width=0.6, edgecolor="none")
    ax1.set_title("Tool Usage", pad=14, fontsize=12, fontweight="bold")
    ax1.set_ylabel("Count")
    ax1.set_ylim(0, max(values or [1]) * 1.3)
    ax1.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax1.set_axisbelow(True)
    plt.setp(ax1.get_xticklabels(), rotation=35, ha="right", fontsize=8)
    for bar, val in zip(bars, values):
        if val > 0:
            ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
                     str(val), ha="center", va="bottom", fontsize=9,
                     color="#c8d3e8", fontweight="bold")

    non_zero = [(l,v,c) for l,v,c in zip(labels,values,colors) if v>0]
    if non_zero:
        ls2, vs2, cs2 = zip(*non_zero)
        wedges, texts, autotexts = ax2.pie(vs2, labels=ls2, autopct="%1.0f%%",
                                            colors=cs2, startangle=120,
                                            wedgeprops={"edgecolor":"#151b27","linewidth":2},
                                            textprops={"fontsize":8})
        for at in autotexts:
            at.set_color("#151b27"); at.set_fontweight("bold")
    else:
        ax2.text(0, 0, "No data yet", ha="center", va="center", fontsize=13, color=MUTED)

    ax2.set_title("Distribution", pad=14, fontsize=12, fontweight="bold")
    fig.tight_layout(pad=2.5)

    canvas = FigureCanvasTkAgg(fig, master=main_area)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=BOTH, expand=True, padx=30, pady=10)


# ══════════════════════════════════════════════
#  SETTINGS
# ══════════════════════════════════════════════

def clear_db_history():
    conn = sqlite3.connect("security_toolkit.db")
    conn.cursor().execute("DELETE FROM activity")
    conn.commit(); conn.close()
    toast("History cleared from database", "warn")
    set_status("History cleared", WARN_COL)

def show_settings():
    clear_main()
    set_status("Settings")
    page_header("Settings", "Configure toolkit preferences")

    content = tb.Frame(main_area, padding=30)
    content.pack(fill=X)

    def section(title):
        tb.Label(content, text=title, font=("Consolas",12,"bold"), foreground=ACCENT).pack(anchor=W, pady=(16,4))
        ttk.Separator(content).pack(fill=X)

    def setting_row(label, widget_fn):
        row = tb.Frame(content, padding=(0,8))
        row.pack(fill=X)
        tb.Label(row, text=label, font=FONT_SUB, foreground="#c8d3e8", width=28, anchor=W).pack(side=LEFT)
        widget_fn(row)

    section("Database")
    setting_row("Activity History",  lambda p: tb.Button(p, text="Clear History",
        bootstyle="danger-outline", command=clear_db_history, padding=(10,4)).pack(side=LEFT))
    setting_row("Export Records",    lambda p: tb.Button(p, text="Export to CSV",
        bootstyle="success-outline", command=export_csv, padding=(10,4)).pack(side=LEFT))

    section("Info")
    setting_row("Theme",          lambda p: tb.Label(p, text="Cyborg (Dark)", font=FONT_SUB, foreground=MUTED).pack(side=LEFT))
    setting_row("Database",       lambda p: tb.Label(p, text="SQLite 3",      font=FONT_SUB, foreground=MUTED).pack(side=LEFT))
    setting_row("Chart Library",  lambda p: tb.Label(p, text="Matplotlib",    font=FONT_SUB, foreground=MUTED).pack(side=LEFT))
    setting_row("Version",        lambda p: tb.Label(p, text="v2.0",          font=FONT_SUB, foreground=MUTED).pack(side=LEFT))


# ══════════════════════════════════════════════
#  ABOUT
# ══════════════════════════════════════════════

def show_about():
    clear_main()
    set_status("About")
    page_header("About", "Cyber Security Toolkit v2.0")

    content = tb.Frame(main_area, padding=30)
    content.pack(fill=BOTH)

    tb.Label(content, text="🛡  Cyber Security Toolkit",
             font=("Consolas",20,"bold"), foreground=ACCENT).pack(anchor=W)
    tb.Label(content, text="Version 2.0  •  Developed by Deswanth",
             font=FONT_SUB, foreground=MUTED).pack(anchor=W, pady=(4,18))

    features = [
        ("🔑","Password Analyzer",   "Strength analysis with visual meter"),
        ("🔐","Password Generator",  "Cryptographic random password creation"),
        ("📡","Port Scanner",        "Open port detection on any host"),
        ("🔗","URL Inspector",       "Safety and reachability analysis"),
        ("#" ,"Hash Generator",      "MD5 & SHA-256 file checksums"),
        ("🌐","DNS Lookup",          "A, MX, NS, TXT, CNAME, PTR records"),
        ("🔒","SSL Checker",         "Certificate expiry, issuer, cipher"),
        ("📍","IP Geolocation",      "Country, city, ISP, coordinates"),
        ("📶","Ping Tool",           "Latency and packet loss measurement"),
        ("🔢","Subnet Calculator",   "CIDR range, hosts, broadcast"),
        ("🔤","Cipher Tool",         "Base64, ROT13, Caesar, Hex, URL"),
        ("📊","Analytics",           "Charts of all toolkit usage"),
    ]

    grid = tb.Frame(content)
    grid.pack(fill=X)

    for i, (ico, name, desc) in enumerate(features):
        card = tb.Frame(grid, padding=14, style="dark.TFrame")
        card.grid(row=i//3, column=i%3, padx=6, pady=5, sticky="nsew")
        grid.columnconfigure(i%3, weight=1)
        tb.Label(card, text=f"{ico}  {name}", font=("Consolas",10,"bold"), foreground=ACCENT).pack(anchor=W)
        tb.Label(card, text=desc, font=FONT_SMALL, foreground=MUTED, wraplength=220, justify=LEFT).pack(anchor=W, pady=(2,0))

    tb.Label(content,
             text="\nPython  •  Tkinter  •  ttkbootstrap  •  SQLite  •  Matplotlib  •  socket  •  ssl  •  ipaddress",
             font=FONT_SMALL, foreground=MUTED).pack(anchor=W, pady=(16,0))


# ══════════════════════════════════════════════
#  LAUNCH
# ══════════════════════════════════════════════

show_dashboard()
root.mainloop()