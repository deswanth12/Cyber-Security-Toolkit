import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog
from tkinter import ttk

from password_checker import check_password
from scanner import scan_common_ports
from hash_generator import generate_md5, generate_sha256
from checker import check_url
from database import save_activity, get_history

# ==========================
# WINDOW
# ==========================

root = tb.Window(themename="cyborg")
root.title("Cyber Security Toolkit")
root.geometry("1200x700")

# ==========================
# LAYOUT
# ==========================

sidebar = tb.Frame(root, width=250)
sidebar.pack(side=LEFT, fill=Y)

main_area = tb.Frame(root)
main_area.pack(side=RIGHT, fill=BOTH, expand=True)

# SHIELD ICON
tb.Label(
    sidebar,
    text="🛡",
    font=("Segoe UI Emoji", 50)
).pack(pady=10)

# TITLE
tb.Label(
    sidebar,
    text="Cyber Security\nToolkit",
    font=("Segoe UI", 22, "bold")
).pack(pady=20)

# ==========================
# HELPERS
# ==========================

def clear_main():
    for widget in main_area.winfo_children():
        widget.destroy()