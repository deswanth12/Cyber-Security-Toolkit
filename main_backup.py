import ttkbootstrap as tb
from ttkbootstrap.constants import *
from database import save_activity
from database import get_history

root = tb.Window(themename="cyborg")
root.title("Cyber Security Toolkit")
root.geometry("1200x700")

# Sidebar
sidebar = tb.Frame(root, width=250)
sidebar.pack(side=LEFT, fill=Y)

# Main Area
main_area = tb.Frame(root)
main_area.pack(side=RIGHT, fill=BOTH, expand=True)

title = tb.Label(
    sidebar,
    text="Cyber Security\nToolkit",
    font=("Segoe UI", 20, "bold")
)
title.pack(pady=20)

buttons = [
    "Dashboard",
    "Password Analyzer",
    "Port Scanner",
    "URL Inspector",
    "Hash Checker",
    "Reports",
    "Settings"
]

for btn in buttons:
    tb.Button(
        sidebar,
        text=btn,
        width=20,
        bootstyle="info-outline"
    ).pack(pady=5)

dashboard_title = tb.Label(
    main_area,
    text="Dashboard",
    font=("Segoe UI", 24, "bold")
)
dashboard_title.pack(pady=20)

card1 = tb.Labelframe(main_area, text="Password Checks")
card1.pack(fill=X, padx=20, pady=10)

tb.Label(card1, text="0").pack(pady=20)

card2 = tb.Labelframe(main_area, text="Ports Scanned")
card2.pack(fill=X, padx=20, pady=10)

tb.Label(card2, text="0").pack(pady=20)

card3 = tb.Labelframe(main_area, text="URLs Checked")
card3.pack(fill=X, padx=20, pady=10)

tb.Label(card3, text="0").pack(pady=20)

root.mainloop()
