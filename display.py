import sqlite3
import tkinter as tk
from tkinter import ttk

def fetch_data():
    conn = sqlite3.connect('network_sniffer.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_addresses")
    ip_data = cursor.fetchall()
    cursor.execute("SELECT * FROM traffic")
    traffic_data = cursor.fetchall()
    conn.close()
    return ip_data, traffic_data

def populate_tree(tree, data):
    for row in data:
        tree.insert("", "end", values=row)

def create_ui():
    root = tk.Tk()
    root.title("Network Sniffer Data")

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    ip_frame = ttk.Frame(notebook)
    traffic_frame = ttk.Frame(notebook)
    notebook.add(ip_frame, text="IP Addresses")
    notebook.add(traffic_frame, text="Traffic")

    ip_tree = ttk.Treeview(ip_frame, columns=("ID", "IP Address"), show="headings")
    ip_tree.heading("ID", text="ID")
    ip_tree.heading("IP Address", text="IP Address")
    ip_tree.pack(expand=True, fill="both")

    traffic_tree = ttk.Treeview(traffic_frame, columns=("ID", "Source", "Destination", "Counter"), show="headings")
    traffic_tree.heading("ID", text="ID")
    traffic_tree.heading("Source", text="Source")
    traffic_tree.heading("Destination", text="Destination")
    traffic_tree.heading("Counter", text="Counter")
    traffic_tree.pack(expand=True, fill="both")

    ip_data, traffic_data = fetch_data()

    populate_tree(ip_tree, ip_data)
    populate_tree(traffic_tree, traffic_data)

    root.mainloop()

if __name__ == "__main__":
    create_ui()
