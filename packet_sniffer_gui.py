import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import sys
import os
from sniffer_logic import SnifferLogic

# --- Configuration ---
APP_TITLE = "Real-time Network Traffic Analyzer"
# --- End Configuration ---

class PacketSnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.sniffer = SnifferLogic(self.update_packet_list)
        self.sniff_thread = None
        self.packets_data = {} # Stores full packet data keyed by ID
        
        self._create_widgets()
        self._setup_layout()

    def _create_widgets(self):
        """Creates all GUI elements."""
        
        # --- 1. Controls Frame ---
        self.control_frame = ttk.Frame(self)
        
        self.start_button = ttk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.status_label = ttk.Label(self.control_frame, text="Status: Ready", foreground="gray")
        
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)
        self.status_label.pack(side=tk.LEFT, padx=20, pady=10)

        # --- 2. Packet List (Treeview) ---
        self.packet_list_frame = ttk.Frame(self)
        
        columns = ('#', 'Time', 'Protocol', 'Source', 'Destination', 'Length', 'Summary')
        self.tree = ttk.Treeview(self.packet_list_frame, columns=columns, show='headings')
        self.tree.heading('#', text='ID')
        self.tree.heading('Time', text='Time')
        self.tree.heading('Protocol', text='Protocol')
        self.tree.heading('Source', text='Source IP')
        self.tree.heading('Destination', text='Destination IP')
        self.tree.heading('Length', text='Length (B)')
        self.tree.heading('Summary', text='Summary')

        # Adjust column widths
        self.tree.column('#', width=40, stretch=tk.NO)
        self.tree.column('Time', width=120, stretch=tk.NO)
        self.tree.column('Protocol', width=80, stretch=tk.NO)
        self.tree.column('Source', width=120, stretch=tk.NO)
        self.tree.column('Destination', width=120, stretch=tk.NO)
        self.tree.column('Length', width=80, stretch=tk.NO)
        self.tree.column('Summary', width=400)
        
        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(self.packet_list_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(self.packet_list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # --- 3. Packet Details (Raw Data, Hex, Layers) ---
        self.details_frame = ttk.LabelFrame(self, text="Packet Details (Hexadecimal, Layers, Cookies, etc.)")
        self.detail_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, height=15, width=50, font=('Consolas', 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- 4. Statistics Panel (Sub-divisions of Details) ---
        self.stats_frame = ttk.LabelFrame(self, text="Real-time Traffic Statistics")
        self.stats_label_text = tk.StringVar(value="Total Packets: 0\nTCP: 0\nUDP: 0\nICMP: 0\nOther: 0")
        self.stats_label = ttk.Label(self.stats_frame, textvariable=self.stats_label_text, justify=tk.LEFT)
        self.stats_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Start the periodic stat update
        self.after(1000, self.update_stats)

    def _setup_layout(self):
        """Arranges frames using grid layout."""
        self.control_frame.pack(fill=tk.X)
        self.packet_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.stats_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

    def start_sniffing(self):
        """Starts the sniffing thread."""
        if not self.sniff_thread or not self.sniff_thread.is_alive():
            self.sniffer.is_sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniffer.start_sniffing, daemon=True)
            self.sniff_thread.start()
            
            self.status_label.config(text="Status: Sniffing LIVE...", foreground="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.status_label.config(text="Status: Sniffing already running.", foreground="orange")

    def stop_sniffing(self):
        """Stops the sniffing process."""
        self.sniffer.stop_sniffing()
        
        # Wait for the thread to actually finish (max 2 seconds)
        for _ in range(20):
            if not self.sniff_thread.is_alive():
                break
            time.sleep(0.1)

        self.status_label.config(text=f"Status: Stopped. Data logged to {self.sniffer.LOG_CSV_PATH} and {self.sniffer.LOG_MCCOS_PATH}", foreground="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_packet_list(self, packet_data):
        """
        Callback function called from the SnifferLogic thread to update the GUI list.
        Uses after() to safely update Tkinter widgets from another thread.
        """
        self.packets_data[packet_data['id']] = packet_data
        
        # Prepare the list row
        row = (
            packet_data['id'],
            packet_data['timestamp'].split(' ')[1], # Just show time
            packet_data['protocol'],
            packet_data['src_ip'],
            packet_data['dst_ip'],
            packet_data['length'],
            packet_data['summary']
        )
        
        # Schedule the update on the main thread
        self.after(0, lambda: self._insert_packet_row(packet_data['id'], row))
        
    def _insert_packet_row(self, packet_id, row):
        """Inserts a new row into the Treeview."""
        self.tree.insert('', tk.END, iid=packet_id, values=row)
        # Ensure only the last 1000 packets are kept to prevent memory overload
        if len(self.tree.get_children()) > 1000:
            self.tree.delete(self.tree.get_children()[0])

    def show_packet_details(self, event):
        """
        Displays the full hexadecimal and layer details of the selected packet.
        """
        selected_item = self.tree.focus()
        if selected_item:
            packet_id = int(selected_item)
            data = self.packets_data.get(packet_id, {})
            
            if data:
                detail_output = []
                detail_output.append(f"--- Full Packet ID: {data['id']} ---")
                detail_output.append(f"Timestamp: {data['timestamp']}")
                detail_output.append(f"Source IP: {data['src_ip']} | Destination IP: {data['dst_ip']}")
                detail_output.append(f"Protocol: {data['protocol']} | Length: {data['length']} bytes\n")
                
                detail_output.append("--- Layer Decipher (Protocol, Data, Cookies, etc.) ---")
                detail_output.append(data['packet_layers'])
                
                detail_output.append("\n--- Raw Hexadecimal Bytes ---")
                # Format hex for easier reading (e.g., 32 bytes per line)
                hex_data = data['full_hex']
                formatted_hex = '\n'.join([hex_data[i:i+64] for i in range(0, len(hex_data), 64)])
                detail_output.append(formatted_hex)

                self.detail_text.delete('1.0', tk.END)
                self.detail_text.insert(tk.END, '\n'.join(detail_output))
                self.detail_text.see(tk.END)

    def update_stats(self):
        """Periodically updates the statistics panel."""
        stats = self.sniffer.get_stats()
        
        stats_text = (
            f"Total Packets: {stats['total_packets']}\n"
            f"TCP (Handshake/Streaming): {stats['tcp']}\n"
            f"UDP (DNS/Video): {stats['udp']}\n"
            f"ICMP (Pings/Errors): {stats['icmp']}\n"
            f"Other Protocols: {stats['other']}"
        )
        
        self.stats_label_text.set(stats_text)
        self.after(1000, self.update_stats) # Schedule next update

    def on_closing(self):
        """Handles graceful shutdown when the window is closed."""
        self.stop_sniffing() # Ensure sniffing thread is stopped
        # A small delay to allow the thread to stop
        if self.sniff_thread and self.sniff_thread.is_alive():
            time.sleep(0.5)
        self.destroy()
        
# Check if the sniffer_logic file exists before running
if __name__ == "__main__":
    if not os.path.exists('sniffer_logic.py'):
        print("ERROR: sniffer_logic.py not found. Please ensure both files are saved in the same directory.")
        sys.exit(1)
        
    print(f"--- {APP_TITLE} ---")
    print("WARNING: This program requires 'scapy' and must be run with elevated permissions (sudo/admin) to capture live traffic.")
    print("Starting GUI...")
    app = PacketSnifferApp()
    app.mainloop()
