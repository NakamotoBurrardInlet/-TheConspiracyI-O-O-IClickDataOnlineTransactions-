import csv
import time
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, PcapWriter

# --- Configuration ---
LOG_CSV_PATH = "network_log.csv"
LOG_MCCOS_PATH = "raw_packet_data.mccos"
# --- End Configuration ---

class SnifferLogic:
    """
    Handles the network packet capture, parsing, and logging operations 
    using the scapy library.
    """
    def __init__(self, update_callback):
        """
        Initializes the sniffer with a callback function to update the GUI.
        :param update_callback: Function (packet_data) -> None to refresh the UI.
        """
        self.is_sniffing = False
        self.update_callback = update_callback
        self.stats = {'total_packets': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}

        self._initialize_log_files()

    def _initialize_log_files(self):
        """Prepares CSV file with headers."""
        try:
            with open(LOG_CSV_PATH, 'w', newline='') as csvfile:
                fieldnames = ['Timestamp', 'Source_IP', 'Destination_IP', 'Protocol', 'Length_Bytes', 'Payload_Summary']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        except IOError as e:
            print(f"Error initializing CSV file: {e}")

    def start_sniffing(self):
        """Starts the scapy sniffing process in a blocking manner."""
        self.is_sniffing = True
        print("Sniffing started...")
        try:
            # Note: Scapy's sniff is blocking, so this must be run in a separate thread.
            sniff(prn=self._process_packet, store=0, stop_filter=self._stop_filter)
        except Exception as e:
            print(f"An error occurred during sniffing: {e}. Check permissions (run with sudo/admin).")
        finally:
            self.is_sniffing = False
            print("Sniffing stopped.")

    def _stop_filter(self, packet):
        """Determines when to stop sniffing."""
        return not self.is_sniffing

    def _process_packet(self, packet):
        """
        Extracts data from a single packet, updates the GUI, and logs to files.
        """
        if not self.is_sniffing:
            return

        self.stats['total_packets'] += 1
        
        # --- 1. Extract Core Data ---
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        protocol = 'N/A'
        src_ip = 'N/A'
        dst_ip = 'N/A'
        
        # Check for IP layer (Layer 3)
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check for Transport layer (Layer 4)
            if TCP in packet:
                protocol = 'TCP'
                self.stats['tcp'] += 1
            elif UDP in packet:
                protocol = 'UDP'
                self.stats['udp'] += 1
            elif packet[IP].proto == 1: # ICMP
                protocol = 'ICMP'
                self.stats['icmp'] += 1
            else:
                protocol = str(packet[IP].proto)
                self.stats['other'] += 1

        length = len(packet)
        payload_summary = packet.summary()
        
        packet_data = {
            'id': self.stats['total_packets'],
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'length': length,
            'summary': payload_summary,
            'full_hex': bytes(packet).hex(),
            'packet_layers': packet.show(dump=True) # Full structured view
        }
        
        # --- 2. Update GUI ---
        self.update_callback(packet_data)
        
        # --- 3. Log to Files ---
        self._log_to_csv(packet_data)
        self._log_to_mccos(packet_data)


    def _log_to_csv(self, data):
        """Appends the parsed packet data to the CSV log."""
        try:
            with open(LOG_CSV_PATH, 'a', newline='') as csvfile:
                fieldnames = ['Timestamp', 'Source_IP', 'Destination_IP', 'Protocol', 'Length_Bytes', 'Payload_Summary']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writerow({
                    'Timestamp': data['timestamp'],
                    'Source_IP': data['src_ip'],
                    'Destination_IP': data['dst_ip'],
                    'Protocol': data['protocol'],
                    'Length_Bytes': data['length'],
                    'Payload_Summary': data['summary']
                })
        except IOError as e:
            print(f"Error writing to CSV: {e}")

    def _log_to_mccos(self, data):
        """
        Appends the raw packet data and details to the custom MCCOS text file.
        This provides all bytes, hexadecimal, and protocol details as requested.
        """
        try:
            with open(LOG_MCCOS_PATH, 'a', encoding='utf-8') as f:
                f.write(f"\n--- Packet ID: {data['id']} ({data['timestamp']}) ---\n")
                f.write(f"Source: {data['src_ip']} -> Destination: {data['dst_ip']} | Protocol: {data['protocol']} | Length: {data['length']} bytes\n")
                f.write("--- Full Layer Decipher ---\n")
                f.write(data['packet_layers'])
                f.write("\n--- Hexadecimal Data ---\n")
                f.write(data['full_hex'])
                f.write("\n")
        except IOError as e:
            print(f"Error writing to MCCOS file: {e}")

    def get_stats(self):
        """Returns the current traffic statistics."""
        return self.stats

    def stop_sniffing(self):
        """Sets the flag to stop the sniffing thread gracefully."""
        self.is_sniffing = False

# Helper function to get the current timestamp for log file naming if needed
def get_current_time():
    return time.strftime("%Y%m%d_%H%M%S")
