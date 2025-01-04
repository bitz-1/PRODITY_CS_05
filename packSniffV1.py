from tkinter import *
from tkinter import ttk
from scapy.all import *
import threading

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")

      
        self.packet_data = []

        self.setup_ui()

    def setup_ui(self):
      
        columns = ("Source IP", "Destination IP", "Protocol", "Payload")
        self.packet_table = ttk.Treeview(self.root, columns=columns, show="headings", height=15)
        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=200)
        self.packet_table.grid(row=0, column=0, columnspan=4, padx=10, pady=10)

        self.start_button = Button(self.root, text="Start", command=self.start_sniffing)
        self.start_button.grid(row=1, column=0, pady=5)

        self.stop_button = Button(self.root, text="Stop", state=DISABLED, command=self.stop_sniffing)
        self.stop_button.grid(row=1, column=1, pady=5)

        Button(self.root, text="Export to CSV", command=self.export_to_csv).grid(row=2, column=2, pady=5)
        Button(self.root, text="Export to JSON", command=self.export_to_json).grid(row=2, column=3, pady=5)

        Label(self.root, text="Protocol:").grid(row=2, column=0, padx=10, pady=5, sticky="W")
        self.protocol_filter = ttk.Combobox(self.root, values=["All", "TCP", "UDP", "ICMP"], state="readonly")
        self.protocol_filter.grid(row=2, column=1, padx=10, pady=5, sticky="W")
        self.protocol_filter.current(0)

        Label(self.root, text="Source/Dest IP:").grid(row=2, column=2, padx=10, pady=5, sticky="W")
        self.ip_filter = Entry(self.root)
        self.ip_filter.grid(row=2, column=3, padx=10, pady=5, sticky="W")

        Button(self.root, text="Show Protocol Distribution", command=self.show_graph).grid(row=3, column=2, pady=5)

       
        Label(self.root, text="Advanced Filter:").grid(row=3, column=0, padx=10, pady=5, sticky="W")
        self.advanced_filter = Entry(self.root)
        self.advanced_filter.grid(row=3, column=1, padx=10, pady=5, sticky="W")
    
    def process_packet(self, packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto

            # Apply filters
            selected_proto = self.protocol_filter.get()
            ip_filter = self.ip_filter.get()
            if selected_proto == "TCP" and proto != 6:
                return
            elif selected_proto == "UDP" and proto != 17:
                return
            elif selected_proto == "ICMP" and proto != 1:
                return
            if ip_filter and ip_filter not in (src_ip, dst_ip):
                return

            payload = "N/A"
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
                payload = payload.decode("utf-8", errors="ignore")[:50]

            # Add packet to data and table
            self.packet_data.append({"Source IP": src_ip, "Destination IP": dst_ip, "Protocol": proto, "Payload": payload})
            self.packet_table.insert("", END, values=(src_ip, dst_ip, proto, payload))

    def start_sniffing(self):
        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.stop_sniffing = True
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def sniff_packets(self):
        self.stop_sniffing = False
        filter_text = self.advanced_filter.get() or None
        sniff(prn=self.process_packet, stop_filter=lambda x: self.stop_sniffing, filter=filter_text)

    def export_to_csv(self):
        import csv
        with open("packets.csv", "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Source IP", "Destination IP", "Protocol", "Payload"])
            writer.writeheader()
            writer.writerows(self.packet_data)
        print("Packets exported to packets.csv")

    def export_to_json(self):
        import json
        with open("packets.json", "w") as file:
            json.dump(self.packet_data, file, indent=4)
        print("Packets exported to packets.json")

    def show_graph(self):
        import matplotlib.pyplot as plt

        # Count protocols
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for packet in self.packet_data:
            if packet["Protocol"] == 6:
                proto_counts["TCP"] += 1
            elif packet["Protocol"] == 17:
                proto_counts["UDP"] += 1
            elif packet["Protocol"] == 1:
                proto_counts["ICMP"] += 1
            else:
                proto_counts["Other"] += 1

        # Plotting the chart
        plt.bar(proto_counts.keys(), proto_counts.values(), color=["blue", "green", "yellow", "red"])
        plt.title("Protocol Distribution")
        plt.xlabel("Protocol")
        plt.ylabel("Packet Count")
        plt.show()

# Run the application
if __name__ == "__main__":
    root = Tk()
    app = PacketSniffer(root)
    root.mainloop()
