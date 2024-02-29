import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import csv
import socket
import struct
import threading
import time

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        # Configure the root window's row and column weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)
        
        # Initialize UI
        self.initialize_ui()
        
        # Variables
        self.running = False
        self.packet_counter = 0
        
        self.show_placeholder()

    def initialize_ui(self):
        # Menu Bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.create_menu()

        # Search Box
        self.search_box = tk.Entry(self.root)
        self.search_box.grid(row=0, column=0, columnspan=4, sticky="ew", padx=10, pady=5)
        self.search_box.insert(0, "Search...")
        self.search_box.bind("<FocusIn>", self.clear_placeholder)
        self.search_box.bind("<FocusOut>", self.restore_placeholder)
        self.search_box.bind("<KeyRelease>", self.search_all)

        # Data Table
        self.initialize_data_table()

        # Description Box
        self.desc_box = tk.Text(self.root, height=10, width=80)
        self.desc_box.grid(row=3, column=0, columnspan=4, padx=10, pady=5, sticky="ew")

        # Buttons
        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=2, column=0, padx=10, pady=5, sticky="ew")


        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        self.clear_button = tk.Button(
        self.root, text="Clear Screen", command=self.clear_screen)
        self.clear_button.grid(row=2, column=2, padx=10, pady=5, sticky="ew")
        

        # Status Bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=4, column=0, columnspan=5, sticky="we")

    def create_menu(self):
        # File Menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open File...", command=self.open_file)
        file_menu.add_command(label="Save As...", command=self.save_file)
        file_menu.add_command(label="Start Sniffing", command=self.start_sniffing)
        file_menu.add_command(label="Stop Sniffing", command=self.stop_sniffing)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Help Menu
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
    def save_file(self):
        file_path = tk.filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if not file_path:
            return  # User cancelled; exit the method
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            # Write headers based on your treeview columns
            writer.writerow([self.tree.heading(col)["text"] for col in self.tree["columns"]])
            for row_id in self.tree.get_children():
                row = self.tree.item(row_id)['values']
                writer.writerow(row)
        self.status_bar.config(text="Data saved successfully.")
        

    def open_file(self):
        file_path = tk.filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if not file_path:
            return  # User cancelled; exit the method
        with open(file_path, 'r', newline='') as file:
            self.tree.delete(*self.tree.get_children())  # Clear current data
            reader = csv.reader(file)
            headers = next(reader)  # Assume first row is headers
            for row in reader:
                self.tree.insert('', tk.END, values=row)
        self.status_bar.config(text="Data loaded successfully.")


    def show_about(self):
        tk.messagebox.showinfo("About", "Packet Sniffer App\nVersion 1.0")

    def initialize_data_table(self):
        style = ttk.Style()
        style.configure("Treeview", highlightthickness=0, bd=0, font=('Calibri', 11))
        style.configure("Treeview.Heading", font=('Calibri', 13, 'bold'))
        
        all_columns = (
            "Packet No.", "Protocol", "Time", "Source IP", "Destination IP",
            "Source MAC", "Destination MAC", "Source Port", "Destination Port",
            "Version", "TTL", "Length", "Data", "Sequence", "Acknowledgement",
            "Flag_URG", "Flag_ACK", "Flag_PSH", "Flag_RST", "Flag_SYN", "Flag_FIN",
        )
        visible_columns = ("Packet No.", "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC", "Protocol")
        
        self.tree = ttk.Treeview(self.root, columns=all_columns, show="headings")
        for col in all_columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, stretch=tk.YES)
        self.tree.grid(row=1, column=0, columnspan=4, sticky="nsew")

        tree_scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=tree_scroll.set)
        tree_scroll.grid(row=1, column=4, sticky="ns")

        self.tree["displaycolumns"] = visible_columns
        self.tree.bind("<<TreeviewSelect>>", self.show_description)


    def initialize_data_table(self):
        all_columns = (
            "Packet No.",
            "Protocol",
            "Time",
            "Source IP",
            "Destination IP",
            "Source MAC",
            "Destination MAC",
            "Source Port",
            "Destination Port",
            "Version",
            "TTL",
            "Length",
            "Data",
            "Sequence",
            "Acknowledgement",
            "Flag_URG",
            "Flag_ACK",
            "Flag_PSH",
            "Flag_RST",
            "Flag_SYN",
            "Flag_FIN",
        )
        visible_columns = ("Packet No.", "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC","Protocol")
    
        # Create the treeview with all columns
        self.tree = ttk.Treeview(self.root, columns=all_columns, show="headings")
        for col in all_columns:
            self.tree.heading(col, text=col, command=lambda: self.sort_column(col))
        self.tree.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

        # Set displaycolumns to show only visible columns
        self.tree["displaycolumns"] = visible_columns

        for col in all_columns:
            self.tree.column(col, width=150)

        tree_scroll = ttk.Scrollbar(
            self.root, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=tree_scroll.set)
        tree_scroll.grid(row=1, column=4, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self.show_description)

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.packet_counter = 0
            threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.running = False

        
    def clear_screen(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_bar.config(text="Screen cleared.")

    def tcp_segment(self, data):
        src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin

        # return flag_urg
    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]
    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H',data[:4])
        return icmp_type, code, checksum, data[4:]

    def sniff_packets(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while self.running:
            try:
                raw_data, _ = conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
                if eth_proto == 8:
                    (version, ttl, length, proto, src, target, data) = self.ipv4_packet(data)
                    if proto == 6:  # If it's a TCP packet
                        src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = self.tcp_segment(data)
                        prorocol_name="TCP"
                        # Now use these variables as intended when inserting into the tree
                        self.packet_counter += 1
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.tree.insert(
                            "",
                            "end",
                            values=(
                                self.packet_counter,
                                prorocol_name,
                                timestamp,
                                src,
                                target,
                                src_mac,
                                dest_mac,
                                src_port,
                                dest_port,
                                version,
                                ttl,
                                length,
                                data,
                                sequence,
                                acknowledgement,
                                flag_urg,
                                flag_ack,
                                flag_psh,
                                flag_rst,
                                flag_syn,
                                flag_fin,
                                # Include other flags as needed
                            ),
                        )
                        pass
                    elif proto == 17:  # UDP
                        src_port, dest_port, length, _ = self.udp_segment(data)
                        prorocol_name = "UDP"
                        # Add your code here to display UDP packet information
                        self.packet_counter += 1
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.tree.insert(
                            "",
                            "end",
                            values=(
                                self.packet_counter,
                                prorocol_name,
                                timestamp,
                                src,
                                target,
                                src_mac,
                                dest_mac,
                                src_port,
                                dest_port,
                                version,
                                ttl,
                                length,
                                data,
                                # "",  # Sequence for UDP is not applicable
                                # "",  # Acknowledgement for UDP is not applicable
                                # "",  # Flags are not applicable for UDP
                                # "",  # You can leave flag-related fields empty or remove them for UDP
                                # "",
                                # "",
                            ),
                        )
                    elif proto == 1:
                        icmp_type, code, checksum, data = self.icmp_packet(data)
                        prorocol_name="ICMP"
                        self.packet_counter += 1
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.tree.insert(
                            "",
                            "end",
                            values=(
                                self.packet_counter,
                                prorocol_name,
                                timestamp,
                                src,
                                target,
                                src_mac,
                                dest_mac,
                                src_port,
                                dest_port,
                                version,
                                ttl,
                                length,
                                data,
                            ),
                        )
            except Exception as e:
                print(e)
                continue


    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
        return (
            self.get_mac_addr(dest_mac),
            self.get_mac_addr(src_mac),
            socket.ntohs(proto),
            data[14:],
        )

    def get_mac_addr(self, bytes_addr):
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        _, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
        return (
            version,
            header_length,
            proto,
            proto,
            self.ipv4(src),
            self.ipv4(target),
            data[header_length:],
        )

    def ipv4(self, addr):
        return ".".join(map(str, addr))

    def sort_column(self, column):
        current_heading = self.tree.heading(column, "text")
        data = [
            (self.tree.set(child, column), child)
            for child in self.tree.get_children("")
        ]
        data.sort(reverse=current_heading.startswith("-"))
        for index, item in enumerate(data):
            self.tree.move(item[1], "", index)
        if current_heading.startswith("-"):
            self.tree.heading(
                column, text=column, command=lambda col=column: self.sort_column(col)
            )
        else:
            self.tree.heading(
                column,
                text=f"-{column}",
                command=lambda col=column: self.sort_column(col),
            )

    def clear_placeholder(self, event):
        if self.search_box.get() == "Search...":
            self.search_box.delete(0, tk.END)

    def restore_placeholder(self, event):
        if not self.search_box.get():
            self.search_box.insert(0, "Search...")

    def search_all(self, event):
        self.search(self.search_box)

    def search(self, entry, column=""):
        search_term = entry.get().lower()
        print(search_term)
        items = self.tree.get_children("")
        for item in items:
            values = self.tree.item(item, "values")
            if values:
                if search_term.startswith("src_ip:"):
                    search = search_term.replace("src_ip:", "")
                    src_ip_index = self.tree["columns"].index("Source IP")
                    if values[src_ip_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("dst_ip:"):
                    search = search_term.replace("dst_ip:", "")
                    dst_ip_index = self.tree["columns"].index("Destination IP")
                    if values[dst_ip_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("src_mac:"):
                    search = search_term.replace("src_mac:", "")
                    src_mac_index = self.tree["columns"].index("Source MAC")
                    if values[src_mac_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                elif search_term.startswith("dst_mac:"):
                    search = search_term.replace("dst_mac:", "")
                    dst_mac_index = self.tree["columns"].index("Destination MAC")
                    if values[dst_mac_index].lower().startswith(search):
                        self.tree.selection_add(item)
                    else:
                        self.tree.selection_remove(item)
                else:
                    self.tree.selection_remove(item)

    def show_placeholder(self):
        self.desc_box.delete("1.0", tk.END)
        self.desc_box.insert(tk.END, "Description")

    def show_description(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            description = "\n".join(
                [
                    f"{column}: {value}"
                    for column, value in zip(self.tree["columns"], values)
                ]
            )
            self.desc_box.delete("1.0", tk.END)
            self.desc_box.insert(tk.END, description)
        else:
            self.show_placeholder()
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()