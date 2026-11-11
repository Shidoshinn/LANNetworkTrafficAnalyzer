
import tkinter as tk
from tkinter import ttk


# SAMPLE PACKETS FOR GUI TESTING ONLY
SAMPLE_PACKETS = [
    {
        "no": 1,
        "time": "12:00:01",
        "src": "192.168.1.5",
        "dst": "8.8.8.8",
        "protocol": "UDP",
        "length": 74,
        "info": "DNS query"
    },
    {
        "no": 2,
        "time": "12:00:02",
        "src": "8.8.8.8",
        "dst": "192.168.1.5",
        "protocol": "UDP",
        "length": 90,
        "info": "DNS response"
    },
    {
        "no": 3,
        "time": "12:00:03",
        "src": "192.168.1.5",
        "dst": "142.250.1.1",
        "protocol": "TCP",
        "length": 66,
        "info": "SYN"
    },
]


# PACKET TABLE COLUMNS
COLUMNS = (
    "no",
    "time",
    "src",
    "dst",
    "protocol",
    "length",
    "info"
)


class PacketApp(tk.Tk):
    """Main window for the LAN Traffic Analyzer."""

    def __init__(
        self,
        on_start=None,
        on_stop=None,
        on_refresh=None
    ):
        super().__init__()

        self.title("NETWORK TRAFFIC ANALYZER")
        self.geometry("1100x600")
        self.minsize(800, 450)

        # Main application callbacks
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_refresh = on_refresh

        # Maps displayed adapter names to actual Npcap names
        self._interface_name_by_label = {}

        self._build_controls()
        self._build_table()
        self._build_status()

    # --------------------------------------------------
    # CONTROL PANEL
    # --------------------------------------------------

    def _build_controls(self):
        """Create interface selector and control buttons."""

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=8)

        ttk.Label(
            bar,
            text="Network Interface:"
        ).pack(side="left", padx=(0, 6))

        self.interface_var = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            bar,
            textvariable=self.interface_var,
            state="readonly",
            width=55
        )

        self.interface_combo.pack(
            side="left",
            padx=(0, 8)
        )

        self.refresh_button = ttk.Button(
            bar,
            text="Refresh",
            command=self._refresh_interfaces
        )

        self.refresh_button.pack(
            side="left",
            padx=(0, 8)
        )

        self.start_button = ttk.Button(
            bar,
            text="Start",
            command=self._start
        )

        self.start_button.pack(side="left")

        self.stop_button = ttk.Button(
            bar,
            text="Stop",
            command=self._stop,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=4
        )

        self.clear_button = ttk.Button(
            bar,
            text="Clear",
            command=self.clear_packets
        )

        self.clear_button.pack(side="left")

    # --------------------------------------------------
    # NETWORK INTERFACE MANAGEMENT
    # --------------------------------------------------

    def _refresh_interfaces(self):
        """Refresh available Ethernet and Wi-Fi adapters."""

        if self.on_refresh:
            self.on_refresh()

    def set_interfaces(self, interfaces):
        """
        Populate the interface dropdown.

        Only Ethernet and Wi-Fi should be supplied by capture.py.

        The displayed adapter name is separate from its
        actual Scapy/Npcap capture device name.
        """

        current_selection = self.interface_var.get()

        self._interface_name_by_label = {}

        labels = []
        recommended_label = None

        for entry in interfaces or []:

            if isinstance(entry, dict):

                name = entry.get("name", "")

                # Actual Npcap interface name
                capture_name = entry.get(
                    "capture_name",
                    name
                )

                ip_address = entry.get("ip", "")

                is_default = entry.get(
                    "is_default_route",
                    False
                )

            else:

                # Support plain string interfaces
                name = str(entry)
                capture_name = name
                ip_address = ""
                is_default = False

            if not name or not capture_name:
                continue

            # Allow only the two physical adapters
            if name.lower() not in ("ethernet", "wi-fi", "wifi"):
                continue

            # Display friendly adapter name
            label = name

            if ip_address:
                label += f" [{ip_address}]"

            if is_default:
                label += " ★ DEFAULT ROUTE"
                recommended_label = label

            labels.append(label)

            # IMPORTANT:
            # Store actual Npcap name, not display label
            self._interface_name_by_label[label] = capture_name

        self.interface_combo["values"] = labels

        # Preserve the previous selection if possible
        if current_selection in labels:
            self.interface_var.set(current_selection)

        elif recommended_label:
            self.interface_var.set(recommended_label)

        elif labels:
            self.interface_var.set(labels[0])

        else:
            self.interface_var.set("")
            self.set_status(
                "No Ethernet or Wi-Fi adapters found"
            )

    def get_selected_interface(self):
        """
        Return the actual Scapy/Npcap interface name.
        """

        selected_label = self.interface_var.get().strip()

        return self._interface_name_by_label.get(
            selected_label,
            ""
        )

    # --------------------------------------------------
    # CAPTURE BUTTON STATES
    # --------------------------------------------------

    def set_capture_state(self, capturing):
        """Update button states during packet capture."""

        self.interface_combo.configure(
            state="disabled" if capturing else "readonly"
        )

        self.refresh_button.configure(
            state="disabled" if capturing else "normal"
        )

        self.start_button.configure(
            state="disabled" if capturing else "normal"
        )

        self.stop_button.configure(
            state="normal" if capturing else "disabled"
        )

    # --------------------------------------------------
    # PACKET TABLE
    # --------------------------------------------------

    def _build_table(self):
        """Create the packet table and scrollbar."""

        frame = ttk.Frame(self)

        frame.pack(
            fill="both",
            expand=True,
            padx=8,
            pady=4
        )

        self.tree = ttk.Treeview(
            frame,
            columns=COLUMNS,
            show="headings"
        )

        # Configure table headings
        for col in COLUMNS:

            self.tree.heading(
                col,
                text=col.upper()
            )

            self.tree.column(
                col,
                width=110,
                anchor="w"
            )

        self.tree.column("no", width=55)
        self.tree.column("time", width=100)
        self.tree.column("src", width=140)
        self.tree.column("dst", width=140)
        self.tree.column("protocol", width=100)
        self.tree.column("length", width=90)
        self.tree.column("info", width=300)

        # Vertical scrollbar
        scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(
            yscrollcommand=scroll.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scroll.pack(
            side="right",
            fill="y"
        )

    def add_packet(self, pkt: dict):
        """Insert a captured packet into the table."""

        values = [
            pkt.get(column, "")
            for column in COLUMNS
        ]

        self.tree.insert(
            "",
            "end",
            values=values
        )

        # Automatically scroll to latest packet
        self.tree.yview_moveto(1)

    def clear_packets(self):
        """Remove all packet records from the table."""

        self.tree.delete(
            *self.tree.get_children()
        )

        self.set_status("Packet table cleared")

    # --------------------------------------------------
    # STATUS BAR
    # --------------------------------------------------

    def _build_status(self):
        """Create the application status bar."""

        self.status = tk.StringVar(
            value="Idle"
        )

        ttk.Label(
            self,
            textvariable=self.status,
            relief="sunken",
            anchor="w"
        ).pack(
            fill="x",
            side="bottom"
        )

    def set_status(self, text: str):
        """Update the application status message."""

        self.status.set(text)

    # --------------------------------------------------
    # START CAPTURE
    # --------------------------------------------------

    def _start(self):
        """Start capturing on the selected adapter."""

        selected_interface = self.get_selected_interface()

        if not selected_interface:

            self.set_status(
                "Please select an Ethernet or Wi-Fi adapter"
            )

            return

        if self.on_start:

            self.on_start(selected_interface)

        else:

            self.set_status(
                "Capture callback is not connected"
            )

    # --------------------------------------------------
    # STOP CAPTURE
    # --------------------------------------------------

    def _stop(self):
        """Stop the current packet capture."""

        if self.on_stop:

            self.on_stop()

        else:

            self.set_status("Stopped")


# ------------------------------------------------------
# GUI TEST MODE
# ------------------------------------------------------

if __name__ == "__main__":

    app = PacketApp()

    # Sample adapters for GUI testing only
    app.set_interfaces([
        {
            "name": "Ethernet",
            "capture_name": "Ethernet",
            "ip": "192.168.1.61"
        },
        {
            "name": "Wi-Fi",
            "capture_name": "Wi-Fi",
            "ip": "192.168.1.4"
        }
    ])

    for packet in SAMPLE_PACKETS:
        app.add_packet(packet)

    app.mainloop()
