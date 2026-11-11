
"""
GUI module for LAN Network Traffic Analyzer.

Features:
- Ethernet and Wi-Fi interface selection
- Start and Stop packet capture
- Refresh network interfaces
- Display packet date and time
- Display captured packet information
- Clear displayed packet records
- Export packet logs through main.py
- Horizontal and vertical table scrolling
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime


# ------------------------------------------------------
# SAMPLE PACKETS FOR GUI TESTING ONLY
# ------------------------------------------------------

SAMPLE_PACKETS = [
    {
        "no": 1,
        "date": "2026-11-12",
        "time": "12:00:01",
        "src": "192.168.1.5",
        "dst": "8.8.8.8",
        "protocol": "UDP",
        "length": 74,
        "info": "DNS query"
    },
    {
        "no": 2,
        "date": "2026-11-12",
        "time": "12:00:02",
        "src": "8.8.8.8",
        "dst": "192.168.1.5",
        "protocol": "UDP",
        "length": 90,
        "info": "DNS response"
    },
    {
        "no": 3,
        "date": "2026-11-12",
        "time": "12:00:03",
        "src": "192.168.1.5",
        "dst": "142.250.1.1",
        "protocol": "TCP",
        "length": 66,
        "info": "SYN"
    },
]


# ------------------------------------------------------
# PACKET TABLE COLUMNS
# ------------------------------------------------------

COLUMNS = (
    "no",
    "date",
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
        on_refresh=None,
        on_export=None
    ):
        super().__init__()

        # Window settings
        self.title("NETWORK TRAFFIC ANALYZER")
        self.geometry("1250x680")
        self.minsize(900, 450)

        # Application callbacks
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_refresh = on_refresh
        self.on_export = on_export

        # Interface mapping
        self._interface_name_by_label = {}

        # Packet counter
        self.packet_count = 0

        # Build GUI
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
            width=38
        )

        self.interface_combo.pack(side="left", padx=(0, 8))

        self.refresh_button = ttk.Button(
            bar,
            text="Refresh",
            command=self._refresh_interfaces
        )
        self.refresh_button.pack(side="left", padx=3)

        self.start_button = ttk.Button(
            bar,
            text="Start",
            command=self._start
        )
        self.start_button.pack(side="left", padx=3)

        self.stop_button = ttk.Button(
            bar,
            text="Stop",
            command=self._stop,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=3)

        self.clear_button = ttk.Button(
            bar,
            text="Clear",
            command=self.clear_packets
        )
        self.clear_button.pack(side="left", padx=3)

        self.export_button = ttk.Button(
            bar,
            text="Export Logs",
            command=self._export
        )
        self.export_button.pack(side="left", padx=3)

    # --------------------------------------------------
    # NETWORK INTERFACE MANAGEMENT
    # --------------------------------------------------

    def _refresh_interfaces(self):
        """Refresh available network interfaces."""

        if self.on_refresh:
            self.on_refresh()
        else:
            self.set_status(
                "Interface refresh callback is not connected"
            )

    def set_interfaces(self, interfaces):
        """
        Populate the interface dropdown.

        Only Ethernet and Wi-Fi adapters are displayed.
        Actual Scapy/Npcap names are retained for capture.
        """

        current_selection = self.interface_var.get()

        self._interface_name_by_label = {}

        labels = []
        recommended_label = None

        for entry in interfaces or []:

            if isinstance(entry, dict):
                name = entry.get("name", "")
                capture_name = entry.get("capture_name", name)
                ip_address = entry.get("ip", "")
                is_default = entry.get("is_default_route", False)

            else:
                name = str(entry)
                capture_name = name
                ip_address = ""
                is_default = False

            if not name or not capture_name:
                continue

            # Allow Ethernet and Wi-Fi adapters.
            normalized_name = name.strip().lower()

            is_ethernet = normalized_name.startswith("ethernet")
            is_wifi = (
                normalized_name.startswith("wi-fi")
                or normalized_name.startswith("wifi")
            )

            if not (is_ethernet or is_wifi):
                continue

            # Friendly display label
            label = name

            if ip_address:
                label += f" [{ip_address}]"

            if is_default:
                label += " ★ DEFAULT ROUTE"
                recommended_label = label

            labels.append(label)

            # Map display label to actual capture name
            self._interface_name_by_label[label] = capture_name

        self.interface_combo["values"] = labels

        # Preserve current selection
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
            return

        self.set_status(
            f"Found {len(labels)} Ethernet/Wi-Fi adapter(s)"
        )

    def get_selected_interface(self):
        """Return the actual Scapy/Npcap interface name."""

        selected_label = self.interface_var.get().strip()

        return self._interface_name_by_label.get(
            selected_label,
            ""
        )

    # --------------------------------------------------
    # CAPTURE BUTTON STATES
    # --------------------------------------------------

    def set_capture_state(self, capturing):
        """Update button states while capturing."""

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
        """Create packet table and scrollbars."""

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
            show="headings",
            selectmode="extended"
        )

        # Table headings
        headings = {
            "no": "NO.",
            "date": "DATE",
            "time": "TIME",
            "src": "SOURCE",
            "dst": "DESTINATION",
            "protocol": "PROTOCOL",
            "length": "LENGTH",
            "info": "INFORMATION"
        }

        for column in COLUMNS:
            self.tree.heading(
                column,
                text=headings[column]
            )

            self.tree.column(
                column,
                width=110,
                anchor="center"
            )

        # Column widths
        self.tree.column("no", width=55, anchor="center")
        self.tree.column("date", width=105, anchor="center")
        self.tree.column("time", width=95, anchor="center")
        self.tree.column("src", width=150, anchor="center")
        self.tree.column("dst", width=150, anchor="center")
        self.tree.column("protocol", width=100, anchor="center")
        self.tree.column("length", width=85, anchor="center")
        self.tree.column("info", width=350, anchor="w")

        # Vertical scrollbar
        vertical_scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.tree.yview
        )

        # Horizontal scrollbar
        horizontal_scroll = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical_scroll.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal_scroll.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    # --------------------------------------------------
    # ADD PACKET
    # --------------------------------------------------

    def add_packet(self, pkt: dict):
        """Insert a captured packet into the table."""

        if not isinstance(pkt, dict):
            return

        self.packet_count += 1

        packet_number = pkt.get(
            "no",
            self.packet_count
        )

        # Get date and time from packet data.
        timestamp = pkt.get("timestamp", "")

        packet_date = pkt.get("date", "")
        packet_time = pkt.get("time", "")

        # If a full timestamp is available, use it.
        if timestamp:
            try:
                parsed_timestamp = datetime.fromisoformat(
                    str(timestamp)
                )

                if not packet_date:
                    packet_date = parsed_timestamp.strftime(
                        "%Y-%m-%d"
                    )

                if not packet_time:
                    packet_time = parsed_timestamp.strftime(
                        "%H:%M:%S"
                    )

            except ValueError:
                pass

        # If no date was supplied, use the current date.
        if not packet_date:
            packet_date = datetime.now().strftime("%Y-%m-%d")

        # If no time was supplied, use the current time.
        if not packet_time:
            packet_time = datetime.now().strftime("%H:%M:%S")

        values = [
            packet_number,
            packet_date,
            packet_time,
            pkt.get("src", ""),
            pkt.get("dst", ""),
            pkt.get("protocol", "Other"),
            pkt.get("length", 0),
            pkt.get("info", "")
        ]

        self.tree.insert(
            "",
            "end",
            values=values
        )

        # Scroll to latest packet
        self.tree.yview_moveto(1)

        self.set_status(
            f"Packets displayed: {len(self.tree.get_children())}"
        )

    # --------------------------------------------------
    # CLEAR PACKETS
    # --------------------------------------------------

    def clear_packets(self):
        """
        Clear the displayed packet table.

        This does not delete records from SQLite.
        """

        self.tree.delete(
            *self.tree.get_children()
        )

        self.packet_count = 0

        self.set_status(
            "Packet display cleared. Database records are unchanged."
        )

    # --------------------------------------------------
    # EXPORT PACKET LOGS
    # --------------------------------------------------

    def _export(self):
        """Call the export function connected from main.py."""

        if self.on_export:
            self.on_export()
        else:
            self.set_status(
                "Export callback is not connected"
            )

    # --------------------------------------------------
    # STATUS BAR
    # --------------------------------------------------

    def _build_status(self):
        """Create the application status bar."""

        self.status = tk.StringVar(value="Idle")

        status_frame = ttk.Frame(self)

        status_frame.pack(
            fill="x",
            side="bottom"
        )

        ttk.Label(
            status_frame,
            textvariable=self.status,
            relief="sunken",
            anchor="w",
            padding=(6, 4)
        ).pack(fill="x")

    def set_status(self, text: str):
        """Update application status."""

        self.status.set(str(text))

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
            self.set_status(
                "Stop callback is not connected"
            )


# ------------------------------------------------------
# GUI TEST MODE
# ------------------------------------------------------

if __name__ == "__main__":

    app = PacketApp()

    # Sample interfaces for GUI testing only
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

    # Display sample packets
    for packet in SAMPLE_PACKETS:
        app.add_packet(packet)

    app.mainloop()
