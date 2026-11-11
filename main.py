
"""
Main application entry point for LAN Network Traffic Analyzer.

Features:
- Ethernet and Wi-Fi interface selection
- Start and stop packet capture
- Save captured packet information to SQLite
- Display packet date and time
- Export packet logs to CSV, JSON, and PDF
- Cleanly stop capture when closing the application
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

import capture
import database
import export

from gui import PacketApp


class TrafficAnalyzer:

    def __init__(self):

        self.sniffer = None
        self.packet_number = 0
        self.capture_running = False

        # Create GUI and connect callbacks
        self.app = PacketApp(
            on_start=self.start_capture,
            on_stop=self.stop_capture,
            on_refresh=self.refresh_interfaces,
            on_export=self.export_logs
        )

        # Initialize database after creating the Tkinter root
        try:
            database.init_db()

        except Exception as error:
            messagebox.showerror(
                "Database Error",
                f"Could not initialize the database:\n\n{error}",
                parent=self.app
            )

            self.app.destroy()
            raise

        # Load available network interfaces
        self.refresh_interfaces()

        # Handle application closing
        self.app.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

    # --------------------------------------------------
    # TIMESTAMP HANDLING
    # --------------------------------------------------

    def normalize_timestamp(self, timestamp=None, date=None, time=None):
        """
        Return a complete timestamp, date, and time.

        The database and GUI both receive the full date/time.
        """

        now = datetime.now()

        # Use separate date and time if supplied
        if not timestamp and date and time:
            timestamp = f"{date} {time}"

        elif not timestamp and time:
            timestamp = str(time)

        if isinstance(timestamp, datetime):
            dt = timestamp

        elif timestamp:

            timestamp = str(timestamp).strip()

            try:
                # Handle standard ISO timestamps
                dt = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

            except ValueError:

                # Handle time-only timestamps
                dt = None

                for time_format in (
                    "%H:%M:%S",
                    "%H:%M:%S.%f"
                ):
                    try:
                        parsed_time = datetime.strptime(
                            timestamp,
                            time_format
                        )

                        dt = now.replace(
                            hour=parsed_time.hour,
                            minute=parsed_time.minute,
                            second=parsed_time.second,
                            microsecond=parsed_time.microsecond
                        )

                        break

                    except ValueError:
                        continue

                # Use current time if timestamp is invalid
                if dt is None:
                    dt = now

        else:
            dt = now

        full_timestamp = dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        packet_date = dt.strftime("%Y-%m-%d")
        packet_time = dt.strftime("%H:%M:%S")

        return full_timestamp, packet_date, packet_time

    # --------------------------------------------------
    # REFRESH NETWORK INTERFACES
    # --------------------------------------------------

    def refresh_interfaces(self):
        """Load available Ethernet and Wi-Fi interfaces."""

        try:
            interfaces = capture.get_interface_details()

            self.app.set_interfaces(interfaces)

            if interfaces:

                recommended = next(
                    (
                        item for item in interfaces
                        if isinstance(item, dict)
                        and item.get("is_default_route")
                    ),
                    None
                )

                if recommended:
                    self.app.set_status(
                        "Recommended interface: "
                        f"{recommended.get('name', 'Unknown')} "
                        f"({recommended.get('ip') or 'No IPv4 address'})"
                    )

            else:
                self.app.set_status(
                    "No Ethernet or Wi-Fi interfaces found"
                )

        except Exception as error:

            self.app.set_interfaces([])

            self.app.set_status(
                f"Interface error: {error}"
            )

            print("Interface discovery error:", error)

    # --------------------------------------------------
    # START PACKET CAPTURE
    # --------------------------------------------------

    def start_capture(self, interface):
        """Start capturing packets on the selected interface."""

        if self.sniffer is not None:
            self.app.set_status(
                "A capture is already running"
            )
            return

        if not interface:
            self.app.set_status(
                "Please select a network interface"
            )
            return

        try:
            self.packet_number = 0

            self.sniffer = capture.start_capture(
                interface,
                self.handle_packet
            )

            self.capture_running = True

            self.app.set_capture_state(True)

            self.app.set_status(
                f"Capturing on {interface}"
            )

        except Exception as error:

            self.sniffer = None
            self.capture_running = False

            self.app.set_capture_state(False)

            self.app.set_status(
                f"Capture error: {error}"
            )

            messagebox.showerror(
                "Capture Error",
                str(error),
                parent=self.app
            )

            print("Capture start error:", error)

    # --------------------------------------------------
    # HANDLE CAPTURED PACKETS
    # --------------------------------------------------

    def handle_packet(self, packet_data):
        """
        Process packet information received from capture.py.

        Database saving happens in the capture callback.
        GUI updates are scheduled on the Tkinter main thread.
        """

        if not isinstance(packet_data, dict):
            return

        self.packet_number += 1

        # Get complete timestamp
        timestamp, packet_date, packet_time = (
            self.normalize_timestamp(
                timestamp=packet_data.get("timestamp"),
                date=packet_data.get("date"),
                time=packet_data.get("time")
            )
        )

        # Extract packet information
        source = (
            packet_data.get("source")
            or packet_data.get("source_ip")
            or "Unknown"
        )

        destination = (
            packet_data.get("destination")
            or packet_data.get("destination_ip")
            or "Unknown"
        )

        protocol = packet_data.get(
            "protocol",
            "Other"
        )

        length = packet_data.get(
            "length",
            0
        )

        info = packet_data.get(
            "info",
            ""
        )

        # Prepare database record
        # Store the complete date and time.
        database_record = {
            "timestamp": timestamp,
            "source_ip": source,
            "destination_ip": destination,
            "protocol": protocol,
            "length": length,
            "info": info
        }

        # Save packet to SQLite
        try:
            database.save_packet(database_record)

        except Exception as error:
            print(
                "Database save error:",
                error
            )

        # Prepare GUI record
        # Both date and time are sent separately.
        display_record = {
            "no": self.packet_number,
            "date": packet_date,
            "time": packet_time,
            "timestamp": timestamp,
            "src": source,
            "dst": destination,
            "protocol": protocol,
            "length": length,
            "info": info
        }

        # Update Tkinter safely from the main thread
        try:
            self.app.after(
                0,
                self.app.add_packet,
                display_record
            )

        except tk.TclError:
            # Ignore GUI updates if the window has closed
            pass

    # --------------------------------------------------
    # STOP PACKET CAPTURE
    # --------------------------------------------------

    def stop_capture(self):
        """Stop the active packet capture."""

        if self.sniffer is None:

            self.capture_running = False
            self.app.set_capture_state(False)

            return

        try:
            capture.stop_capture(self.sniffer)

        except Exception as error:
            print(
                "Capture stop error:",
                error
            )

        finally:
            self.sniffer = None
            self.capture_running = False

            self.app.set_capture_state(False)

            self.app.set_status(
                "Packet capture stopped"
            )

    # --------------------------------------------------
    # EXPORT PACKET LOGS
    # --------------------------------------------------

    def export_logs(self):
        """Export saved packet records to CSV, JSON, or PDF."""

        try:
            packets = database.get_all_packets()

            if not packets:
                messagebox.showwarning(
                    "No Packet Logs",
                    "There are no packet records to export.",
                    parent=self.app
                )

                self.app.set_status(
                    "No packet logs available"
                )

                return

            # Ask user where to save the exported file
            file_path = filedialog.asksaveasfilename(
                parent=self.app,
                title="Export Packet Logs",
                defaultextension=".csv",
                filetypes=[
                    ("CSV Files", "*.csv"),
                    ("JSON Files", "*.json"),
                    ("PDF Files", "*.pdf")
                ]
            )

            # User cancelled the save dialog
            if not file_path:
                return

            # Get selected file extension
            extension = os.path.splitext(
                file_path
            )[1].lower().replace(".", "")

            if extension not in ("csv", "json", "pdf"):
                messagebox.showerror(
                    "Invalid File Format",
                    "Please select CSV, JSON, or PDF.",
                    parent=self.app
                )
                return

            self.app.set_status(
                f"Exporting packet logs to {extension.upper()}..."
            )

            # Call export.py
            export.export_packets(
                file_path,
                extension
            )

            messagebox.showinfo(
                "Export Successful",
                f"Packet logs successfully exported!\n\n"
                f"File: {file_path}\n"
                f"Total packets: {len(packets)}",
                parent=self.app
            )

            self.app.set_status(
                f"Export successful: {os.path.basename(file_path)}"
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                f"Could not export packet logs:\n\n{error}",
                parent=self.app
            )

            self.app.set_status(
                "Packet export failed"
            )

            print("Export error:", error)

    # --------------------------------------------------
    # CLOSE APPLICATION
    # --------------------------------------------------

    def close(self):
        """Stop packet capture before closing the application."""

        try:
            self.stop_capture()

        finally:
            self.app.destroy()

    # --------------------------------------------------
    # RUN APPLICATION
    # --------------------------------------------------

    def run(self):
        """Start the Tkinter application."""

        self.app.mainloop()


# ------------------------------------------------------
# APPLICATION ENTRY POINT
# ------------------------------------------------------

if __name__ == "__main__":

    analyzer = TrafficAnalyzer()
    analyzer.run()
