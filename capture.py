
"""
Network interface discovery and packet capture for Windows.

Features:
- Ethernet and Wi-Fi interface discovery
- Npcap device matching
- IPv4 and MAC address information
- Packet capture using Scapy
- Full packet timestamp (date and time)
- Packet processing through packet_parser.py
"""

from datetime import datetime

from scapy.all import AsyncSniffer, get_if_list
from scapy.arch.windows import get_windows_if_list

from packet_parser import parse_packet


# ------------------------------------------------------
# ALLOWED NETWORK ADAPTERS
# ------------------------------------------------------

ALLOWED_ADAPTERS = {
    "ethernet": "Ethernet",
    "wi-fi": "Wi-Fi",
    "wifi": "Wi-Fi",
}

ALLOWED_DESCRIPTIONS = {
    "realtek pcie gbe family controller": "Ethernet",
    "rz616 wi-fi 6e 160mhz": "Wi-Fi",
}


# ------------------------------------------------------
# INTERFACE HELPERS
# ------------------------------------------------------

def normalize_guid(value):
    """Normalize adapter GUIDs for comparison."""

    return str(value).strip().strip("{}").lower()


def find_scapy_device(guid, scapy_devices):
    """Find the Scapy Npcap device matching a Windows adapter GUID."""

    target_guid = normalize_guid(guid)

    for device in scapy_devices:
        if target_guid and target_guid in normalize_guid(device):
            return device

    return None


# ------------------------------------------------------
# GET NETWORK INTERFACE DETAILS
# ------------------------------------------------------

def get_interface_details():
    """
    Return only the main Ethernet and Wi-Fi adapters.

    Each result includes:
    - name
    - capture_name
    - description
    - ip
    - mac
    - is_default_route
    - is_loopback
    """

    adapters = get_windows_if_list()
    scapy_devices = get_if_list()

    interfaces = []
    found_names = set()

    for adapter in adapters:

        adapter_name = adapter.get("name", "").strip()
        description = adapter.get("description", "").strip()

        name_key = adapter_name.lower()
        description_key = description.lower()

        # Identify permitted physical adapters.
        display_name = ALLOWED_ADAPTERS.get(name_key)

        if not display_name:
            display_name = ALLOWED_DESCRIPTIONS.get(
                description_key
            )

        # Ignore other network adapters.
        if not display_name:
            continue

        # Avoid duplicate entries.
        if display_name in found_names:
            continue

        guid = adapter.get("guid", "")

        # Find actual Npcap device name.
        capture_device = find_scapy_device(
            guid,
            scapy_devices
        )

        if not capture_device:
            print(
                f"Npcap device not found for {display_name}"
            )
            continue

        # Retrieve IPv4 address.
        ip_address = ""

        for ip in adapter.get("ips", []):
            ip = str(ip)

            if (
                "." in ip
                and not ip.startswith("169.254.")
            ):
                ip_address = ip
                break

        mac_address = adapter.get("mac", "")

        interfaces.append({
            "name": display_name,
            "capture_name": capture_device,
            "description": description,
            "ip": ip_address,
            "mac": mac_address,
            "is_default_route": False,
            "is_loopback": False
        })

        found_names.add(display_name)

    return interfaces


def get_interfaces():
    """Return only permitted Scapy/Npcap interface names."""

    return [
        item["capture_name"]
        for item in get_interface_details()
    ]


# ------------------------------------------------------
# PACKET TIMESTAMP
# ------------------------------------------------------

def get_packet_timestamp(packet):
    """
    Get the original packet capture timestamp.

    Returns:
    - timestamp: YYYY-MM-DD HH:MM:SS
    - date: YYYY-MM-DD
    - time: HH:MM:SS
    """

    try:
        # Scapy records the packet capture time.
        packet_time = float(packet.time)

        dt = datetime.fromtimestamp(packet_time)

    except (AttributeError, TypeError, ValueError, OverflowError):
        # Fallback if packet timestamp is unavailable.
        dt = datetime.now()

    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    packet_date = dt.strftime("%Y-%m-%d")
    packet_time = dt.strftime("%H:%M:%S")

    return timestamp, packet_date, packet_time


# ------------------------------------------------------
# START PACKET CAPTURE
# ------------------------------------------------------

def start_capture(interface, packet_callback):
    """
    Start packet capture on the selected Ethernet or Wi-Fi adapter.

    Packet metadata is passed to the callback.
    """

    allowed_interfaces = get_interfaces()

    if interface not in allowed_interfaces:
        raise ValueError(
            "Invalid interface. Only Ethernet and Wi-Fi are allowed."
        )

    def process_packet(packet):

        try:
            # Parse packet information.
            packet_data = parse_packet(packet)

            if not packet_data:
                return

            if not isinstance(packet_data, dict):
                return

            # Get original capture timestamp.
            timestamp, packet_date, packet_time = (
                get_packet_timestamp(packet)
            )

            # Create a separate dictionary.
            packet_data = dict(packet_data)

            # Include complete date and time.
            packet_data["timestamp"] = timestamp
            packet_data["date"] = packet_date
            packet_data["time"] = packet_time

            # Send packet information to main.py.
            packet_callback(packet_data)

        except Exception as error:
            print(
                "Packet processing error:",
                error
            )

    # Create asynchronous packet sniffer.
    sniffer = AsyncSniffer(
        iface=interface,
        prn=process_packet,
        store=False
    )

    sniffer.start()

    print(
        "Packet capture started:",
        interface
    )

    return sniffer


# ------------------------------------------------------
# STOP PACKET CAPTURE
# ------------------------------------------------------

def stop_capture(sniffer):
    """Stop the active packet capture session."""

    if sniffer is not None and sniffer.running:

        sniffer.stop()

        print("Packet capture stopped.")
