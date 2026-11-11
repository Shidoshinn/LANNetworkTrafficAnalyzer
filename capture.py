
"""Network interface discovery and packet capture for Windows."""

from scapy.all import AsyncSniffer, get_if_list
from scapy.arch.windows import get_windows_if_list

from packet_parser import parse_packet


# Only allow these two physical network adapters.
ALLOWED_ADAPTERS = {
    "ethernet": "Ethernet",
    "wi-fi": "Wi-Fi",
    "wifi": "Wi-Fi",
}

# Match the actual hardware descriptions on your computer.
ALLOWED_DESCRIPTIONS = {
    "realtek pcie gbe family controller": "Ethernet",
    "rz616 wi-fi 6e 160mhz": "Wi-Fi",
}


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


def get_interface_details():
    """
    Return ONLY the main Ethernet and Wi-Fi adapters.

    Each result includes:
    - name: Display name
    - capture_name: Actual Scapy/Npcap device
    - description: Hardware description
    - ip: IPv4 address
    - mac: MAC address
    - is_default_route: Default route indicator
    - is_loopback: Always False
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

        # Identify the two permitted physical adapters.
        display_name = ALLOWED_ADAPTERS.get(name_key)

        if not display_name:
            display_name = ALLOWED_DESCRIPTIONS.get(description_key)

        # Ignore every other network adapter.
        if not display_name:
            continue

        # Avoid duplicate entries.
        if display_name in found_names:
            continue

        guid = adapter.get("guid", "")

        # Find its actual Npcap device name.
        capture_device = find_scapy_device(
            guid,
            scapy_devices
        )

        if not capture_device:
            print(f"Npcap device not found for {display_name}")
            continue

        # Retrieve IPv4 address.
        ip_address = ""

        for ip in adapter.get("ips", []):
            if "." in str(ip) and not str(ip).startswith("169.254."):
                ip_address = str(ip)
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
    """Return only the permitted Scapy/Npcap interface names."""

    return [
        item["capture_name"]
        for item in get_interface_details()
    ]


def start_capture(interface, packet_callback):
    """
    Start packet capture on the selected Ethernet or Wi-Fi adapter.
    """

    allowed_interfaces = get_interfaces()

    if interface not in allowed_interfaces:
        raise ValueError(
            "Invalid interface. Only Ethernet and Wi-Fi are allowed."
        )

    def process_packet(packet):
        try:
            packet_data = parse_packet(packet)

            if packet_data:
                packet_callback(packet_data)

        except Exception as error:
            print("Packet processing error:", error)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=process_packet,
        store=False
    )

    sniffer.start()

    print("Packet capture started:", interface)

    return sniffer


def stop_capture(sniffer):
    """Stop the active packet capture session."""

    if sniffer is not None and sniffer.running:
        sniffer.stop()
        print("Packet capture stopped.")
