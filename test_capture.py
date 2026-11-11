
import time

from capture import start_capture, stop_capture
from scapy.all import conf


# Display available network interfaces
interfaces = list(conf.ifaces.values())

print("AVAILABLE NETWORK INTERFACES")

for index, interface in enumerate(interfaces):
    print(f"\n[{index}]")
    print("Name:", interface.name)
    print("Description:", interface.description)
    print("IP Address:", interface.ip)
    print("MAC Address:", interface.mac)

if not interfaces:
    print("No network interfaces found.")
    raise SystemExit


# Select an interface
choice = int(input("\nSelect interface number: "))

if choice < 0 or choice >= len(interfaces):
    print("Invalid interface selection.")
    raise SystemExit

selected_interface = interfaces[choice].name

# Display captured packets
def display_packet(packet_data):
    print("\nNEW PACKET CAPTURED")
    print("-------------------")

    for key, value in packet_data.items():
        print(f"{key}: {value}")


# Start capture
sniffer = start_capture(
    selected_interface,
    display_packet
)

print("\nCapturing packets for 30 seconds...")

try:
    time.sleep(30)
finally:
    stop_capture(sniffer)

print("Capture session ended.")
