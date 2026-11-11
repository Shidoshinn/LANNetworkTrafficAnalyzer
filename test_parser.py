
from scapy.layers.inet import IP, TCP
from packet_parser import parse_packet

# Create a sample packet
sample_packet = (
    IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=1234, dport=80)
)

# Parse the packet
result = parse_packet(sample_packet)

# Display the result
print("PACKET INFORMATION")
print("-------------------")

for key, value in result.items():
    print(f"{key}: {value}")
