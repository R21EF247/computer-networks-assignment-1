import pyshark
from scapy.all import PcapWriter
from scapy.all import Ether

def extract_http_frames(input_file, output_file):
    # Read packets from the input PCAPNG file using Pyshark
    # Enable use_json and include_raw to get raw packet data
    cap = pyshark.FileCapture(input_file, use_json=True, include_raw=True)

    # Initialize an empty list to hold Scapy packets
    http_frames = []

    # Iterate through each packet in the capture
    for packet in cap:
        # Check if the packet has an HTTP layer
        if 'HTTP' in packet:
            # Create a Scapy packet from the raw bytes
            scapy_pkt = Ether(packet.get_raw_packet())
            # Append the Scapy packet to the list
            http_frames.append(scapy_pkt)

    # Create a new Scapy "PcapWriter" object for writing packets to a new file
    with PcapWriter(output_file, append=True, sync=True) as pcap_writer:
        # Write Scapy packets to the new file
        pcap_writer.write(http_frames)

# Example usage
if __name__ == "__main__":
    input_file = "./raw_frames.pcapng"  # Replace with your input file path
    output_file = "./http_frames.pcapng"  # Replace with your output file path
    extract_http_frames(input_file, output_file)
    print(f"HTTP frames have been extracted to {output_file}")
