import pyshark

def count_http_frames(pcapng_file_path):
    # Create a FileCapture object
    cap = pyshark.FileCapture(pcapng_file_path)

    # Initialize HTTP frame count
    http_count = 0

    # Iterate through each packet
    for packet in cap:
        # Check if the packet has the HTTP layer
        if 'HTTP' in packet:
            http_count += 1

    return http_count

if __name__ == "__main__":
    pcapng_file_path = "./http_frames.pcapng"  # Update this to your actual file path
    http_frames = count_http_frames(pcapng_file_path)
    print(f"Number of HTTP frames: {http_frames}")

