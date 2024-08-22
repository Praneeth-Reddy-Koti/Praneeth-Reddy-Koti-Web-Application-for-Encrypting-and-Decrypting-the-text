import pyshark

def detect_packet_sniffing(pcap_file):
    print("Detecting Packet Sniffing...")
    capture = pyshark.FileCapture(pcap_file)

    suspicious_packets = 0
    total_packets = 0

    for packet in capture:
        total_packets += 1
        try:
            if 'ip' in packet and packet.ip.dst == '255.255.255.255':
                print(f"Suspicious broadcast packet: {packet}")
                suspicious_packets += 1
        except AttributeError:
            pass

    capture.close()

    if suspicious_packets > 0:
        print(f"Potential packet sniffing detected! {suspicious_packets}/{total_packets} packets are suspicious.")
    else:
        print("No packet sniffing detected.")

if __name__ == "__main__":
    pcap_file = r'C:\Projects\Computer Security\wireshark files\sniff.pcapng'
    detect_packet_sniffing(pcap_file)