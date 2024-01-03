import re
import binascii
from string import printable
import os
import argparse
import subprocess
import sys

def check_tshark_installed():
    try:
        # Check if tshark is available in the system
        subprocess.run(['tshark', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print("tshark is already installed.")
    except subprocess.CalledProcessError as e:
        print("tshark is not installed.")
        choice = input("Do you want to install tshark? (Y/N): ").lower()

        if choice == 'y':
            try:
                # Attempt to install tshark using the appropriate package manager based on the OS
                if sys.platform.startswith('linux'):
                    subprocess.run(['sudo', 'apt-get', 'install', '-y', 'tshark'])
                elif sys.platform.startswith('darwin'):
                    subprocess.run(['brew', 'install', 'wireshark'])
                elif sys.platform.startswith('win'):
                    print("Please download Wireshark from https://www.wireshark.org/download.html and install it manually.")
                else:
                    print("Unsupported platform. Please install Wireshark manually.")
            except subprocess.CalledProcessError as install_error:
                print(f"Installation failed: {install_error}")
        else:
            print("Installation aborted.")


def extract_tcp_streams_from_pcap(pcap_file, bad_domain):
    raw_data = os.popen('tshark -r '+ pcap_file + ' -Tfields -e dns.qry.name').read()

    extracted_data = ''
    for packet in raw_data.splitlines():  # Splitting raw_data into lines
        result = re.findall('([a-z0-9\.]+)\.' + bad_domain, packet)

        if result:
            bytes_data = binascii.unhexlify(result[0].replace('.' + bad_domain, '').replace('.', ''))
            packet_data = bytes_data[9:]

            try:
                packet_data = packet_data.decode(encoding='utf-8')
            except UnicodeDecodeError:
                continue  # Skip decoding errors

            decoded = ''.join(char for char in packet_data if char in printable)
            decoded = decoded.replace('\r\n', '\n')

            if len(decoded) > 5 and decoded not in extracted_data:
                extracted_data += decoded
                print(decoded)

    return extracted_data


def main():
    parser = argparse.ArgumentParser(description='Extract TCP streams from a pcap file.')
    parser.add_argument('file', help='Path to the input pcap file')
    parser.add_argument('domain', help='Domain used by dnscat')
    args = parser.parse_args()
    pcap_file = args.file
    bad_domain = args.domain

    check_tshark_installed()

    extracted_data = extract_tcp_streams_from_pcap(pcap_file, bad_domain)


if __name__ == "__main__":
    main()
