# pktsniffer.py
# Parker Johnson

import sys


def pktsniffer(file_name):
    data = open(file_name, 'rb')
    print(data)

def main():
    print("Hello world")
    if len(sys.argv) >= 2:
        pktsniffer(sys.argv[1])
    else:
        print("Usage: python pktsniffer packet_file");

main()
