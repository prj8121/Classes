# pktsniffer.py
# Parker Johnson

import sys


def pktsniffer(fileName):
    with open(fileName, mode='rb') as file:
        fileContent = file.read()
        print(fileContent)

def main():
    print("Hello world")
    if len(sys.argv) >= 3 and sys.argv[1] == "-r":
        pktsniffer(sys.argv[2])
    else:
        print("Usage: python pktsniffer -r packet_file");

main()
