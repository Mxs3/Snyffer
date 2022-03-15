import os
import sys
import socket
from struct import *
import logging as log


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = "\033[97m"


def sniff_traffic(encoding: str, mode: str):

    log_dir = "./packet-logs"
    log_file_name = "captured.log"

    global raw_data
    global data

    try:
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    except socket.error as err_code:
        print(Colors.RED + "COULD NOT CREATE SOCKET => " + Colors.WHITE + "ERROR_CODE: " +
              str(err_code[0]) + "MESSAGE: " + str(err_code[1]))
        sys.exit()

    if mode == "log":
        os.mkdir(f"{log_dir}")

        log.basicConfig(filename=(log_dir + "/" + log_file_name),
                        level=log.DEBUG, format="%(asctime)s: %(message)s")

    while True:
        packet = sock.recvfrom(65565)
        packet = packet[0]

        ip_header = packet[:20]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]

        protocol = iph[6]

        src_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        print(Colors.WHITE + 'VERSION: ' + str(version) + "\n" + 'IP_HEADER_LEN: ' + str(ihl) + "\n" + 'TTL: ' + str(ttl) + "\n" + 'PROTOCOL: ' +
              str(protocol) + "\n" + 'SRC_ADDR: ' + str(src_addr) + "\n" + 'DEST_ADDR: ' + str(dest_addr) + "\n")

        tcp_header = packet[iph_length:iph_length+20]
        tcph = unpack('!HHLLBBHHH', tcp_header)

        src_port = tcph[0]
        dest_port = tcph[1]

        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]

        tcph_length = doff_reserved >> 4

        print(Colors.WHITE + 'SRC_PORT: ' + str(src_port) + "\n" + 'DEST_PORT: ' + str(dest_port) + "\n" + 'SEQ_NUMBER: ' +
              str(sequence) + "\n" + 'ACK: ' + str(acknowledgement) + "\n" + 'TCP_HEADER_LEN: ' + str(tcph_length) + "\n")

        header_size = iph_length + tcph_length * 4
        data_size = len(packet) - header_size

        raw_data = packet[header_size:]

        data = raw_data.decode(encoding=encoding, errors="backslashreplace")

        print(Colors.YELLOW + "RAW_DATA: " + str(raw_data) + "\n")
        print(Colors.GREEN + "DECODED_DATA: " + str(data) + "\n")

        print(mode)

        log.info(f"RAW_DATA: {str(raw_data)}")


if __name__ == '__main__':
    if sys.argv[1] == "-l" or sys.argv[1] == "--log":
        sniff_traffic("utf-8", "log")

    elif sys.argv[1] == "-n" or sys.argv[1] == "--no-log":
        sniff_traffic("utf-8", "no_log")
