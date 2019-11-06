# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from tcp_machine import TCPMachine
from segment import Segment
from packet_reader import PacketReader
from socket import *
import sys
import time


class Session:

    def __init__(self, ip_address, file_name, server_port, client_port):
        self.state = TCPMachine()
        self.ip_address = ip_address
        self.file_name = file_name
        self.server_port = server_port
        self.client_port = client_port
        self.server = (self.ip_address, self.server_port)

    def run_session(self):

        """

            # declare TCP machine
            tcp_machine = TCPMachine()

            # Create client socket + bind to client port
            client_socket = socket(AF_INET, SOCK_DGRAM)
            client_socket.bind(('', self.client_port))

            # Establish connection
            Send SYN (syn_bit = 1, seq = x)
            tcp_machine.snd_syn()
            Receive SYN-ACK (syn_bit = 1, seq = y, ack_bit = 1, ack_num = x + 1)
            Send ACK (ack_bit = 1, ack_num = y + 1)
            tcp_machine.recv_syn_ack()

            # Transmit data using selective repeat
            my_file = open(self.file_name, 'rb')



            ...CLOSING PROCEDURES...

        """