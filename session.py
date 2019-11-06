# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from tcp_machine import TCPMachine
from segment import Segment
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

        """ 3-WAY HANDSHAKE  """

        # create client socket + send SYN segment to server
        client_socket = socket(AF_INET, SOCK_DGRAM)
        client_socket.bind(('', self.client_port))
        # FIXME: Make and send SYN packet

        # receive SYN ACK + send ACK, establishing connection
        received = client_socket.recvfrom(1024)
        # FIXME: if received is SYN-ACK, send ACK

        """ TRANSMIT DATA """
        my_file = open(self.file_name, 'rb')


        """ CLOSE CONNECTION """
        # Close file + client socket, terminate program
        my_file.close()
        client_socket.close()
        sys.exit()
