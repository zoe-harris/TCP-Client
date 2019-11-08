# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from segment import Segment
from packet_reader import PacketReader
from socket import *


class Session:

    def __init__(self, ip_address, file_name, server_port, client_port):

        self.ip_address = ip_address
        self.file_name = file_name
        self.s_port = server_port
        self.c_port = client_port
        self.server = (self.ip_address, self.s_port)
        self.win_size = 14520

    def run_session(self):

        # set up client socket + server
        client_socket = socket(AF_INET, SOCK_DGRAM)
        client_socket.bind(('', self.c_port))

        # use 3-way handshake to establish connection
        self.handshake(client_socket)

        """
        # set up initial sequence number and send base
        initial_seq_num = 0
        next_seq_num = initial_seq_num
        send_base = initial_seq_num
        unacked_packets = []

        while True:

            # SEND PACKET:
                if next_seq_num < (send_base + self.win_size):
                    segment = Segment(self.c_port, self.s_port, self.win_size, next_seq_num)
                    unacked_packets.append(segment)
                    next_seq_num = next_seq_num + 1452
                    client_socket.sendto(bytearray(segment.pkt), self.server)


            # TIMEOUT + RETRANSMISSION
            for pkt in unacked_packets:
                if pkt.timed_out():
                    send packet
                    reset packet's timer

            # RECEIVE ACK
            # advance send base
            if (ACK number > send_base):
                send_base = ACK number
            for pkt in unacked_packets:
                if pkt.seq == ACK number:
                    remove pkt from unacked_packets

        """

    def handshake(self, client_socket):

        # make + send SYN packet
        syn = Segment(self.c_port, self.s_port, self.win_size, 0)
        syn.set_syn_bit()
        client_socket.sendto(bytearray(syn.pkt), self.server)

        # receive SYN-ACK packet, write SEQ number to y
        recv_pkt = (client_socket.recvfrom(1472))[0]
        y = PacketReader.get_seq_num(recv_pkt)

        # make ACK packet with ACK number = y + 1
        ack = Segment(self.c_port, self.s_port, self.win_size, 0)
        ack.set_ack_bit()
        ack.set_ack_num(y + 1)
        client_socket.sendto(bytearray(syn.pkt), self.server)
