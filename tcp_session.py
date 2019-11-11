# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from segment import Segment
from packet_reader import PacketReader
from socket import *
from tcp_machine import TCPMachine
import sys
import time


class Session:

    def __init__(self, ip_address, file_name, server_port, client_port):

        # PORTS AND ADDRESSES
        self.ip_address = ip_address
        self.s_port = server_port
        self.c_port = client_port
        self.server = (self.ip_address, self.s_port)

        # FILE
        self.file_name = file_name

        # TCP MACHINE
        self.tcp_machine = TCPMachine()

        # SELECTIVE REPEAT VARIABLES
        self.win_size = 14520
        self.unacked_packets = []
        self.send_base = 0
        self.next_seq = 0
        self.last_seq_num = 0
        self.next_ack_num = 0

        # CLIENT SOCKET
        self.client_socket = socket(AF_INET, SOCK_DGRAM)
        self.client_socket.bind(('', self.c_port))

    """ run TCP session with client in send mode """
    def run_session(self):

        # 3-WAY HANDSHAKE
        if self.tcp_machine.closed:

            self.handshake()

        if self.tcp_machine.established:

            file = open(self.file_name, 'rb')

            # ESTABLISHED + TRANSMIT DATA
            while not self.tcp_machine.fin_wait_1:

                self.send_packet(file)
                self.retransmit()
                self.receive_ack()

            # FIN WAIT 1
            while self.tcp_machine.fin_wait_1:

                self.retransmit()
                self.receive_ack()

            # FIN WAIT 2
            if self.tcp_machine.fin_wait_2:

                fin_pkt = (self.client_socket.recvfrom(1472))[0]
                ack = Segment(self.c_port, self.s_port, self.win_size, self.next_seq)
                ack.set_ack_num(PacketReader.get_seq_num(fin_pkt) + 1)
                ack.set_ack_bit()
                ack.set_checksum()
                self.tcp_machine.snd_ack()

            # TIMED WAIT -> CLOSED
            if self.tcp_machine.time_wait:
                time.sleep(5)
                self.file_name.close()
                self.client_socket.close()
                sys.exit()

    """ Establish connection using three-way handshake protocol """
    def handshake(self):

        # make + send SYN packet
        syn = Segment(self.c_port, self.s_port, self.win_size, 61)
        syn.set_syn_bit()
        syn.set_checksum()
        self.client_socket.sendto(syn.pkt.bytes, self.server)

        # advance TCP machine from CLOSED to SYN-SENT
        self.tcp_machine.snd_syn()

        # receive SYN-ACK packet, write SEQ number to y
        recv_pkt = (self.client_socket.recvfrom(1472))[0]
        self.next_ack_num = PacketReader.get_seq_num(recv_pkt)
        y = PacketReader.get_seq_num(recv_pkt)

        # make ACK packet with ACK number = y + 1
        ack = Segment(self.c_port, self.s_port, self.win_size, 61)
        ack.set_ack_bit()
        ack.set_ack_num(y + 1)
        syn.set_checksum()
        self.client_socket.sendto(syn.pkt.bytes, self.server)

        # advance TCP machine from SYN-SENT to ESTABLISHED
        self.tcp_machine.recv_syn_ack()

    """ if next SEQ number within window, make + send new segment """
    def send_packet(self, file):
        # if next SEQ number is within send  window, make + send the next segment
        if self.next_seq < (self.send_base + self.win_size):

            # read data + make new TCP segment
            data = bytearray(file.read(1452))
            segment = Segment(self.c_port, self.s_port, self.win_size, self.next_seq, data)
            segment.set_ack_num(self.next_ack_num)
            segment.set_checksum()

            # check if this was the last packet to be made
            if len(data) < 1452:
                segment.set_fin_bit()
                self.last_seq_num = self.next_seq
                # advance TCP machine to FIN-WAIT-1
                self.tcp_machine.snd_fin()

            # add segment to list of unACKed packets
            self.unacked_packets.append(segment)

            # advance next SEQ number
            self.next_seq += 1452

            # send the new TCP segment + start timer for that segment
            self.client_socket.sendto(segment.pkt.bytes, self.server)
            segment.start_timer()

    """ retransmit any unACKed packets that have timed out """
    def retransmit(self):

        for pkt in self.unacked_packets:
            if pkt.timed_out():
                self.client_socket.sendto(pkt.pkt.bytes, self.server)
                pkt.start_timer()

    """ receive ACK from server + update list of unACKed packets """
    def receive_ack(self):

        # receive ACK from server + extract ACK number
        server_ack = (self.client_socket.recvfrom(1472))[0]
        server_ack_num = PacketReader.get_ack_num(server_ack)
        self.next_ack_num = PacketReader.get_seq_num(server_ack)

        # if ACK number > send base, advance send base
        if server_ack_num > self.send_base:
            self.send_base += server_ack_num

        # remove ACKed packet from list of unACKed packets
        for pkt in self.unacked_packets:
            if pkt.seq == server_ack_num:
                self.unacked_packets.remove(pkt)

        # check if ACK was for FIN packet
        if PacketReader.get_seq_num(server_ack) == self.last_seq_num:
            self.tcp_machine.rcv_ack()
