# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from bitstring import *
from crccheck.checksum import Checksum16


class PacketWriter:

    def __init__(self, src_port, dest_port, window_size):

        self.src_port = src_port
        self.dest_port = dest_port
        self.window_size = window_size

    """ This method populates a Segment object's BitArray """
    def write_packet(self, s):

        # SOURCE PORT ADDRESS
        s.packet.append(Bits(uint=self.src_port, length=16))
        # DESTINATION PORT ADDRESS
        s.packet.append(Bits(uint=self.dest_port, length=16))
        # SEQUENCE NUMBER (DEFAULT ZERO)
        s.packet.append(Bits(uint=0, length=32))
        # ACKNOWLEDGMENT NUMBER (DEFAULT ZERO)
        s.packet.append(Bits(uint=0, length=32))
        # HEADER LENGTH
        s.packet.append(Bits(uint=5, length=4))
        # RESERVED BITS
        s.packet.append(Bits(uint=0, length=6))
        # FLAGS (DEFAULT TO ZERO)
        s.packet.append(Bits(uint=0, length=6))
        # WINDOW SIZE
        s.packet.append(Bits(uint=self.window_size, length=16))
        # CHECKSUM
        s.packet.append(Bits(uint=Checksum16.calc(s.data), length=16))
        # URGENT POINTER (NOT USED)
        s.packet.append(Bits(uint=0, length=16))
        # DATA (1452 BYTES)
        s.packet.append(s.data)

        # ADD ZERO PADDING AS NEEDED
        if len(s.packet) < 11776:
            s.packet.append(Bits(uint=0, length=(11776 - len(s.packet))))

    """ METHODS FOR SETTING ACK AND FIN FLAGS """

    @staticmethod
    def set_ack_bit(s):
        s.packet.set(True, 107)

    @staticmethod
    def set_fin(s):
        s.packet.set(True, 111)

    """ METHODS FOR SETTING SEQ AND ACK NUMBERS"""

    @staticmethod
    def set_ack_num(s, ack_num):
        ack_num = Bits(uint=ack_num, length=32)
        s.packet.overwrite(ack_num, 64)

    @staticmethod
    def set_seq(s, seq):
        seq = Bits(uint=seq, length=32)
        s.packet.overwrite(seq, 32)
