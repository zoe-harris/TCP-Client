# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from bitstring import *
from crccheck.checksum import Checksum16


class Segment:

    def __init__(self, src_port, dest_port, window_size):

        self.src_port = src_port
        self.dest_port = dest_port
        self.window_size = window_size

    def make_segment(self, data):

        segment = BitArray()

        # SOURCE PORT ADDRESS
        segment.append(Bits(uint=self.src_port, length=16))
        # DESTINATION PORT ADDRESS
        segment.append(Bits(uint=self.dest_port, length=16))
        # SEQUENCE NUMBER (DEFAULT ZERO)
        segment.append(Bits(uint=0, length=32))
        # ACKNOWLEDGMENT NUMBER (DEFAULT ZERO)
        segment.append(Bits(uint=0, length=32))
        # HEADER LENGTH
        segment.append(Bits(uint=5, length=4))
        # RESERVED BITS
        segment.append(Bits(uint=0, length=6))
        # FLAGS (DEFAULT TO ZERO)
        segment.append(Bits(uint=0, length=6))
        # WINDOW SIZE
        segment.append(Bits(uint=self.window_size, length=16))
        # CHECKSUM
        segment.append(Bits(uint=Checksum16.calc(data), length=16))
        # URGENT POINTER (NOT USED)
        segment.append(Bits(uint=0, length=16))
        # DATA (1452 BYTES)
        segment.append(data)

        return segment

    @staticmethod
    def set_ack(segment):
        segment.set(True, 107)

    @staticmethod
    def set_seq(segment, seq):
        seq = Bits(uint=seq, length=32)
        segment.overwrite(seq, 32)
        return

    @staticmethod
    def set_fin(segment):
        segment.set(True, 111)
