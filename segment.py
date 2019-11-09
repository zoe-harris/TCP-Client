# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from bitstring import *
from time import *
from crccheck.checksum import Checksum16


class Segment:

    def __init__(self, src_port, dest_port, window_size, seq, data=BitArray()):

        # INITIALIZE MEMBER VARIABLES
        self.src_port = src_port
        self.dest_port = dest_port
        self.window_size = window_size
        self.seq = seq
        self.data = data

        # START PACKET TIMER
        self.timer = time()

        # DECLARE PACKET AS BIT ARRAY
        self.pkt = BitArray()
        # SOURCE PORT ADDRESS
        self.pkt.append(Bits(uint=self.src_port, length=16))
        # DESTINATION PORT ADDRESS
        self.pkt.append(Bits(uint=self.dest_port, length=16))
        # SEQUENCE NUMBER
        self.pkt.append(Bits(uint=self.seq, length=32))
        # ACKNOWLEDGMENT NUMBER (DEFAULT ZERO)
        self.pkt.append(Bits(uint=0, length=32))
        # HEADER LENGTH
        self.pkt.append(Bits(uint=5, length=4))
        # RESERVED BITS
        self.pkt.append(Bits(uint=0, length=6))
        # FLAGS (DEFAULT TO ZERO)
        self.pkt.append(Bits(uint=0, length=6))
        # WINDOW SIZE
        self.pkt.append(Bits(uint=self.window_size, length=16))
        # CHECKSUM (ZERO ACTS AS PLACHOLDER)
        self.pkt.append(Bits(uint=0, length=16))
        # URGENT POINTER (NOT USED)
        self.pkt.append(Bits(uint=0, length=16))
        # DATA (1452 BYTES)
        self.pkt.append(self.data)

        # ADD ZERO PADDING AS NEEDED
        if len(self.pkt) < 11776:
            self.pkt.append(Bits(uint=0, length=(11776 - len(self.pkt))))

        # OVERWRITE [128:144] WITH CHECKSUM
        checksum = Checksum16.calc(self.pkt)
        self.pkt.overwrite(Bits(uint=checksum, length=16), 128)

    """ METHODS FOR SETTING ACK AND FIN FLAGS """

    def set_ack_bit(self):
        self.pkt.set(True, 107)

    def set_syn_bit(self):
        self.pkt.set(True, 110)

    def set_fin_bit(self):
        self.pkt.set(True, 111)

    """ METHODS FOR SETTING SEQ AND ACK NUMBERS"""

    def set_ack_num(self, ack_num):
        ack_num = Bits(uint=ack_num, length=32)
        self.pkt.overwrite(ack_num, 64)

    def set_seq(self, seq):
        seq = Bits(uint=seq, length=32)
        self.pkt.overwrite(seq, 32)

    """ TIMEOUT METHODS """

    def start_timer(self):
        self.timer = time()

    def timed_out(self):
        if (time() - self.timer) > 1:
            return True


