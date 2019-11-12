# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from bitstring import *


class PktReader:

    @staticmethod
    def get_ack_num(segment):
        segment = Bits(bytes=segment)
        return segment[64:96].uint

    @staticmethod
    def get_ack_bit(segment):
        segment = Bits(bytes=segment)
        return segment[107]

    @staticmethod
    def get_syn_bit(segment):
        segment = Bits(bytes=segment)
        return segment[110]

    @staticmethod
    def get_fin_bit(segment):
        segment = Bits(bytes=segment)
        return segment[111]

    @staticmethod
    def get_seq_num(segment):
        segment = Bits(bytes=segment)
        return segment[32:64].uint
