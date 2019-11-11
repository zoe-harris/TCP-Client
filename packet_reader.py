# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2
from bitstring import *

class PacketReader:

    @staticmethod
    def get_ack_num(segment):
        return segment[64:96].uint

    @staticmethod
    def get_ack_bit(segment):
        return segment[107]

    @staticmethod
    def get_syn_bit(segment):
        return segment[110]

    @staticmethod
    def get_fin_bit(segment):
        return segment[111]

    @staticmethod
    def get_seq_num(segment):
        return segment[32:64]

    @staticmethod
    def print_pkt(segment):

        pkt = segment.pkt

        # PRINT BINARY CONTENTS
        print("TOTAL PACKET LENGTH: {}".format(len(pkt)))
        print()
        print("{} {}".format(pkt[0:16].bin, pkt[16:32].bin))  # SRC PORT & DEST PORT
        print("{}".format(pkt[32:64].bin))  # SEQ NUMBER
        print("{}".format(pkt[64:96].bin))  # ACK NUMBER
        print("{} {} {} {} {} {} {} {} {}".format(pkt[96:100].bin, pkt[100:106].bin, pkt[106], pkt[107],
                                                           pkt[108], pkt[109], pkt[110], pkt[111],
                                                           pkt[112:128].bin))
        print("{} {}".format(pkt[128:144].bin, pkt[144:160].bin))

        # NEW LINE
        print()

        # PRINT UNSIGNED INT CONTENTS
        print("SRC PORT: {}  DEST PORT: {}".format(pkt[0:16].uint, pkt[16:32].uint))
        print("SEQ: {}".format(pkt[32:64].uint))
        print("ACK NUM: {}".format(pkt[64:96].uint))
        print("DATA OFFSET: {}    RESERVED: {}    ".format(pkt[96:100].uint, pkt[100:106].uint))
        print("URG: {}  ACK: {}  PSH: {}  RST: {}  SYN: {}  FIN: {}".format(pkt[106], pkt[107],
                                                                            pkt[108], pkt[109], pkt[110],
                                                                            pkt[111],))
        print("WINDOW SIZE: {}".format(pkt[112:128].uint))
        print("CHECKSUM: {}    URGENT PTR: {}".format(pkt[128:144].uint, pkt[144:160].uint))

        # NEW LINE
        print()