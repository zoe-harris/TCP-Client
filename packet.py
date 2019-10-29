# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2


class Packet:

    def __init__(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port

    def tcp_segment(self):

        # BITS      CONTENTS
        # 0:16      src_port
        # 16:32     dest_port
        # 32:64     seq_num
        # 64:96     ack_num
        # 95:100    data_offset (header length) (>= 5)
        # 100:106   zeros (reserved bits)
        # 106       zero (URG=0, not used)
        # 107       ack_bit (could be zero or one)
        # 108       zero (PSH=0, not used)
        # 109       zero (RST=0, not used)
        # 110       syn_bit (could be zero or one)
        # 111       fin_bit (could be zero or one)
        # 112:128   recv_window
        # 144:160   zero (Urgent pointer is not used)
        # 160       if offset = 5, this is a DATA segment
        # TOTAL PACKET SIZE SHOULD EQUAL 1472 BYTES

        return "TCP Segment"
