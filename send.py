# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2


class Send:

    def __init__(self, ip_address, file_name, server_port, client_port):
        self.ip_address = ip_address
        self.file_name = file_name
        self.server_port = server_port
        self.client_port = client_port

    # data from above: if next available seq_num in window, send pkt
    # timeout(n): resend packet n, restart timer
    # ack(n) in [send_base, send_base + N]: mark packet as received,
    # advance window base to next unACK'ed sequence number
