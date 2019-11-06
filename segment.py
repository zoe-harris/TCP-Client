# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from bitstring import *
from time import *


class Segment:

    def __init__(self, data):

        self.data = data
        self.packet = BitArray()
        self.timer = time()

    def timed_out(self):

        if (time() - self.timer) > 1:
            return True

    def reset_timer(self):

        self.timer = time()

