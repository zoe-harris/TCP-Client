# Zoe Harris
# CSCE365 Computer Networks
# Programming Assignment #2

from statemachine import StateMachine, State


class TCPMachine(StateMachine):

    """ 3-WAY HANDSHAKE STATES """
    # CLOSED: represents no connection at all
    closed = State('CLOSED', initial=True)
    # SYN-SENT: waiting for matching connection request after sending request
    syn_sent = State('SYN-SENT')
    # ESTABLISHED: open connection, normal state for data transfer phase
    established = State('ESTABLISHED')

    """ CONNECTION CLOSURE STATES """
    # FIN-WAIT-1: waiting for remote TCP termination request, or ACK of local request
    fin_wait_1 = State('FIN-WAIT-1')
    # FIN-WAIT-2: waiting for remote TCP termination request
    fin_wait_2 = State('FIN-WAIT-2')
    # TIME-WAIT: waiting for enough time to pass to be sure remote TCP received last ACK
    time_wait = State('TIME-WAIT')

    """ 3-WAY HANDSHAKE TRANSITIONS """
    snd_syn = closed.to(syn_sent)  # Client socket is opened, send SYN to server
    recv_syn_ack = syn_sent.to(established)  # Receive SYN-ACK + send ACK, establishing connection

    """ CONNECTION CLOSURE TRANSITIONS """
    snd_fin = established.to(fin_wait_1)  # On last data transmission, FIN=1
    rcv_ack = fin_wait_1.to(fin_wait_2)  # Receive ACK, send nothing
    snd_ack = fin_wait_2.to(time_wait)  # Receive FIN, send ACK
    timeout = time_wait.to(closed)  # Wait 30 seconds, then delete connection
