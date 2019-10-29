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
    # CLOSE-WAIT: waiting for termination request from local user
    close_wait = State('CLOSE-WAIT')
    # CLOSING: waiting for termination request from remote TCP
    closing = State('CLOSING')
    # LAST-ACK: waiting for ACK of previous termination request
    last_ack = State('LAST-ACK')
    # TIME-WAIT: waiting for enough time to pass to be sure remote TCP received last ACK
    time_wait = State('TIME-WAIT')

    """ 3-WAY HANDSHAKE TRANSITIONS """
    snd_syn = closed.to(syn_sent)  # Client socket is opened, sends SYN to server
    recv_syn_ack = syn_sent.to(established)  # Client receives SYN-ACK, establishing connection

    """ CONNECTION CLOSURE TRANSITIONS """
    snd_fin = established.to(fin_wait_1)  # On last data transmission, FIN=1
    rcv_fin_ack = fin_wait_1.to(fin_wait_2)  # Remote TCP send segment with FIN=1 and ACK=1
    snd_ack = fin_wait_1.to(closing)  # ACK remote TCP's FIN-ACK
    timeout = time_wait.to(closed)  # Wait 2 MSL, then delete connection
