# Problems
# Send Last ACK but drop --> Start FIN. (On last packet recv, need to re-send last ACK and FIN.)
# Send Last ACK but drop --> Start Sending. (On last packet recv, need to re-send last ACK)
# Send Last ACK but drop --> Start Recv again. (On last packet recv, need to re-send last ACK)

import binascii
import socket as syssock
import struct
import sys
import select
import time
import random

# encryption libraries 
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

sendPort = 27182
recvPort = 27182

PACKET_SIZE_LIMIT_IN_BYTES = 64000

WORD_SIZE = 16 # BITS

TIME_OUT = 0.2 # SECONDS

# Flag bits
SOCK352_SYN     = 0b00001  # 0x01 == 1
SOCK352_FIN     = 0b00010  # 0x02 == 2
SOCK352_ACK     = 0b00100  # 0x04 == 4
SOCK352_RESET   = 0b01000  # 0x08 == 8
SOCK352_HAS_OPT = 0b10000  # 0x10 == 16

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

# If last packet received == next packet received
# ignore and resend last packet sent.
# Last Packet Received
# Last Packet Sent

def init(UDPportTx,UDPportRx): 
    global sendPort
    global recvPort
    # Save send and receive ports
    sendPort = int(UDPportTx)
    recvPort = int(UDPportRx)

def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex 
    global publicKeys
    global privateKeys 
    
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")             

    return (publicKeys,privateKeys)
    
class socket:
    
    def __init__(self):
        # Prepare System UDP Socket
        self.syssock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
        self.dropPercentage = 0
        self.encrypt = False
        self.connected = False
        self.nonce = nacl.utils.random(Box.NONCE_SIZE)
        self.lastAckSent = None
        self.lastPacketRecv = None
    
    def bind(self,address):
        # Bind - Server will bind on recvPort and wait for incoming connections.
        self.syssock.bind((address[0], recvPort))
        return 

    def connect(self, address, encrypt_flag=0):
        # Client will connect to address on sendPort and will receive from recvPort.
        self.syssock.bind(('', recvPort))
        self.syssock.connect((address[0], sendPort))
        # Perform 3-way handshake as client
        # Handshake part 1 - Send SYN to server.
        seq_no = random.randint(0, 4294967294)
        self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_SYN, seq_no, 0), True)
        # Handshake part 2 - Receive SYN/ACK from server.
        packet = self.recvSingleRdpPacket()
        if packet.flags & SOCK352_RESET > 0:
            print("RESET flag received from server.")
            return
        if packet.ack_no != seq_no + 1:
            print("Invalid sequence number received.")
            return
        # Handshake part 3 - Send ACK to server.
        self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, seq_no + 1, packet.sequence_no + 1), True)
        # print "3-way Handshake completed from client side."
        self.connected = True
        
        if (encrypt_flag == ENCRYPT):
            self.encrypt = True
            # print "Client's public Key for server"
            # print publicKeysHex[address[0], str(sendPort)]
            self.box = Box(privateKeys[('*', '*')], publicKeys[address[0], str(sendPort)])
        return 
    
    def listen(self,backlog):
        # Does nothing - will be more useful for multithreaded socket applications.
        return

    def accept(self, encrypt_flag=0):
        # Server accepts incoming connection, performs 3-way handhsake, and connects to sender's sendPort
        # Perform 3-way handshake as server
        # Handshake part 1 - Receive SYN
        packet = self.recvSingleRdpPacket()
        address = packet.sender_address
        seq_no = random.randint(0, 4294967294)
        # Prepare Reverse Direction Connection
        self.syssock.connect((address[0], sendPort))
        # Handshake part 2 - Send SYN/ACK
        self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_SYN | SOCK352_ACK, seq_no, packet.sequence_no + 1), True)
        # Handshake part 3 - Receive ACK
        packet = self.recvSingleRdpPacket()
        if packet.ack_no != seq_no + 1:
            print("Invalid sequence number received")
            return
        # print "3-way Handshake completed from server side."
        self.connected = True
        if (encrypt_flag == ENCRYPT):
            self.encrypt = True
            # print "Server's private key:"
            # print privateKeysHex[('*', '*')]
            self.box = Box(privateKeys[('*', '*')], publicKeys[(address[0], str(sendPort))])
        return (self, address)
    
    """
    Closes connection obetween client and server.
    Verifies that both client and server are finished by performing 2-way handshake.
    Client and Server both send a FIN and an ACK for the FIN that they receive.
    """
    def close(self): 
        catchupNeeded = False
        # 2-way double handshake. Send FIN and wait for ACK.
        rand_no = random.randint(1000000000, 4294967294)
        # Handshake part 1 - Send FIN.
        self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_FIN, rand_no, rand_no), True)
        # Handshake part 2 - Receive FIN.
        packet = self.recvSingleRdpPacket()
        # If packet received is not a FIN packet, that means last ACK was not received. 
        while (packet.flags & SOCK352_FIN == 0):
            catchupNeeded = True
            print("Not a FIN packet. Sending last ACK and Restarting. Flags: " + str(packet.flags))
            self.sendSingleRdpPacket(self.lastAckSent)
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_FIN, rand_no, rand_no), True)
            packet = self.recvSingleRdpPacket()

        try:
            # Handshake part 3 - Send ACK.
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, packet.ack_no, packet.ack_no), True)
            catchupNeeded = False
            # Handshake part 4 - Receive ACK.
            packet = self.recvSingleRdpPacket()
            # If packet received is not a FIN packet, that means last ACK was not received. 
            while (packet.flags & SOCK352_ACK == 0 or packet.ack_no != rand_no):
                catchupNeeded = True
                print("Not a final ACK packet. Sending FIN/ACK and receiving again... Flags: " + str(packet.flags))
                self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_FIN, rand_no, rand_no), True)
                self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, packet.ack_no, packet.ack_no), True)
                packet = self.recvSingleRdpPacket()
        except:
            # Other end closed socket. We will close socket too.
            pass
        print "Closing complete. Flags Received here: " + str(packet.flags)
        # print "2-way double handshake complete. Closing Socket."
        # Tell OS we are done with socket.
        self.syssock.close()
        self.connected = False
        return 

    """
    Send arbitrary buffer of data. This function should break down buffer into a series of 
    RDP packets to transmit through the socket. 
    """
    def send(self,buffer):
        packets = []
        # Break down buffer into packets of max size 64k.
        for i in range(0, len(buffer), PACKET_SIZE_LIMIT_IN_BYTES):
            bufferChunk = buffer[i:i + PACKET_SIZE_LIMIT_IN_BYTES]
            # Build packet from buffer chunk
            packet = rdpPacket((1, 0, 0, 0, 40, 0, 0, 0, i / PACKET_SIZE_LIMIT_IN_BYTES, i / PACKET_SIZE_LIMIT_IN_BYTES, 0, len(bufferChunk)), bufferChunk)
            packets.append(packet)
        self.sendRdpPackets(packets)
        return len(buffer) 

    """
    Receive arbitrary buffer of data. This function should recombine the packets received by 
    the RDP Protocol into the original buffer of data that was transmitted.
    This data should be returned to the caller.
    """
    def recv(self,nbytes):
        # Determine number of packets to receive via RDP Protocol.
        packets_expected = (nbytes - 1) / PACKET_SIZE_LIMIT_IN_BYTES + 1
        packets = self.recvRdpPackets(packets_expected)
        # Unpack packets back into buffer and return to user.
        buffer = ''
        for packet in packets:
            buffer += packet.data
        return buffer 

    """
    Send a set of RDP Packets through the socket. This function will also receive Acknowledgement (ACK) 
    packets from the recipient to ensure the data has been received.
    This function will use the Go-Back-N Procedure to re-send any packets that have not been acknowledged. 
    """
    def sendRdpPackets(self, packets):
        # Send packets in order. Start timer to measure timeout for each packet.
        # Listen for ACKs and re-send packets that exceed timeout.
        # Send individual packets using sendSingleRdpPacket(packet)
        # If ACK N > 0 not received after timeout, continue to send from Sequence N.
        lastAckReceived = -1
        lastPacketSent = -1
        timer = Timer(TIME_OUT)

        while(lastAckReceived + 1 < len(packets)):

            # Send next packet
            if lastPacketSent + 1 < len(packets):
                # print "More packets to send."
                lastPacketSent += 1

                # start timer for packet # (lastAckReceived + 1) if not already started
                if not timer.started():
                    # print "Starting timer for " + str(lastPacketSent)
                    timer.start_timer()

                self.sendSingleRdpPacket(packets[lastPacketSent])
                # print "Sent " + str(lastPacketSent) + ", last ACK received: " + str(lastAckReceived)

            # Check for ACK packet availability here.
            # Select System Call will check if the UDP socket can be read from.
            # If it cannot be read from, we will not call recv until after sending the next packet.
            # This prevents "stop-and-wait" and allows multiple packets to be sent before 
            # receiving the first ACK.
            (readableSockets, writableSockets, err) = select.select([self.syssock], [], [], 0)
            if (len(readableSockets) > 0):
                print "Receiving ACK. Next Ack expected: " + str(lastAckReceived)
                packet = self.recvSingleRdpPacket() 
                # If packet received is NOT an ACK, user is still sending. Last ACK we sent must not have been received.
                # Re-send ACK. Start sending from packet 0 again.
                if (packet.equals(self.lastPacketRecv)):
                    self.sendSingleRdpPacket(self.lastAckSent)
                    lastPacketSent = -1
                    continue
                if packet.flags & SOCK352_ACK == 0:
                    # Ignore packet
                    continue
                print "ACK Packet Received. ACK: " + str(packet.ack_no) + ", flags: " + str(packet.flags)

                # start timer if ACK # not previously seen was received and if ACK is not completely up-to-date
                if (lastAckReceived < packet.ack_no < lastPacketSent): 
                    # print "Starting timer for packet " + str(packet.ack_no + 1)
                    timer.start_timer()

                lastAckReceived = max(packet.ack_no, lastAckReceived)

            # Check if packet exceeded timeout
            if lastPacketSent > lastAckReceived: # ACKs are not up-to-date

                nextAckExpected = packets[lastAckReceived + 1]

                # If segment hasn't received ACK after timeout, resend.
                if timer.time_out(): 

                    # stop the timer and set timer for packet # (lastAckReceived + 1)
                    # print "Timed out. Starting timer for packet " + str(lastAckReceived + 1)
                    timer.start_timer()
                    lastPacketSent = lastAckReceived # this resets so that all unacknowledged packets are sent again (timeout)

            # same as lastPacketSent == lastAckReceived (ACKs are up-to-date)    
            else: 
                # stop the timer
                # print "Timer stopped, everything up-to-date. lastAckReceived = " + str(lastAckReceived)
                timer.stop_timer()

    """
    Receive a set of RDP Packets from the socket. This function will also send Acknowledgement (ACK)
    packets to the sender to inform them that the packet has been received.  
    """
    def recvRdpPackets(self, numPackets):
        # Continuously call recvSingleRdpPacket and fill in packets receive.
        # After each received packet, send acknowledgement of latest packet received where all previous
        # packets have also been received.
        # Return set of packets received back to caller.
        ret = [None] * numPackets
        lastAck = -1
        while(lastAck + 1 < numPackets):
            nextPacket = self.recvSingleRdpPacket()
            if (nextPacket.equals(self.lastPacketRecv)):
                # Still receiving packets from previous recvRdpPackets call... Re-send last ACK and restart.
                self.sendSingleRdpPacket(self.lastAckSent)
                continue
            if nextPacket.flags & SOCK352_FIN > 0:
                # Ignore packet
                continue
            print "Received Sequence no: " + str(nextPacket.sequence_no) + " (out of " + str(numPackets) + ")"
            if (nextPacket.sequence_no == lastAck + 1): 
                lastAck += 1
                ret[lastAck] = nextPacket
                self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, lastAck, lastAck))
            elif (nextPacket.sequence_no <= lastAck): # if receive old packet, resend the current cumulative ACK
                self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, lastAck, lastAck))
        self.lastAckSent = self.generateEmptyPacket(SOCK352_ACK, lastAck, lastAck)
        self.lastPacketRecv = ret[-1]
        return ret


    """
    Sends single RDP Packet. All transmissions across UDP Network should use this.
    Packets have a size limit. It may be necessary for the caller to break up 
    the transmitted data into multiple packets and send them in order.

    Once the packet is sent, it is the responsibility of the caller to receive the Acknowledgement (ACK)
    packet from the receiver of the packet.
    """
    def sendSingleRdpPacket(self, packet, handshake = False):
        # Serialize RDP Packet into raw data.
        # Transmit data through UDP socket.

        if (self.encrypt and not packet.encrypted):
            packet.flags |= SOCK352_HAS_OPT
            packet.opt_ptr = 1
            packet.data = self.box.encrypt(packet.data, self.nonce)
            packet.payload_len = len(packet.data)
            packet.encrypted = True

        rand = random.randint(1, 100)
        if (not handshake and rand < self.dropPercentage):
            # Drop Packet.
            # print "Dropping packet (Seq No: " + str(packet.sequence_no) + ")"
            return
        self.syssock.send(packet.pack())

    """
    Receives single RDP Packet. All packets should be received using this.
    Packets have a size limit. It may be necessary for the caller to 
    receive multiple packets before they get all the data they want.

    Once the packet is received, it is the responsibility of the caller to send the Acknowledgement (ACK)
    packet back to the sender of the packet.
    """
    def recvSingleRdpPacket(self):

        # Deserialize raw data and rebuild RDP Packet.
        # Return RDP Packet to caller.
        # Read one entire datagram.
        (packedPacket, address) = self.syssock.recvfrom(PACKET_SIZE_LIMIT_IN_BYTES + 200)

        header = struct.unpack("!BBBBHHLLQQLL", packedPacket[:40])
        # Last 4 bytes contain payload length.
        payload_len = header[-1]
        data = ''
        if payload_len > 0:
            data = packedPacket[40:]
        ret = rdpPacket(header, data)
        ret.sender_address = address

        if ret.flags & SOCK352_SYN > 0 and self.connected: # and we don't have a connection yet:
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_RESET, ret.sequence_no + 1, ret.sequence_no + 1))
            return recvSinglePacket()

        if ret.opt_ptr == 1:
            original = ret.data
            ret.data = self.box.decrypt(ret.data)
            ret.payload_len = len(ret.data)
            ret.opt_ptr = 0
            # print ret.data[:20]

        return ret


    """
    Generate RDP Packet with no payload
    """
    def generateEmptyPacket(self, flags, seq_no, ack_no):
        return rdpPacket((1, flags, 0, 0, 40, 0, 0, 0, seq_no, ack_no, 0, 0), '')

class rdpPacket:

    def __init__(self, (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len), data):
        self.data = data
        self.version = version # Should be 1
        self.flags = flags
        self.opt_ptr = opt_ptr # Should be 0
        self.protocol = protocol # Should be 0
        self.header_len = header_len # Should be 40
        self.checksum = self.generateChecksum()
        self.source_port = source_port # Should be 0
        self.dest_port = dest_port # Should be 0
        self.sequence_no = sequence_no
        self.ack_no = ack_no
        self.window = window
        self.payload_len = payload_len
        self.encrypted = False

    def pack(self):
        return struct.pack("!BBBBH", self.version, self.flags, self.opt_ptr, self.protocol, self.header_len) + struct.pack("!i", self.checksum)[2:] + struct.pack("!LLQQLL", self.source_port, self.dest_port, self.sequence_no, self.ack_no, self.window, self.payload_len) + self.data

    def equals(self, packet):
        if packet is None:
            return False
        for field in self.__dict__.keys():
            if getattr(self, field) != getattr(packet, field):
                return False
        return True

    """
    Generates the checksum for the packet's data.
    The packet's checksum needs to be in bytes format because the checksum is supposed to be 2 bytes
    """
    def generateChecksum(self):
        new_checksum = 0
        num_bytes = WORD_SIZE / 8
        list_words = [self.data[i : i + num_bytes] for i in range(0, len(self.data), num_bytes)]

        for word in list_words:
            if len(word) == 2:
                new_checksum ^= struct.unpack("!H", word)[0]
            elif len(word) == 1:
                new_checksum ^= struct.unpack("!B", word)[0]

        new_checksum = ~new_checksum
        return new_checksum

    """
    Returns 0 if packet is not corrupted (checksum was unchanged)
    """
    def check_checksum(self):
        return self.checksum ^ generateChecksum(self)


"""
Timer Class
"""
class Timer:
    """
    A timer has a start time that indicates when the timer has started, which is initially set to zero.
    The timeout to tell when the timer has "timed out" is also specified.
    """
    def __init__(self, timeout):
        self.start = None
        self.timeout = timeout

    """
    Return true if timer is running, false otherwise.
    """
    def started(self):
        return self.start != None

    """
    Starts the timer.
    """
    def start_timer(self):
        self.start = time.time()

    """
    Stops the timer.
    """
    def stop_timer(self):
        self.start = None

    """
    Returns true if the timer has timed out, false otherwise.
    """
    def time_out(self):
        if self.started():
            return time.time() - self.start >= self.timeout
        return False
