import sock352

sock352.readKeyChain('client.key')
sock352.init(38911, 38912)

socket = sock352.socket()

# Client will drop 20% of the packets it sends.
socket.dropPercentage = 20

# Create really long string.
s = "".join([str(i) for i in range(100000)])
# for i in range(100000):
# 	s += str(i)

print len(s)

print "Connecting..."
socket.connect(('localhost', 1010), sock352.ENCRYPT)
print "Connected"

print "Sending TEST"
socket.send(s)

print "Receiving TEST"
ret = socket.recv(488890)

print "DATA RECEIVED BACK"
print "VALID: " + str(ret == s)

socket.close()

print "Closed socket."