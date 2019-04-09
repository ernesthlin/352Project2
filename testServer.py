import sock352

sock352.readKeyChain('server.key')
sock352.init(38912, 38911)

socket = sock352.socket()

# Server will drop 20% of the packets it sends.
socket.dropPercentage = 20

print "Binding..."
socket.bind(('', 1010))
print "Listening..."
socket.listen(5)
print "Accepting..."
socket.accept()#sock352.ENCRYPT)

print "Receiving..."

data = socket.recv(488890)

print "Sending: " + data[:20] + "..." + data[-20:]
ret = socket.send(data)

print "Sent."
print "Closing socket..."

socket.close()

print "Closed socket."