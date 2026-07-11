import socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("149.154.167.02", 443))
# take last encrypted message
# decrypt it to fill all session fields
# create new message with session object
# send