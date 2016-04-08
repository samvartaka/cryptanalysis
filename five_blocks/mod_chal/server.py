#!/usr/bin/python
from ciphers import bcs
import os
import hashlib
import struct
import SocketServer
import logging
import base64


"""
    params
"""

ADDRESS = '0.0.0.0'
PORT = 8888
TIMEOUT = 60.0
MAX_DATA_TO_RECEIVE_LENGTH = 8196
logger = None


"""
    server
"""

def read_message(s):
    received_buffer = s.recv(4)
    if len(received_buffer) < 4:
        raise Exception('Error while receiving data')
    to_receive = struct.unpack('>I', received_buffer[0:4])[0]
    if to_receive > MAX_DATA_TO_RECEIVE_LENGTH:
        raise Exception('Too many bytes to receive')
    received_buffer = ''
    while (len(received_buffer) < to_receive):
        received_buffer += s.recv(to_receive - len(received_buffer))
    return received_buffer

def send_message(s, message):
    send_buffer = struct.pack('>I', len(message)) + message
    s.sendall(send_buffer)


class ForkingTCPServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    pass

class ServiceServerHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        logger.info('Accepted  connection from {0}'.format(self.client_address[0]))
        self.request.settimeout(TIMEOUT)
        try:
            key_bc1 = ''.join([struct.pack('<I', x) for x in [1, 2, 3, 4, 5, 6]]) #data[:6*4]
            key_bc2 = ''.join([struct.pack('<H', x) for x in [7, 8, 9, 10]]) #data[6*4:]
            cryptor = bcs(key_bc1, key_bc2)
            data_to_encrypt = read_message(self.request)
            iv = os.urandom(8)
            encrypted_data = cryptor.encrypt(data_to_encrypt, iv)
            to_send = iv + encrypted_data
            send_message(self.request, to_send)

        except Exception as ex:
            logger.error(str(ex), exc_info=True)
        finally:
            logger.info('Processed connection from {0}'.format(self.client_address[0]))
        return



"""
    main
"""

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
    address = (ADDRESS, PORT)
    server = ForkingTCPServer(address, ServiceServerHandler)
    server.serve_forever()
