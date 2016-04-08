#!/usr/bin/env python

"""
					..:: FEAL-4 chosen plaintext collection code ::..
					'five blocks' - VolgaCTF Quals 2016 (Crypto/600)
									by Jos Wetzels
"""

import struct
from pwn import *

MAX_DATA_TO_RECEIVE_LENGTH = 8196

def left_half(x):
	return ((x >> 32) & 0xFFFFFFFF)

def right_half(x):
	return (x & 0xFFFFFFFF)

def bytes_to_qword(plaintext):
	p = struct.unpack('<Q', plaintext)[0]
	return ((right_half(p) << 32) | left_half(p))

def qword_to_bytes(ciphertext):
	return struct.pack('<Q', ((right_half(ciphertext) << 32) | left_half(ciphertext)))

def block_xor(b1, b2):
    return ''.join([chr(ord(a) ^ ord(b))  for a,b in zip(b1, b2)])

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
    s.send(send_buffer)

def get_pair(h, plaintext):
	send_message(h, plaintext)
	m = read_message(h)
	iv = m[:8]
	ciphertext = m[8:]
	return plaintext, ciphertext, iv

def get_plaintext_ciphertext_pair(input_text):
	host = 'localhost'
	port = 8888

	h = remote(host, port, timeout = None)

	plaintext, ciphertext, iv = get_pair(h, input_text)

	h.close()
	return plaintext, ciphertext, iv

def get_bc1_bc2_ciphertext(plaintext_block):
	# [(D2(E1(A)) ^ iv)] [D2(E1(A)) ^ E1(A)]
	plaintext, ciphertext, iv = get_plaintext_ciphertext_pair(plaintext_block + plaintext_block)
	D2E1A = block_xor(ciphertext[0:8], iv)
	E1A = block_xor(ciphertext[8:16], D2E1A)
	return E1A, D2E1A

def bc1_chosen_plaintexts(n, input_differential):
	pairs = []

	for i in xrange(n):
		# Retry if we timeout
		while(True):
			try:
				plaintext0 = struct.unpack('<Q', os.urandom(8))[0]
				plaintext1 = (plaintext0 ^ input_differential)
				ciphertext0 = bytes_to_qword(get_bc1_bc2_ciphertext(qword_to_bytes(plaintext0))[0])
				ciphertext1 = bytes_to_qword(get_bc1_bc2_ciphertext(qword_to_bytes(plaintext1))[0])

				pairs.append(([plaintext0, ciphertext0], [plaintext1, ciphertext1]))
			except EOFError:
				continue
			break

	return pairs