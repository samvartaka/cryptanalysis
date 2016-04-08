#!/usr/bin/env python

"""
..:: MitM attack against a custom Lai-Massey scheme ::..
	'five blocks' - VolgaCTF Quals 2016 (Crypto/600)
				by Jos Wetzels
"""

import sys
import struct
from math import sqrt

def split_int(m):
    return ((m>>16) & 0xFFFF, m & 0xFFFF)

def join_int(l, r):
    return (l<<16) | r

def orth(m):
    (l, r) = split_int(m)
    return join_int(r, l ^ r)

def inv_orth(m):
    (l, r) = split_int(m)
    return join_int(l ^ r, l)

def F(m, subkey):
    (l, r) = split_int(m)
    (k_l, k_r) = split_int(subkey)
    (mul_l, mul_r) = split_int(l * r)
    l = ((mul_l + r) * k_l) & 0xFFFFFFFF
    r = ((mul_r * l) + k_r) & 0xFFFFFFFF
    l = ((l<<7) | (l>>25)) & 0xFFFFFFFF
    r = ((r<<18) | (r>>14)) & 0xFFFFFFFF
    return r ^ l

def M(L, R, subkey):
    A = F((L - R) & 0xFFFFFFFF, subkey)
    CL = orth((L + A) & 0xFFFFFFFF)
    CR = (R + A) & 0xFFFFFFFF
    return (CL, CR)

def inv_M(L, R, subkey):
    L = inv_orth(L)
    A = F((L - R) & 0xFFFFFFFF, subkey)
    PL = (L - A) & 0xFFFFFFFF
    PR = (R - A) & 0xFFFFFFFF
    return (PL, PR)

def encrypt_block(plaintext, subkeys):
	(L0, R0) = struct.unpack('>II', plaintext)
	(L1, R1) = M(L0, R0, subkeys[0])
	(L2, R2) = M(L1, R1, subkeys[1])
	(L3, R3) = M(L2, R2, subkeys[2])
	(CL, CR) = M(L3, R3, subkeys[3])
	return struct.pack('>II', CL, CR)

def decrypt_block(ciphertext, subkeys):
	(L0, R0) = struct.unpack('>II', ciphertext)
	(L1, R1) = inv_M(L0, R0, subkeys[3])
	(L2, R2) = inv_M(L1, R1, subkeys[2])
	(L3, R3) = inv_M(L2, R2, subkeys[1])
	(PL, PR) = inv_M(L3, R3, subkeys[0])
	return struct.pack('>II', PL, PR)

def compute_lookup_table(target_ciphertext):
	lookup_table = {}
	for k3_candidate in xrange(2**16):
		(L0, R0) = struct.unpack('>II', target_ciphertext)
		(L1, R1) = inv_M(L0, R0, k3_candidate)
		(L2, R2) = inv_M(L1, R1, k3_candidate)
		lookup_table[(L2, R2)] = k3_candidate
	return lookup_table

def brute_force_lookup(lookup_table, target_plaintext, confirmation_plaintext, confirmation_ciphertext):
	for k0_candidate in xrange(2**16):
		for k1_candidate in xrange(2**16):
			(L0, R0) = struct.unpack('>II', target_plaintext)
			(L1, R1) = M(L0, R0, k0_candidate)
			(L2, R2) = M(L1, R1, k1_candidate)

			if ((L2, R2) in lookup_table):
				candidate_subkeys = [k0_candidate, k1_candidate, lookup_table[(L2, R2)], lookup_table[(L2, R2)]]
				if (encrypt_block(confirmation_plaintext, candidate_subkeys) == confirmation_ciphertext):
					return candidate_subkeys
	return None

def perform_mitm(target_plaintext, target_ciphertext, confirmation_plaintext, confirmation_ciphertext):
	print "[*] Building lookup table ..."
	lookup_table = compute_lookup_table(target_ciphertext)	
	print "[*] Finished building lookup table, performing lookup ..."
	subkeys = brute_force_lookup(lookup_table, target_plaintext, confirmation_plaintext, confirmation_ciphertext)
	# Undo the pow(round_key, 2) operation in key scheduling
	return [sqrt(x) for x in subkeys]

if __name__ == '__main__':
	if (len(sys.argv) != 5):
		print "[-] Usage: %s plaintext0, ciphertext0, plaintext1, ciphertext1 (in hex eg. 0x0102)" % sys.argv[0]
		exit()

	plaintext0 = long(sys.argv[1], 16)
	ciphertext0 = long(sys.argv[2], 16)
	plaintext1 = long(sys.argv[3], 16)
	ciphertext1 = long(sys.argv[4], 16)

	subkeys = perform_mitm(ciphertext0, plaintext0, ciphertext1, plaintext1)
	
	if (subkeys != None):
		print "[+] Recovered key schedule: [0x%04X, 0x%04X, 0x%04X, 0x%04X]!" % (subkeys[0], subkeys[1], subkeys[2], subkeys[3])
	else:
		print "[-] Could not recover key schedule for given plaintext/ciphertext pairs..."