#!/usr/bin/env python

"""
	'five blocks' - VolgaCTF Quals 2016 (Crypto/600)
				by Jos Wetzels

"""

from feal4_differential_cryptanalysis import *
from bc2_mitm_attack import *

output_differential = 0x0000000008000000

print "[*] Collecting chosen plaintexts ..."

pairs_2 = bc1_chosen_plaintexts(12, 0x0000000008000000)
pairs_3 = bc1_chosen_plaintexts(12, 0x0000000080800000)
pairs_4 = bc1_chosen_plaintexts(12, 0x8080000080800000)

print "[*] Mounting differential cryptanalysis attack ..."

valid_schedules = differential_cryptanalysis(output_differential, [None, pairs_2, pairs_3, pairs_4])

assert (len(valid_schedules) == 1)
subkeys_bc1 = valid_schedules[0]

print "[*] Collecting known plaintexts ..."

plaintext0, ciphertext0 = get_bc1_bc2_ciphertext(qword_to_bytes(0x0BADC0DEF00DFACE))
plaintext1, ciphertext1 = get_bc1_bc2_ciphertext(qword_to_bytes(0xC0DEFACE0BADF00D))

print "[*] Mounting MitM cryptanalysis attack ..."

subkeys_bc2 = perform_mitm(ciphertext0, plaintext0, ciphertext1, plaintext1)

assert (subkeys_bc2 != None)

print "[+] Recovered valid BC_1 key schedule [0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X, 0x%08X]!" % (subkeys_bc1[0], subkeys_bc1[1], subkeys_bc1[2], subkeys_bc1[3], subkeys_bc1[4], subkeys_bc1[5])
print "[+] Recovered valid BC_2 key schedule: [0x%04X, 0x%04X, 0x%04X, 0x%04X]!" % (subkeys_bc2[0], subkeys_bc2[1], subkeys_bc2[2], subkeys_bc2[3])