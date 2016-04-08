#!/usr/bin/env python

"""
		 ~ FEAL-4 Differential Cryptanalysis attack under chosen plaintext conditions ~
					'five blocks' - VolgaCTF Quals 2016 (Crypto/600)
									by Jos Wetzels

based on Jon King's FEAL-4 differential cryptanalysis demo code (http://www.theamazingking.com/feal4full.c)
Using modified differential characteristic and adapted backtracking algorithm for elimination of false positive keys
"""

import array
import struct
from time import time
from collect_chosen_plaintexts import *

# Bit manipulation operations
def left_half(x):
	return ((x >> 32) & 0xFFFFFFFF)

def right_half(x):
	return (x & 0xFFFFFFFF)

def sep_byte(x, i):
	return ((x >> (8 * i)) & 0xFF)

def combine_bytes(b3, b2, b1, b0):
	return (((b3 << 24) | (b2 << 16) | (b1 << 8) | (b0)) & 0xFFFFFFFF)

def combine_halves(x, y):
	return (((x << 32) | (y & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF)

# FEAL-4 Rotation
def rot(x):
	return ((x<<4) | (x>>4)) & 0xff

# FEAL-4 G-Box
def g_box(a, b, mode):
	return rot((a + b + mode) & 0xff)

# FEAL-4 round function ('f-box')
def f_box(x):
	x0 = sep_byte(x, 0)
	x1 = sep_byte(x, 1)
	x2 = sep_byte(x, 2)
	x3 = sep_byte(x, 3)

	t0 = (x2 ^ x3)
	y1 = g_box(x0 ^ x1, t0, 1)
	y0 = g_box(x0, y1, 0)
	y2 = g_box(y1, t0, 0)
	y3 = g_box(y2, x3, 1)
	return combine_bytes(y3, y2, y1, y0)

# Round key cracking function
def crack_round_key(pairs, output_differential):
	valid_candidates = []
	candidate_key = 0
	while (candidate_key < 2**32):
		score = 0
		for i in xrange(len(pairs)):
			cipher_left = left_half(pairs[i][0][1])
			cipher_left ^= left_half(pairs[i][1][1])
			cipher_right = right_half(pairs[i][0][1])
			cipher_right ^= right_half(pairs[i][1][1])

			y = cipher_right
			z = (cipher_left ^ output_differential)

			candidate_right = right_half(pairs[i][0][1])
			candidate_left = left_half(pairs[i][0][1])
			candidate_right2 = right_half(pairs[i][1][1])
			candidate_left2 = left_half(pairs[i][1][1])

			y0 = candidate_right
			y1 = candidate_right2

			candidate_input0 = y0 ^ candidate_key
			candidate_input1 = y1 ^ candidate_key
			candidate_output0 = f_box(candidate_input0)
			candidate_output1 = f_box(candidate_input1)
			candidate_differential = (candidate_output0 ^ candidate_output1)

			if (candidate_differential == z):
				score += 1
			else:
				break

		if (score == len(pairs)):
			valid_candidates.append(candidate_key)

		candidate_key += 1

	return valid_candidates

# Undo last FEAL-4 round
def undo_last_round(pairs, round_key):
	for i in xrange(len(pairs)):
		cipher_left0 = left_half(pairs[i][0][1])
		cipher_right0 = right_half(pairs[i][0][1])

		cipher_left1 = left_half(pairs[i][1][1])
		cipher_right1 = right_half(pairs[i][1][1])

		cipher_left0 = cipher_right0
		cipher_left1 = cipher_right1
		cipher_right0 = f_box(cipher_left0 ^ round_key) ^ (pairs[i][0][1] >> 32)
		cipher_right1 = f_box(cipher_left1 ^ round_key) ^ (pairs[i][1][1] >> 32)

		pairs[i][0][1] = combine_halves(cipher_left0, cipher_right0)
		pairs[i][1][1] = combine_halves(cipher_left1, cipher_right1)

	return pairs

# Undo final operation of a Feistel round (cipherLeft ^ R4R)
def undo_final_operation(pairs):
	for i in xrange(len(pairs)):
		cipher_left0 = left_half(pairs[i][0][1])
		cipher_right0 = right_half(pairs[i][0][1]) ^ cipher_left0

		cipher_left1 = left_half(pairs[i][1][1])
		cipher_right1 = right_half(pairs[i][1][1]) ^ cipher_left1

		pairs[i][0][1] = combine_halves(cipher_left0, cipher_right0)
		pairs[i][1][1] = combine_halves(cipher_left1, cipher_right1)

	return pairs

# Backtracking approach to cracking rounds 2 to 4 (subkeys 2, 3 and 4)
def phase1(current_round, subkeys = [], output_differential = 0, chosen_pairs = []):
	valid_candidates = []
	# Work our way back from final round 4 (index 3) to round 2 (index 1)
	if (current_round == 0):
		# If we get to this point in a path, we recovered a candidate partial key schedule that's valid from rounds 4 to 2
		return [subkeys[::-1]]
	else:
		print "[*] Cracking round %d, using output differential %lx ..." % (current_round+1, output_differential)
		# Take chosen plaintext pairs crafted with input differential tailored to this round, undo final Feistel operation

		pairs = undo_final_operation(chosen_pairs[current_round])
		# Undo previous rounds with round keys extracted so far in this path
		for j in xrange(0, (3-current_round)):
			pairs = undo_last_round(pairs, subkeys[j])

		# Obtain candidates for this round
		candidate_roundkeys = crack_round_key(pairs, output_differential)
		
		if (len(candidate_roundkeys) == 0):
			# Failed to find any subkey candidates for this round using given recovered keyschedule, backtrack...
			return []
		else:
			for candidate_k in candidate_roundkeys:
				print "[*] Trying candidate subkey [0x%08x] for round %d ..." % (candidate_k, current_round+1)
				r = phase1(current_round-1, subkeys + [candidate_k], output_differential, chosen_pairs)
				if (len(r) > 0):
					# We've recovered a valid partial key schedule
					valid_candidates += r

	return valid_candidates

# Crack round 1 and subkeys 1, 5 and 6
def phase2(candidate_schedules = [], chosen_pairs = [], multi = False):
	valid_schedules = []
	for subkeys in candidate_schedules:
		# Take pairs for round 2, strip to round 1
		pairs = undo_last_round(chosen_pairs[1], subkeys[0])

		k0_guess = 0
		while (k0_guess < 2**32):
			k4_guess = None
			k5_guess = None

			for j in xrange(len(pairs)):
				plain_left0 = left_half(pairs[j][0][0])
				plain_right0 = right_half(pairs[j][0][0])

				cipher_left0 = left_half(pairs[j][0][1])
				cipher_right0 = right_half(pairs[j][0][1])

				y = (f_box(cipher_right0 ^ k0_guess) ^ cipher_left0)

				# Make first guess attempt
				if (k4_guess == None):
					k4_guess = (y ^ plain_left0)
					k5_guess = (y ^ cipher_right0 ^ plain_right0)
				
				# Maintain consistency across pairs
				elif ((y ^ plain_left0 != k4_guess) or (y ^ cipher_right0 ^ plain_right0 != k5_guess)):
					k4_guess = None
					k5_guess = None
					break

			# Valid k0, k4, k5 combo found, adjust key schedule
			if ((k4_guess != None) and (k5_guess != None)):
				subkeys.insert(0, k0_guess)
				subkeys.insert(4, k4_guess)
				subkeys.insert(5, k5_guess)
				break

			k0_guess += 1

		# If we've recored a valid full key schedule we immediately return it if we don't require multiple possible valid key schedules, else we add it to a list
		if(len(subkeys) == 6):
			if (multi):
				valid_schedules.append(subkeys)
			else:
				return [subkeys]

	return valid_schedules

# Combine backtracking routines into single complete differential cryptanalysis routine
def differential_cryptanalysis(output_differential, chosen_pairs):
	subkeys = []

	# Crack final 3 round keys
	candidate_schedules = phase1(3, subkeys, output_differential, chosen_pairs)

	if (len(candidate_schedules) == 0):
		print "[-] Failed to crack round keys 2 to 4..."
		return
	else:
		print "[*] Recovered %d candidate partial key schedules..." % len(candidate_schedules)

	# Crack first 3 round keys
	return phase2(candidate_schedules, chosen_pairs, False)

if __name__ == "__main__":
	print "~ FEAL-4 Differential Cryptanalysis attack under chosen plaintext conditions ~"
	print "\t\t\t\t'five blocks' - VolgaCTF Quals 2016 (Crypto/600)"
	print "\t\t\t\t\t\t\tby Jos Wetzels\n"
	print "based on Jon King's FEAL-4 differential cryptanalysis demo code (http://www.theamazingking.com/feal4full.c)"
	print "Using modified differential characteristic and adapted backtracking algorithm for elimination of false positive keys\n"

	output_differential = 0x0000000008000000

	pairs_2 = bc1_chosen_plaintexts(12, 0x0000000008000000)
	pairs_3 = bc1_chosen_plaintexts(12, 0x0000000080800000)
	pairs_4 = bc1_chosen_plaintexts(12, 0x8080000080800000)

	valid_schedules = differential_cryptanalysis(output_differential, [None, pairs_2, pairs_3, pairs_4])

	if (len(valid_schedules) > 0):
		for subkeys in valid_schedules:
			print "[+] Recovered valid FEAL-4 key schedule [0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x]!" % (subkeys[0], subkeys[1], subkeys[2], subkeys[3], subkeys[4], subkeys[5])
	else:
		print "[-] Failed to recover FEAL-4 key schedule..."