import random
import string
from bitarray import bitarray
from bitstring import BitArray


# Key Generator(s) and other helpful functions
def generate_random_key(plaintext):
    size = len(plaintext)
    key = ""

    for _ in range(size):
        key += random.choice(string.printable)  # generates random key choosing from all ascii characters

    # integer value of key: ord(key[i])
    return key


# 56 bit random key generator
def generate_56bit_key():
    key = []
    for _ in range(56):
        key.append(random.randint(0, 1))
    return key


# 64 bit random key generator
def generate_64bit_key():
    key = []
    for _ in range(64):
        key.append(random.randint(0, 1))
    return key


def generate_random_8bytes():
    chars = "0123456789abcdef"
    bytes = "0x"

    for i in range(16):
        bytes += random.choice(chars)
    return bytes


# creates a 2D array (4x4) which holds the bytes of the random key
# 128 bits -> 4 words(32 bit chunks)/16 bytes
def generate_random_AES_key():
    chars = "0123456789abcdef"
    key = []

    for i in range(4):
        row = []
        for j in range(4):
            byte = ""
            byte += random.choice(chars)
            byte += random.choice(chars)
            row.append(byte)
        key.append(row)

    print("AES key:")
    for i in range(4):
        for j in range(4):
            print(key[i][j], end="\t")
        print()
    print()

    return key


# generates a 128 bit plaintexxt and puts it's bytes in a 4x4 array
# used just for testing the algorithm
def create_aes_plaintext():
    chars = "0123456789abcdef"
    pt = []

    for i in range(4):
        row = []
        for j in range(4):
            byte = ""
            byte += random.choice(chars)
            byte += random.choice(chars)
            row.append(byte)
        pt.append(row)

    return pt


# Encryption Algorithms with complexities

# Shift Cipher -> Θ(n)
# ----------------------------------------------------------------------------------------------------------------------

def shift_cipher_enc(plaintext):

    encrypted = ""
    key = random.randint(0, 255)    # 256 chars in ascii table

    for i in range(len(plaintext)):
        enc_char = chr(ord(plaintext[i]) + key)
        encrypted += enc_char

    return encrypted, key

# ----------------------------------------------------------------------------------------------------------------------


# Vigenere Cipher -> Θ(n)
# ----------------------------------------------------------------------------------------------------------------------

def vigenere_cipher_enc(plaintext, key):

    if len(plaintext) != len(key):
        print("ERROR! Key Length doesn't match message length!")
        return None

    encrypted = ""

    for i in range(len(plaintext)):
        enc_char = chr(ord(plaintext[i]) + ord(key[i]))
        encrypted += enc_char

    return encrypted

# ----------------------------------------------------------------------------------------------------------------------


# One-Time Pad (or XOR encryption) -> Θ(n)
"""
Vulnerabilities:
            -> c1 = k XOR m1, c2 = k XOR m2, attacker can compute c1 XOR c2 = (k XOR m1) XOR (k XOR m2) = m1 XOR m2
            which leaks info about m1, m2 if the same key is used twice (no longer perfectyly secret)
"""
# ----------------------------------------------------------------------------------------------------------------------


def one_time_pad_enc(plaintext, key):

    if len(plaintext) != len(key):
        print("ERROR! Key Length doesn't match message length!")
        return None

    encrypted = ""

    for i in range(len(plaintext)):
        enc_char = chr(ord(plaintext[i]) ^ ord(key[i]))
        encrypted += enc_char

    return encrypted

# ----------------------------------------------------------------------------------------------------------------------


# DES (Data Encryption Standard, used for network security)
# ----------------------------------------------------------------------------------------------------------------------

# plaintext: 64 bits
# key: 56 bits (or 64 bits)


# === DES main functions ===
# ======================================================================================================================

# Encrypts a string with DES algorithm (not recommended since DES is used for encrypting packets and takes only 64 bits)
# convert plaintext to bits and encrypt to ciphertext (DES' main)
def des_string_encryption(plaintext):
    ba = bitarray()

    ba.frombytes(plaintext.encode('utf-8'))
    binary_plaintext = bitarray_to_array(ba)

    if len(binary_plaintext) % 64 != 0:
        print("Cannot decode this string since it's binary length cannot be divided by 64!")
        return None, None

    ciphertext = []

    key = generate_56bit_key()

    for i in range(1, int(len(binary_plaintext)/64)+1):
        start = i*64 - 64
        end = i*64
        ciphertext.append(des_enc(binary_plaintext[start:end], key))

    return ciphertext, key


# Encrypts packet data with DES algorithm
# convert packet byte data into bits and print ciphertext into bits
def des_packet_encryption(packet, key):
    packet_ba = BitArray(hex=packet)
    packet_bits = bitarray_to_array(packet_ba)
    print("plaintext:\t\t" + str(packet))
    print("Key:\t\t\t", end="")
    for k in key:
        print(k, end="")
    print()

    ciphertext = des_enc(packet_bits, key)
    print("Ciphertext:\t\t", end="")
    for c in ciphertext:
        print(c, end="")
    print()

    return ciphertext


# ======================================================================================================================

# global variables for DES algorithm
IPtext = [None]*64

KEYS_48bit = [[None]*48]*16
C = [[None]*48 for i in range(17)]       # subkey1 array for each step2 round
D = [[None]*48 for i in range(17)]       # subkey2 array for each step2 round

# permutation table for each subkey pairs to help convert 56bit subkeys to 48it ones
PC2 = [14, 17, 11, 24,  1,  5,
       3, 28, 15,  6, 21, 10,
       23, 19, 12,  4, 26,  8,
       16,  7, 27, 20, 13,  2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# list of new positions for every bit (for example the 1st bit goes to position 58 out of 64bits of plaintext)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Plaintext Partitions
LPT = [[None]*32 for i in range(17)]
RPT = [[None]*32 for i in range(17)]

# helps with expansion positioning
E = [32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32,  1]

# expanded bits of RPT
expanded = [None]*48

# S-Box Substitution XOR input
XORtext = [None]*48

# S-Bot Substitution Arrays
X = [[None]*6 for i in range(8)]
X2 = [None]*32

INDEX = 0

# S [4][16]
S1 = [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
      [0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
      [4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
      [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]]

S2 = [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
      [3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
      [0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
      [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]]

S3 = [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
      [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
      [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
      [1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]]

S4 = [[7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
      [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14, 9],
      [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8, 4],
      [3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]]

S5 = [[2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14, 9],
      [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8, 6],
      [4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
      [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]]

S6 = [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
      [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
      [9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
      [4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]]

S7 = [[4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
      [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
      [1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
      [6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]]

S8 = [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
      [1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
      [7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
      [2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]

# arrays for P-Box Permutation
P = [16,  7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
     32, 27,  3,  9,
     19, 13, 30,  6,
     22, 11,  4, 25]

R = [None]*32

# for Final Permutation
CIPHER = [None]*64
ENCRYPTED = [None]*64

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41,  9, 49, 17, 57, 25]


def des_enc(plaintext, key):

    # STEP 1: Initial Permutation

    for i in range(64):
        j = 0
        while j < 64:
            if IP[j] == i+1:
                break
            j += 1
        IPtext[j] = plaintext[i]

    LPT[0] = IPtext[:32]
    RPT[0] = IPtext[32:]

    # STEP 2: (16 rounds) Key Transformation, Expansion Permutation, S-Box Substitution, P-Box Permutation. XOR and Swap

    # 2.1 key transformation (Compression, Permutation)
    create_16_keys(key)

    mode = 0    # 0 = Encryption, 1 = Decryption

    # 16 rounds
    for rnd in range(1, 17):
        cipher(rnd, mode)

        for i in range(32):
            LPT[rnd][i] = RPT[rnd-1][i]

    # STEP 3: Final Permutation
    for i in range(64):
        if i < 32:
            CIPHER[i] = RPT[16][i]
        else:
            CIPHER[i] = LPT[16][i-32]
        final_permutation(i, CIPHER[i])

    return ENCRYPTED


# ciphertext: 64 bits

# Final Permutation (step3) funciton
def final_permutation(pos, data):
    i = 0

    while i < 64:
        if FP[i] == pos + 1:
            break
        i += 1
    ENCRYPTED[i] = data


# cipher generation function
def cipher(Round, mode):
    # 2.2 Expansion Permutation
    for i in range(32):
        # RPT 32bits -> 48 bits
        expansion(i, RPT[Round - 1][i])
    # 48bit transformed key XOR 48bit expanded RPT -> S-Box Substitution
    for i in range(48):

        """
        !!! I CHANGED KEYS_48bit[ROUND][i] AND KEYS_48bit[17 - Round] TO WHAT IT IS NOW IN XOR()
        """

        if mode == 0:
            # encryption
            XORtext[i] = XOR(expanded[i], KEYS_48bit[Round-1][i])
        else:
            # decryption
            XORtext[i] = XOR(expanded[i], KEYS_48bit[17 - Round - 1][i])

    # 2.3 S-Box Substitution (48 bits from the previous XOR -> 32 bits for X2 used in the next step)
    SBox(XORtext)

    # 2.4 P-Box Permutation
    for i in range(32):
        PBox(i, X2[i])

    # 2.5 XOR and Swap
    for i in range(32):
        RPT[Round][i] = XOR(LPT[Round - 1][i], R[i])


# XOR two bit-arrays
def XOR(a, b):
    return a ^ b


def PBox(pos, data):
    i = 0

    while i < 32:
        if P[i] == pos + 1:
            break
        i += 1
    R[i] = data


# S-Box Substitution
def SBox(xortext):

    global INDEX
    temp_x2 = list()

    # 8 S-Boxes with 6 bits each
    for i in range(8):
        for j in range(6):
            X[i][j] = xortext[j + 6*i]

    # substitute the 8 6bit boxes into 8 4bit ones and convert them into one 32bit box
    for INDEX in range(8):
        # these are not needed since i recreated them
        # value = F1(INDEX)
        # ToBits(value)

        temp_x2.append(SBoxes(INDEX + 1, X[INDEX]))

    for idx in range(8):
        for jdx in range(4):
            X2[idx*4 + jdx] = temp_x2[idx][jdx]


# takes 6bit box and converts it to a 4 bit one
def SBoxes(box_num, box):
    temp_s = []

    if box_num == 1:
        temp_s = S1
    elif box_num == 2:
        temp_s = S2
    elif box_num == 3:
        temp_s = S3
    elif box_num == 4:
        temp_s = S4
    elif box_num == 5:
        temp_s = S5
    elif box_num == 6:
        temp_s = S6
    elif box_num == 7:
        temp_s = S7
    elif box_num == 8:
        temp_s = S8

    # decimal number from 0 to 3 determined by the first and last bits of box
    i = binary_to_decimal_2([box[0], box[5]])    # represents row in temp_s
    # decimal from 0 to 15 determined by the 4 middle bits of box
    j = binary_to_decimal_4([box[1], box[2], box[3], box[4]])    # represents column in temp_s

    x2 = decimal_to_bin_array(temp_s[i][j])

    return x2


# 2 bits
def binary_to_decimal_2(bit_array):
    decimal_num = bit_array[0] * 2 + bit_array[1]
    return decimal_num


# 4 bits
def binary_to_decimal_4(bit_array):
    decimal_num = bit_array[0] * 8 + bit_array[1] * 4 + bit_array[2] * 2 + bit_array[3]
    return decimal_num


def decimal_to_bin_array(num):
    array = [0]*4

    idx = 3

    while num != 0:
        bit = num % 2
        array[idx] = bit

        num = int(num/2)
        idx -= 1

    return array


# i rewrote the code for this part so these are not needed

def F1(i):
    b = []

    for j in range(6):
        b.append(X[i][j])

    r = b[0] * 2 + b[5]
    c = 8 * b[1] + 4 * b[2] + 2 * b[3] + b[4]

    if i == 0:
        return S1[r][c]
    elif i == 1:
        return S2[r][c]
    elif i == 2:
        return S3[r][c]
    elif i == 3:
        return S4[r][c]
    elif i == 4:
        return S5[r][c]
    elif i == 5:
        return S6[r][c]
    elif i == 6:
        return S7[r][c]
    elif i == 7:
        return S8[r][c]


# BUG HERE (X2 has its 9 last bits None)
def ToBits(value):

    global INDEX

    if INDEX % 32 == 0:
        INDEX = 0

    j = 3
    while j >= 0:
        m = 1 << j
        k = value & m

        if k == 0:
            X2[3 - j + INDEX] = ord('0') - 48
        else:
            X2[3 - j + INDEX] = ord('1') - 48

        INDEX += 4
        j -= 1


# additional functions
def expansion(pos, data):
    for i in range(48):
        if E[i] == pos+1:
            expanded[i] = data


def create_16_keys(key):
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # 56bit key -> 28bit + 28 bit subkeys
    subkey1 = key[:28]  # highest to mid bit
    subkey2 = key[28:]  # mid to lowest bit

    # shift the halves left circularly by one or two positions depending on the round
    subkey1, subkey2 = shift_circ_key_partitions(subkey1, subkey2, 1)
    C[0] = subkey1
    D[0] = subkey2

    for i in range(1, 17):
        C[i], D[i] = shift_circ_key_partitions(C[i-1], D[i-1], shifts[i-1])

    # combine the two subkeys into one for each row of CD, helps with 48bit conversion
    CD = []
    for i in range(17):
        CD.append(C[i] + D[i])

    # select 48bits out of the 56 bits of the new shifted key
    for i in range(1, 17):
        # create 16 keys, Kn -> Cn Dn
        for j in range(48):
            KEYS_48bit[i-1][j] = CD[i][PC2[j]-1]    # bits begin from position 1 to 56 but arrays from 0 to 55


# circular shift for each key partition for each round
def shift_circ_key_partitions(subkey1, subkey2, shift):

    # keep the highest bits of each partition to achieve rotation
    rot1 = subkey1[0]
    rot2 = subkey2[0]

    # convert subkeys to integers
    key1 = bitarray('0'*28)
    key2 = bitarray('0' * 28)

    for i in range(28):
        key1[i] = subkey1[i]
        key2[i] = subkey2[i]

    # shift the bitarrays and convert them back to bits
    key1 = leftshift(key1, shift)
    key2 = leftshift(key2, shift)

    key1 = bitarray_to_array(key1)
    key2 = bitarray_to_array(key2)

    # complete the circular rotation
    key1[27] = rot2
    key2[27] = rot1

    return key1, key2


def leftshift(bit_array, shift):
    return bit_array[shift:] + (bitarray('0') * shift)


def bitarray_to_array(bit_array):
    array = []

    for bit in bit_array:
        array.append(int(bit))

    return array

# ----------------------------------------------------------------------------------------------------------------------


# AES algorithm (Rijndael) -> 6 times faster than triple DES and more secure than DES
# ----------------------------------------------------------------------------------------------------------------------


# input is in bytes not bits
# plaintext = 128 bits -> 16 bytes
# key = 128 bits -> 16 bytes
# ciphertext = 128 bits -> 16 bytes

# Global Variables for AES


# ROWS and COLUMNS values for S-Box tables
#             00    01    02    03    04    05    06    07    08    09    0a    0b    0c    0d    0e    0f
# 00
# 10
# 20
# 30
# 40
# 50
# 60
# 70
# 80
# 90
# a0
# b0
# c0
# d0
# e0
# f0

# forward S-Box table (for encryption)
SBOX_TABLE = [
              ["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
              ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
              ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
              ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
              ["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],
              ["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],
              ["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],
              ["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],
              ["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],
              ["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],
              ["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],
              ["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],
              ["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],
              ["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],
              ["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],
              ["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]]

# inverse S-Box table (for decryption)
INV_SBOX_TABLE = [
              ["52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"],
              ["7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"],
              ["54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"],
              ["08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"],
              ["72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"],
              ["6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"],
              ["90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"],
              ["d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"],
              ["3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"],
              ["96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"],
              ["47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"],
              ["fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"],
              ["1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"],
              ["60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"],
              ["a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"],
              ["17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"]]


# Rcon Array for key expansion
# 10 rows for 10 keys [x^(i-1), 00, 00, 00] (round1 -> RCON[0])
RCON = [
    ["01", "00", "00", "00"],
    ["02", "00", "00", "00"],
    ["04", "00", "00", "00"],
    ["08", "00", "00", "00"],
    ["10", "00", "00", "00"],
    ["20", "00", "00", "00"],
    ["40", "00", "00", "00"],
    ["80", "00", "00", "00"],
    ["1b", "00", "00", "00"],
    ["36", "00", "00", "00"]]

# 4x4 State Array that changes in each step of each round
STATE_ARRAY = [[None]*4 for i in range(4)]
ROUND_KEYS = [[None]*44 for i in range(4)]    # 4x40 array (we need 44 words/columns, which means 10 4x4 arrays/keys)
# columns 0-3 -> K0, 4-7 -> K1 ...

# need 44 subkeys -> each 32bit/1word/4bytes
# 4 subkeys for each round (128bit/4words/16bytes)


def AES_enc(plaintext, key):

    # print plaintext for DEBUGGING
    print("Plaintext (Initial):")
    for i in range(4):
        for j in range(4):
            print(plaintext[i][j], end="\t")
        print()
    print()

    # 1 expand key

    # copy the given key to the global array
    for i in range(4):
        for j in range(4):
            ROUND_KEYS[i][j] = key[i][j]

    expand_key()

    # 2 Add Round Key (K0)
    plaintext = add_round_key(plaintext, 0)

    # 3 Rounds (K1 - K9)
    for i in range(1, 10):
        # 3.1 Substitute Bytes
        plaintext = substitute_bytes(plaintext)

        # 3.2 Shift Rows
        plaintext = shift_rows(plaintext)

        # 3.3 Mix Columns
        plaintext = mix_columns(plaintext)

        # 3.4 Add Round Key (K1, K2, ...)
        plaintext = add_round_key(plaintext, i)

    # 4 -> Round 10 (no mix columns) (K10)
    plaintext = substitute_bytes(plaintext)
    plaintext = shift_rows(plaintext)
    ciphertext = add_round_key(plaintext, 10)

    print("Ciphertext")
    for i in range(4):
        for j in range(4):
            print(ciphertext[i][j], end="\t")
        print()
    print()

    return ciphertext


# MAIN AES FUNCTIONS

# expands key (4x4 bytes) to 11 keys (4x44 bytes)
def expand_key():

    for i in range(4, 44):
        # 1 RotWord
        word1 = rot_word(i-1)   # rotate the 4th column/word for every ROUND_KEY
        # 2 SubBytes
        word1 = sbox_word(word1)
        # 3 XOR
        array_to_roundkey_column(xor_words(word1, get_roundkey_column(i-4), int(i/4)-1), i)


# takes the plaintext at current round and XORs it with the correct round key
def add_round_key(plaintext, rnd):

    # copy the part of ROUND_KEYS we need for this round
    temp_key = [[None]*4 for i in range(4)]

    idx = 0
    for i in range(4):
        for j in range(rnd*4, rnd*4 + 4):
            temp_key[idx][i] = (ROUND_KEYS[i][j])
            idx += 1
        idx = 0

    return xor_matrices(plaintext, temp_key)


def substitute_bytes(plaintext):
    new_plaintext = [[None]*4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            idx1 = int(plaintext[i][j][0], 16)
            idx2 = int(plaintext[i][j][1], 16)
            new_plaintext[i][j] = SBOX_TABLE[idx1][idx2]

    return new_plaintext


def shift_rows(plaintext):

    new_plaintext = [[None]*4 for i in range(4)]
    new_plaintext[0] = plaintext[0]

    for i in range(1, 4):
        new_plaintext[i] = rotate_row(plaintext[i], i)

    return new_plaintext


def mix_columns(plaintext):

    temp_plaintext = [[None]for i in range(4)]
    hex_plaintext = string_to_hex(plaintext)
    new_plaintext = [[None]*4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            temp_plaintext[j][0] = hex_plaintext[j][i]
        new_plaintext_column = matrix_multiply(temp_plaintext)

        # assign the result column to the new plaintext
        for j in range(4):
                new_plaintext[j][i] = new_plaintext_column[j][0][2:]

        temp_plaintext = [[None] for i in range(4)]

    return new_plaintext


# ADDITIONAL AES FUNCTIONS

# key expansion functions

# rotates the given column by 1
def rot_word(word_ptr):
    # word_ptr is the number of the column to be rotated inside the ROUND_KEYS (ROUND_KEYS[i][word_ptr])

    # create an array that represents the rotated column
    rot1 = ROUND_KEYS[0][word_ptr]
    temp = []
    for i in range(1, 4):
        temp.append(ROUND_KEYS[i][word_ptr])
    temp.append(rot1)

    return temp


# uses sbox table to substitute all elements of the column
def sbox_word(word):

    # idx1 and idx2 are indexes for sbox table

    for i in range(4):
        idx1 = int(word[i][0], 16)
        idx2 = int(word[i][1], 16)
        word[i] = SBOX_TABLE[idx1][idx2]

    return word


# xors the 1st column of the current key with the sboxed column of the same key and then with the right RCON element
def xor_words(sub_word, first_word, rnd):
    # sub_word is the sboxed word and first_word the first word of the current key
    int_sub_word = [None]*4
    temp_rcon = [None]*4
    int_first_word = [None]*4

    xor_array = [None]*4

    # convert hex-strings to integers for XOR
    for i in range(4):
        int_sub_word[i] = int(sub_word[i], 16)
        temp_rcon[i] = int(RCON[rnd][i], 16)
        int_first_word[i] = int(first_word[i], 16)

    for i in range(4):
        xor_array[i] = int_sub_word[i] ^ temp_rcon[i]
        xor_array[i] = xor_array[i] ^ int_first_word[i]
        xor_array[i] = str(hex(xor_array[i]))[2:]   # convert integer array back to hex-string

    return xor_array


def array_to_roundkey_column(array, index):

    check_valid_hex(array)

    for i in range(4):
        ROUND_KEYS[i][index] = array[i]


# returns an array-ROUND_KEY column
def get_roundkey_column(index):

    column = []

    for i in range(4):
        column.append(ROUND_KEYS[i][index])
    return column


# if hex-string has only 1 digit, add a 0 in the beginning
def check_valid_hex(word):
    for j in range(len(word)):
        if len(word[j]) < 2:
            new_hex = "0" + word[j]
            word[j] = new_hex
    return word


def check_valid_byte(value):
    if len(value) < 4:
        new_hex = "0x0" + value[len(value)-1]
        value = new_hex
    return value


# rotates a row/array by the given value (used for ShiftRows phase)
def rotate_row(array, value):

    # hold the values to be placed in the beginning of the array (values that achieve the rotation)
    rotators = array[4-value:]

    # shift the values by the given number
    new_array = array[:4-value]

    # complete the rotation
    new_array = rotators + new_array

    return new_array


def matrix_multiply(array):

    result_column = [[0x00],
                     [0x00],
                     [0x00],
                     [0x00]]

    constant = [[0x02, 0x03, 0x01, 0x01],
                [0x01, 0x02, 0x03, 0x01],
                [0x01, 0x01, 0x02, 0x03],
                [0x03, 0x01, 0x01, 0x02]]

    for i in range(4):
        for j in range(4):
            # array is a single-column 4x1 array for each word of the plaintext
            result_column[i][0] ^= aes_multiply(constant[i][j], array[j][0])
        result_column[i][0] = check_valid_byte(hex(result_column[i][0]))

    return result_column


def aes_multiply(value, num):

    result = 0

    if value == 1:
        result = num
    elif value == 2:
        result = mult_2(num)
    elif value == 3:
        result = mult_3(num)

    return result


# multiplication by 2 for mix columns
def mult_2(num):
    res = shift_8bit(num)
    return res


# there might be a bug here!!!
# multiplication by 3 for mix columns
def mult_3(num):
    res = mult_2(num) ^ num
    return res


# shifts only 8 bit numbers
def shift_8bit(num):
    bin_num = str(bin(num << 1)[2:])

    if len(bin_num) > 8:
        bin_num = bin_num[len(bin_num)-8:]
    elif len(bin_num) < 8:
        bin_num = "0"*(8-len(bin_num)) + bin_num

    bin_num = xor_8bit(bin_num)

    new_num = int(bin_num, 2)

    return new_num


# used only for mult2()
def xor_8bit(num):
    xor_str = ["0", "0", "0", "1", "1", "0", "1", "1"]

    num_array = []

    for i in range(8):
        num_array.append(num[i])

    for i in range(len(num)):
        if num_array[i] == xor_str[i]:
            num_array[i] = "0"
        else:
            num_array[i] = "1"

    return "".join(num_array)


# converts hex-string to hex for the matrix multiplication
def string_to_hex(array):

    hex_array = [[None]*4 for i in range(4)]

    # it's a 4x4 array
    for i in range(4):
        for j in range(4):
            hex_array[i][j] = int("0x" + array[i][j], 16)

    return hex_array


# used only for add_round_key()
def xor_matrices(plaintext, key):

    new_plaintext = [[None]*4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            xor1 = int("0x" + plaintext[j][i], 16)
            xor2 = int("0x" + key[i][j], 16)

            result = xor1 ^ xor2
            result = hex(result)[2:]

            # check for hex-string validation
            if len(result) < 2:
                result = "0" + result

            new_plaintext[j][i] = result
    return new_plaintext


# ----------------------------------------------------------------------------------------------------------------------


# Decryption Algorithms with complexities

# Shift Cipher -> Θ(n)
# ----------------------------------------------------------------------------------------------------------------------
def shift_cipher_dec(encrypted, key):

    plaintext = ""

    for i in range(len(encrypted)):
        plain_char = chr(ord(encrypted[i]) - key)
        plaintext += plain_char

    return plaintext
# ----------------------------------------------------------------------------------------------------------------------


# Vigenere Cipher -> Θ(n)
# ----------------------------------------------------------------------------------------------------------------------

def vigenere_cipher_dec(encrypted, key):

    if len(encrypted) != len(key):
        print("ERROR! Key Length doesn't match message length!")
        return None

    plaintext = ""

    for i in range(len(encrypted)):
        plain_char = chr(ord(encrypted[i]) - ord(key[i]))
        plaintext += plain_char

    return plaintext

# ----------------------------------------------------------------------------------------------------------------------


# One-Time Pad -> Θ(n)
# ----------------------------------------------------------------------------------------------------------------------

def one_time_pad_dec(encrypted, key):

    if len(encrypted) != len(key):
        print("ERROR! Key Length doesn't match message length!")
        return None

    plaintext = ""

    for i in range(len(encrypted)):
        plain_char = chr(ord(encrypted[i]) ^ ord(key[i]))
        plaintext += plain_char

    return plaintext

# ----------------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------------------------


# global variables for DES decryption
PLAIN = [None]*64


# takes cipher and key in bits and prints plaintext in bits (packets only/64bits)
def des_dec(ciphertext, key):

    for i in range(64):
        j = 0
        while j < 64:
            if IP[j] == i+1:
                break
            j += 1
        IPtext[j] = ciphertext[i]

    LPT[0] = IPtext[:32]
    RPT[0] = IPtext[32:]

    create_16_keys(key)

    mode = 1

    for k in range(1, 17):
        cipher(k, mode)

        for i in range(32):
            LPT[k][i] = RPT[k-1][i]

    for i in range(64):
        if i < 32:
            PLAIN[i] = RPT[16][i]
        else:
            PLAIN[i] = LPT[16][i-32]
        final_permutation(i, PLAIN[i])

    plaintext = PLAIN

    return plaintext


# ciphertext (4x4 bytes array) + key (4x4 bytes array) -> 128 bit / 4x4 bytes array plaintext
def AES_dec(ciphertext, key):

    # copy the given key to the global array
    for i in range(4):
        for j in range(4):
            ROUND_KEYS[i][j] = key[i][j]

    expand_key()

    ciphertext = add_round_key(ciphertext, 10)
    ciphertext = shift_rows(ciphertext)
    ciphertext = substitute_bytes(ciphertext)

    for i in range(9, 0, -1):
        ciphertext = add_round_key(ciphertext, i)
        ciphertext = mix_columns(ciphertext)
        ciphertext = shift_rows(ciphertext)
        ciphertext = substitute_bytes(ciphertext)

    plaintext = add_round_key(ciphertext, 0)

    print("Plaintext (Final):")
    for i in range(4):
        for j in range(4):
            print(plaintext[i][j], end="\t")
        print()
    print()


# ----------------------------------------------------------------------------------------------------------------------
