from cihpers import *
import time


# ALL FUNCTIONS RETURN: ciphertext,key,time_elapsed (AES,DES decryptions are not included since they might be buggy)


def benchmark_shift(plaintext):

    start = time.time()

    ciphertext, key = shift_cipher_enc(plaintext)

    end = time.time()
    time_elapsed = end - start

    print("CipherText: ", end="\t")
    print(ciphertext)
    print("Key: ", end="\t\t\t")
    print(key)
    print("time elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed


def benchmark_vigenere(plaintext):

    start = time.time()

    key = generate_random_key(plaintext)
    ciphertext = vigenere_cipher_enc(plaintext, key)

    end = time.time()
    time_elapsed = end - start

    print("Ciphertext: ", end="\t")
    print(ciphertext)
    print("Key: ", end="\t\t\t")
    print(key)
    print("time elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed


def benchmark_onetime_pad(plaintext):

    start = time.time()

    key = generate_random_key(plaintext)
    ciphertext = one_time_pad_enc(plaintext, key)

    end = time.time()
    time_elapsed = end - start

    print("Ciphertext: ", end="\t")
    print(ciphertext)
    print("Key: ", end="\t\t\t")
    print(key)
    print("time elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed


def benchmark_des_text(plaintext):

    start = time.time()

    ciphertext, key = des_string_encryption(plaintext)

    end = time.time()
    time_elapsed = end - start

    if ciphertext is not None:
        print("Ciphertext: ", end="")
        for i in range(len(ciphertext)):
	        for bit in ciphertext[i]:
	            print(bit, end="")
    else:
        print("Text must be length that can be divided by 8 for DES algorithm!")
        exit(1)

    print()
    print("Key: ", end="\t\t")
    for k in key:
        print(k, end="")
    print("\ntime elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed


# DES AND AES ARE USED FOR BITS AND BYTES ONLY
def benchmark_des_packet(plaintext):

    start = time.time()

    key = generate_56bit_key()
    ciphertext = des_packet_encryption(plaintext, key)  # array of bits

    end = time.time()
    time_elapsed = end - start

    print("time elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed


def benchmark_aes(plaintext):

    start = time.time()

    key = generate_random_AES_key()
    ciphertext = AES_enc(plaintext, key)  # array of bits

    end = time.time()
    time_elapsed = end - start

    print("time elapsed: ", end="")
    print(time_elapsed)

    return ciphertext, key, time_elapsed
