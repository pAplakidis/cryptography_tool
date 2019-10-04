# Python Cryptography Tool

This is an application/library that uses various encryption and decryption algorithmsto either encrypt a plaintext or bits/bytes message or decrypt a cipher message. It also includes benchmarks for all the algorithms used in the application.

# Usage
Just run app.py

## Note
Some algorithms for decryption are not used in the application due to potential bugs, however they can be used by other python scripts. You can find them in ciphers.py

## Author
- Pavlos Aplakkdis: Computer Science Stutdent

## Licence
[MIT license](https://choosealicense.com/licenses/mit/ "learn about this license")

### Prerequisites
- Python3
- random, string, bitarray, bitstring and time libraries

## How the project works

This porject was mostly made to implement and acess various cryptographic algorithms that have been used over the years.
It's purpose is to mostly work as a library, however it comes with a console app that applies some algorithms (some might be buggy so the have not been used in the app.py file).

## Functions Documentation

## How the algorithms work

### Shift Cipher

This is most likely the simpliest ecnryption algorithm. All it does is take an integer key and add it to the ascii value of each character in the plaintext
To decrypt it just subtract the key from the ascii values of each character in the ciphertext

#### Functions related to this cipher

-ciphers.py:
shift_cipher_enc(plaintext)
shift_cipher_dec(ciphertext)

-benchmarks.py:
benchmark_shift(plaintext)

### Vigenere Cipher

This chipher needs a plaintext and a key of equal length. Like the shift cipher, it shifts each character, however by the value of each key's character ascii value instead of an integer. Every character's ascii value in the plaintext is added with it's key ascii value counterpart.

#### Functions related to this cipher

-ciphers.py:
generate_random_key(plaintext)
vigenere_cipher_enc(plaintext)
vigenere_cipher_dec(ciphertext)

-benchmarks.py:
benchmark_vigenere(plaintext)

### One-Time Pad

This algorithm takes a plaintext and a key of equal length and it XORs each char of the plaintext with it's key.

#### Functions related to this cipher

-ciphers.py:
generate_random_key(plaintext)
one_time_pad_enc(plaintext, key)
one_time_pad_dec(ciphertext, key)

### Data Encryption Standard (DES)

[How This Algorithm Works](http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm "The DES Algorithm Illustrated")

#### Funcitons related to this cipher

des_string_encryption(plaintext)
generate_56bit_key()
des_packet_encryption(plaintext, key)
des_enc(plaintext, key)

- Additional DES functions
final_permutation(pos, data)
cipher(Round, mode)
XOR(a, b)
PBox(pos, data)
SBox(xortext)
SBoxes(box_num, box)
binary_to_decimal_2(bit_array)
binary_to_decimal_4(bit_array)
decimal_to_bin_array(num)
F1(i)
ToBits(value)
expansion(pos, data)
create_16_keys(key)
shift_circ_key_partitions(subkey1, subkey2, shift)
leftshift(bit_array, shift)
bitarray_to_array(bit_array)

### Advanced Encryption Standard (AES) / Rijndael Algorithm

[How This Algorithm Works (Video)](https://www.youtube.com/watch?v=gP4PqVGudtg "AES Rijndael Cipher explained as a Flash animation")
[How This Algorithm Works (Article)](https://www.commonlounge.com/discussion/e32fdd267aaa4240a4464723bc74d0a5 "The Advanced Encryption Standard (AES) Algorithm")

#### Functions related to this cipher

generate_random_AES_key()
AES_enc(plaintext, key)
expand_key()
roundd_key(plaintext, rnd)
substitute_bytes(plaintext)
shift_rows(plaintext)
mix_columns(plaintext)

- Additional AES functions:
rot_word(word_ptr)
sbox_word(word)
xor_words(sub_word, first_word, rnd)
array_to_roundkey_column(array, index)
get_roundkey_column(index)
check_valid_hex(word)
check_valid_byte(value)
rotate_row(array, value)
matrix_multiply(array)
aes_multiply(value, num)
mult_2(num)
mult_3(num)
shift_8bit(num)
xor_8bit(num)
string_to_hex(array)
xor_matrices(plaintext, key)

## TODO
- imporove the app.py so that it is more usable
- debug encryption and decryption algorithms since some of them (DES and AES) may not work well
- maybe make a GUI version of app.py (the goal of this project is mostly to benchmark the perfomance of the various encryption algorithms)
