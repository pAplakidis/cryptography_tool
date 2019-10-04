from benchmarks import *

# for des encryption print an example for the input (generate_random_8bytes())


def main():
    print("1. Encrypt")
    print("2. Decrypt")
    choice = int(input("Choose: "))

    if choice == 1:
        print("1> Text encryption")
        print("2> Packet encryption")
        choice1 = int(input("Choose: "))

        if choice1 == 1:
            plaintext = str(input("Enter the text you want to encrypt: "))

            print("1) Shift Cipher")
            print("2) Vigenere Cipher")
            print("3) One-Time Pad")
            print("4) DES (make sure the text's bit size can be divided by 64, 8/16/24/32/... chars in string)")
            enc_algorithm = int(input("Choose: "))

            if enc_algorithm == 1:
                benchmark_shift(plaintext)
            elif enc_algorithm == 2:
                benchmark_vigenere(plaintext)
            elif enc_algorithm == 3:
                benchmark_onetime_pad(plaintext)
            elif enc_algorithm == 4:
                benchmark_des_text(plaintext)
            else:
                print("Invalid Option")
                exit(1)

        elif choice1 == 2:

            print("1) DES (64 bits plaintext, 56 bits key)")
            print("2) AES (16 bytes plaintext, 16 bytes key)")
            enc_algorithm = int(input("Choose: "))

            if enc_algorithm == 1:

                plaintext = []

                str_plaintext = str(input("Enter a plaintext string of 64 bits (example: 0110011110101010111100...): "))

                for char in str_plaintext:
                    plaintext.append(int(char))

                key = []

                str_key = str(input("Enter a key string of 56 bits (example: 0110011110101010111100...): "))

                for char in str_key:
                    key.append(int(char))

                des_packet_encryption(plaintext, key)

            elif enc_algorithm == 2:
                plaintext = []

                for i in range(4):
                    row = []
                    for j in range(4):
                        byte = ""
                        byte += str(input("Give Byte (example 3f) for plaintext[%d][%d]" % (i, j)))
                        row.append(byte)
                    plaintext.append(row)

                key = []

                for i in range(4):
                    row = []
                    for j in range(4):
                        byte = ""
                        byte += str(input("Give Byte (example 3f) for key[%d][%d]" % (i, j)))
                        row.append(byte)
                    key.append(row)

                AES_enc(plaintext, key)
            else:
                print("Invalid Option")
                exit(1)

        else:
            print("Invalid Option")
            exit(1)

    elif choice == 2:
        print("Text decryption only")

        ciphertext = str(input("Enter the text you want to decrypt: "))
        key = str(input("Enter your key: "))

        print("1) Shift Cipher")
        print("2) Vigenere Cipher")
        print("3) One-Time Pad")
        dec_algorithm = int(input("Choose: "))

        if dec_algorithm == 1:
            shift_cipher_dec(shift_cipher_enc(ciphertext), key)
        elif dec_algorithm == 2:
            vigenere_cipher_dec(ciphertext, key)
        elif dec_algorithm == 3:
            one_time_pad_dec(ciphertext, key)
        else:
            print("Invalid Option")
            exit(1)

    else:
        print("Invalid Option!")
        exit(1)


if __name__ == "__main__":
    main()
