from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64

if __name__ == "__main__":

    # 0. define key and iv
    key = get_random_bytes(16)
    iv = key

    # 1. create plaintext P
    P = get_random_bytes(16*3)

    # 2. calculate ciphertext C for P
    e_cipher = AES.new(key, AES.MODE_CBC, iv)
    C = e_cipher.encrypt(P)

    # 3. Mallory modifies c1c2c3 to c1zc1
    z = bytearray(16)
    C_pr = C[0:16]+z+C[0:16]

    # 4. chosen ciphertext attack on C_pr
    d_cipher = AES.new(key, AES.MODE_CBC, iv)
    P_pr = d_cipher.decrypt(C_pr)
    P1_pr = P_pr[0:16]
    P2_pr = P_pr[16:32]
    P3_pr = P_pr[32:48]

    # 5. guess key(iv) by XORing P1_pr and P3_pr
    guess_key = bytes(a ^ b for a, b in zip(P3_pr, P1_pr))

    # 6. verify
    print("Original key: {}".format(base64.b64encode(key).decode('utf-8')))
    print("Guessed key:  {}".format(base64.b64encode(guess_key).decode(
                                    'utf-8')))
    if guess_key == key:
        print("Guessed key is correct.")
    else:
        print("Guessed key is not correct.")
