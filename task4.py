from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA256
from Crypto.Hash import Poly1305
from Crypto.Hash import HMAC
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import ChaCha20
import base64
import os
import time
import matplotlib.pyplot as plt
import numpy as np
import json


def encrypt(plaintext, mode):
    key = get_random_bytes(16)
    if mode == "AES_CBC":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        start_time = time.time()
        ret = cipher.encrypt(pad(plaintext, AES.block_size))
    elif mode == "AES_OCB":
        cipher = AES.new(key, AES.MODE_OCB)
        start_time = time.time()
        ret, _ = cipher.encrypt_and_digest(plaintext)
        #ret, _ = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
    elif mode == "AES_GCM":
        cipher = AES.new(key, AES.MODE_GCM)
        start_time = time.time()
        ret, _ = cipher.encrypt_and_digest(plaintext)
        #ret, _ = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
    elif mode == "AES_CCM":
        cipher = AES.new(key, AES.MODE_CCM)
        start_time = time.time()
        ret, _ = cipher.encrypt_and_digest(plaintext)
        #ret, _ = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
    elif mode == "RSA1024":
        # generate private key
        key = RSA.generate(1024)
        encrypted_key = key.export_key()
        file_out = open("rsa_key.bin", "wb")
        file_out.write(encrypted_key)
        file_out.close()

        encoded_key = open("rsa_key.bin", "rb").read()
        key = RSA.import_key(encoded_key)

        cipher = PKCS1_OAEP.new(key)
        # max block size of RSA 1024 is 86 Bytes
        blk_size = 86
        start_time = time.time()
        for i in range(0, len(plaintext), blk_size):
            blk_plain = plaintext[i:i+blk_size]
            ret = cipher.encrypt(blk_plain)
    elif mode == "RSA2048":
        # generate private key
        key = RSA.generate(2048)
        encrypted_key = key.export_key()
        file_out = open("rsa_key.bin", "wb")
        file_out.write(encrypted_key)
        file_out.close()

        encoded_key = open("rsa_key.bin", "rb").read()
        key = RSA.import_key(encoded_key)

        cipher = PKCS1_OAEP.new(key)
        # max block size of RSA 1024 is 214 Bytes
        blk_size = 214
        start_time = time.time()
        for i in range(0, len(plaintext), blk_size):
            blk_plain = plaintext[i:i+blk_size]
            ret = cipher.encrypt(blk_plain)
    elif mode == "SHA":
        #hash_obj = SHA3_256.new()
        hash_obj = SHA256.new()
        start_time = time.time()
        hash_obj.update(plaintext)
        ret = hash_obj.hexdigest()
    elif mode == "CC20":
        key = get_random_bytes(32)
        cipher = ChaCha20.new(key=key)
        start_time = time.time()
        ret = cipher.encrypt(plaintext)
    elif mode == "CCP":
        key = get_random_bytes(32)
        mac = Poly1305.new(key=key, cipher=ChaCha20)
        start_time = time.time()
        mac.update(plaintext)
        ret = mac.hexdigest()
    elif mode == "HMAC":
        h = HMAC.new(key, digestmod=SHA256)
        start_time = time.time()
        h.update(plaintext)
        ret = h.hexdigest()
    elif mode == "CMAC":
        cobj = CMAC.new(key, ciphermod=AES)
        start_time = time.time()
        cobj.update(plaintext)
        ret = cobj.hexdigest()
    else:
        print("Mode not supported.")

    end_time = time.time()
    cost_time = end_time - start_time
    return ret, cost_time


def create_plaintext(mbytes):
    ret = os.urandom(mbytes*1024*1024+1)
    return ret


def show_result(record):
    plt.title('Running Time of Encryption')
    plt.xlabel('Plaintext size (MB)')
    plt.ylabel('Time (s)')
    for method in record:
        plt.plot(
            np.arange(1, 1+len(record[method])), record[method], label=method)
    plt.legend()
    plt.savefig('time.jpg')


if __name__ == "__main__":

    # RSA is not included in method list because it's too slow to compare with others.
    # If you still want to try RSA, you can add "RSA1024" and "RSA2048" into method list.
    method = ['AES_CBC', 'AES_OCB', 'AES_GCM', 'AES_CCM',
              'SHA', 'CC20', 'CCP', 'HMAC', 'CMAC']

    # use a dictionary to record the result of running time for every method
    # with different length of plaintext
    record = {}
    for m in method:
        record[m] = []

    # run different method with different length of plaintext
    for plain_len in range(1, 51):
        plaintext = create_plaintext(plain_len)
        for m in method:
            ret, cost_time = encrypt(plaintext, m)
            record[m].append(cost_time)
            print("Plaintext length: {:2d} MBytes,  Encrypt method: {:9s}, Cost time: {:5.5f}".format(
                plain_len, m, cost_time))

    # draw the chart
    show_result(record)

    # record to file
    with open('record.json', 'w') as json_file:
        json.dump(record, json_file)
