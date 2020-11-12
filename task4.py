from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Hash import Poly1305
from Crypto.Hash import HMAC
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import ChaCha20_Poly1305
import base64
import os
import time
import matplotlib.pyplot as plt
import numpy as np
import json
import hashlib
import argparse

def encrypt(plaintext, mode):
    key = get_random_bytes(32)
    ret = None
    if mode == "AES_CBC":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        start_time = time.time()
        ret = cipher.encrypt(pad(plaintext, AES.block_size))
    elif mode == "AES_OCB":
        cipher = AES.new(key, AES.MODE_OCB)
        start_time = time.time()
        #ret, _ = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
        ret, _ = cipher.encrypt_and_digest(plaintext)
    elif mode == "AES_GCM":
        cipher = AES.new(key, AES.MODE_GCM)
        start_time = time.time()
        ret, _ = cipher.encrypt_and_digest(plaintext)
    elif mode == "AES_CCM":
        cipher = AES.new(key, AES.MODE_CCM)
        start_time = time.time()
        #ret, _ = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
        ret, _ = cipher.encrypt_and_digest(plaintext)
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
        # SHA256 provided by Crypto.Hash is slow.
        # hash_obj = SHA256.new()
        # start_time = time.time()
        # hash_obj.update(plaintext)
        # ret = hash_obj.hexdigest()
        m = hashlib.sha256()
        start_time = time.time()
        m.update(plaintext)
        ret = m.digest()

    elif mode == "CC20":
        cipher = ChaCha20.new(key=key)
        start_time = time.time()
        ret = cipher.encrypt(plaintext)
    elif mode == "POLY":
        mac = Poly1305.new(key=key, cipher=AES)
        start_time = time.time()
        mac.update(plaintext)
        ret = mac.hexdigest()
    elif mode == "CCP":
        cipher = ChaCha20_Poly1305.new(key=key)
        start_time = time.time()
        ret, _ = cipher.encrypt_and_digest(plaintext)
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
        exit(1)

    end_time = time.time()
    cost_time = end_time - start_time
    return ret, cost_time


def create_plaintext(mbytes):
    ret = os.urandom(mbytes*1024*1024+1)
    return ret


def save_result(record):
    plt.title('Running Time of Encryption')
    plt.xlabel('Plaintext size (MB)')
    plt.ylabel('Time (s)')
    for method in record:
        plt.plot(
            np.arange(1, 1+len(record[method])), record[method], label=method)
    plt.legend()
    # plt.show()
    plt.savefig('time.jpg')


def get_argument():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--runs", 
                            help="Run for [runs] runs to average speed.", 
                            default=1,
                            type=int)
    arg_parser.add_argument("--max_file", 
                            help="Maximum file size of plaintext.", 
                            default=30,
                            type=int)
    arg_parser.add_argument("--rsa", 
                            help="Use [--rsa] to run rsa with other methods. CAUTION: THIS WILL BE EXTREMELY SLOW.", 
                            action='store_true')
    args = arg_parser.parse_args()
    return args


if __name__ == "__main__":

    args = get_argument()

    method = []
    if args.rsa:
        method = ['AES_CBC', 'AES_OCB', 'AES_GCM', 'AES_CCM',
                  'SHA', 'CC20', 'POLY', 'CCP', 'HMAC', 'CMAC',
                  'RSA1024', 'RSA2048']
    else:
        method = ['AES_CBC', 'AES_OCB', 'AES_GCM', 'AES_CCM',
                  'SHA', 'CC20', 'POLY', 'CCP', 'HMAC', 'CMAC']

    # use a dictionary to record the result of running time for every method
    # with different length of plaintext
    record = {}
    for m in method:
        record[m] = np.zeros(args.max_file)

    # run different method with different length of plaintext
    for run in range(args.runs):
        for plain_len in range(1, args.max_file+1):
            plaintext = create_plaintext(plain_len)
            for m in method:
                ret, cost_time = encrypt(plaintext, m)
                record[m][plain_len-1] += cost_time
                print("Run: {:2d},".format(run),
                      "Plaintext length: {:2d} MBytes,".format(plain_len),
                      "Encrypt method: {:9s},".format(m),
                      "Cost time: {:5.5f}".format(cost_time))

    # calculate average running time
    for m in method:
        record[m] = record[m]/args.runs 

    # draw the chart
    save_result(record)

    # record to file
    # with open('record.json', 'w') as json_file:
    #     for m in method:
    #         json.dump(record[m].tolist(), json_file)
