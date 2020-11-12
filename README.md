# Information Security HW 1
This repository is the assignment 1 for Department of Information Management and Finance, NCTU.

[Report](https://hackmd.io/@qAuHy4xqSx6CEV6YVNaGPw/Syq_hxtYD)
[Instruction](https://hackmd.io/@qAuHy4xqSx6CEV6YVNaGPw/Bk8BbhqKD)

## Introduction
This assignment includes two major parts. 
+ Part 1: task 1~4 is to implement 11 kinds of encryption algorithm and compare the speed of them.
+ Part 2: task 5 is to explain why key as IV of AES-CBC is bad.

## Part 1
`task4.py` includes 11 kinds of encryption algorithms and mode of operations. 

To reproduce the result shown in the report, just simply run `$ pyhon3 task4.py`.

Please notice that RSA is not included in the default methods list because it's too slow to compare with other methods. If you want to run RSA, just add it to the method list in the `main` function.

## Part 2
`task5.py` shows that using key as IV in AES-CBC is not secure under chosen ciphertext attack.

Use `$ python3 task5.py` to run the code. It'll show the key guessed by man in the middle is the same as the original key.

Please take a look at the comments in the code for more explaination.
