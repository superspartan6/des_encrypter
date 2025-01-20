"""
DES Encryption Project
Author: Caleb Zierenberg
Date: 11/27/2024

This module implements the DES encryption algorithm, which takes a 64-bit hexadecimal message and key 
and returns the encrypted message in hexadecimal format.
"""

import math

# DES Standard Permutation Tables
PC1 = [[57, 49, 41, 33, 25, 17, 9],
       [1, 58, 50, 42, 34, 26, 18],
       [10, 2, 59, 51, 43, 35, 27],
       [19, 11, 3, 60, 52, 44, 36],
       [63, 55, 47, 39, 31, 23, 15],
       [7, 62, 54, 46, 38, 30, 22],
       [14, 6, 61, 53, 45, 37, 29],
       [21, 13, 5, 28, 20, 12, 4]]

PC2 = [[14, 17, 11, 24, 1, 5],
       [3, 28, 15, 6, 21, 10],
       [23, 19, 12, 4, 26, 8],
       [16, 7, 27, 20, 13, 2],
       [41, 52, 31, 37, 47, 55],
       [30, 40, 51, 45, 33, 48],
       [44, 49, 39, 56, 34, 53],
       [46, 42, 50, 36, 29, 32]]

# Initial Permutation
IP_TABLE = [[58, 50, 42, 34, 26, 18, 10, 2],
      [60, 52, 44, 36, 28, 20, 12, 4],
      [62, 54, 46, 38, 30, 22, 14, 6],
      [64, 56, 48, 40, 32, 24, 16, 8],
      [57, 49, 41, 33, 25, 17, 9, 1],
      [59, 51, 43, 35, 27, 19, 11, 3],
      [61, 53, 45, 37, 29, 21, 13, 5],
      [63, 55, 47, 39, 31, 23, 15, 7]]

# Final Permutation (IP-)
FP_TABLE = [[40, 8, 48, 16, 56, 24, 64, 32],
      [39, 7, 47, 15, 55, 23, 63, 31],
      [38, 6, 46, 14, 54, 22, 62, 30],
      [37, 5, 45, 13, 53, 21, 61, 29],
      [36, 4, 44, 12, 52, 20, 60, 28],
      [35, 3, 43, 11, 51, 19, 59, 27],
      [34, 2, 42, 10, 50, 18, 58, 26],
      [33, 1, 41, 9, 49, 17, 57, 25]]

# Expansion Permutation
EXPANSION_TABLE = [[32, 1, 2, 3, 4, 5],
      [4, 5, 6, 7, 8, 9],
      [8, 9, 10, 11, 12, 13],
      [12, 13, 14, 15, 16, 17],
      [16, 17, 18, 19, 20, 21],
      [20, 21, 22, 23, 24, 25],
      [24, 25, 26, 27, 28, 29],
      [28, 29, 30, 31, 32, 1]]


PERMUTATION_TABLE = [[16, 7, 20, 21],
      [29, 12, 28, 17],
      [1, 15, 23, 26],
      [5, 18, 31, 10],
      [2, 8, 24, 14],
      [32, 27, 3, 9],
      [19, 13, 30, 6],
      [22, 11, 4, 25]]



S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]


def permutation(input_bitstream: str, table: list) -> str:
    output = ""
    for row in table:
        for i in row:
            output += input_bitstream[i-1]
    return output

def to_binary(value, fill: int) -> str:
    if isinstance(value, str):
        return bin(int(value, 16))[2:].zfill(fill)
    elif isinstance(value, int):
        return bin(value)[2:].zfill(fill)
    else:
        raise ValueError(f"Unsupported type for to_binary: {type(value)}")

def key_schedule(block: str, iteration: int) -> str:
    shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    shift_num = shift[iteration]
    return block[shift_num:] + block[:shift_num]

def XOR(val1: str, val2: str, fill: int) -> str:
    result = bin(int(val1,2) ^ int(val2, 2))[2:].zfill(fill)
    return result.zfill(fill)


# Function f
def f_function(r_block: str, subkey: str) -> str:
    expansion_block = permutation(r_block, EXPANSION_TABLE)
    xor_result = XOR(subkey, expansion_block, 48)

    s_box_output = ""

    for i in range(8):
        block = xor_result[i*6:i*6+6]
        
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)

        s_box_value = S_BOXES[i][row][col]
        s_box_output += to_binary(int(s_box_value), 4)

    return permutation(s_box_output, PERMUTATION_TABLE)


def des_encrypt(message, key):
    message_bin = to_binary(message, 64)
    key_bin = to_binary(key, 64)
    key_bin = permutation(key_bin, PC1)

    keys = []
    C = [key_bin[:28]]
    D = [key_bin[28:]]

    # Generate 16 subkeys
    for i in range(16):
        C.append(key_schedule(C[i], i))
        D.append(key_schedule(D[i], i))
    for i in range(16):
        keys.append(permutation(C[i+1] + D[i+1], PC2))

    ip_result = permutation(message_bin, IP_TABLE)
    L = [ip_result[:32]]
    R = [ip_result[32:]]

    # 16 rounds of processing
    for i in range(16):
        L.append(R[i])
        R.append(XOR(L[i], f_function(R[i], keys[i]), 32))

    # Combine final output: swap L and R in final round
    combined = R[16] + L[16]
    encrypted = permutation(combined, FP_TABLE)
    encrypted_hex = hex(int(encrypted, 2))[2:].upper().zfill(16)

    return encrypted_hex


def main():
    message = "0123456789ABCDEF"
    key = "133457799BBCDFF1"
    encrypted = des_encrypt(message, key)
    print("Encrypted message:", encrypted)



if __name__ == "__main__":
    main()