# verify_coin.py
# Has additional tweaks to enforce proper formatting of coins 
# (e.g., all 4 blocks are unique).
# Usage: python3 verify_coin.py af535 example_coin_for_af535.txt

import hashlib
import sys

usage = "python3 verify_coin.py <netid> <path to coin.txt>"

if len(sys.argv) != 3:
    print("Specify netid and coin.txt as arguments")
    print(usage)
    sys.exit(2)

n = 28
k = 4
c_l = 16
netid = sys.argv[1].encode('ascii')

def hash_to_bin(s):
    return bin(int(hashlib.sha256(s).hexdigest(), base=16)).lstrip('0b').zfill(256)


def verify_1a(filename):
    w = hash_to_bin(netid)[:16]
    W = True
    V = True
    L = []
    num_violations = 0
    with open(filename) as f:
        for line in f:
            c_i = line
            if line[-1] == '\n':
                c_i = line[:-1] # Omitting new line character
            if c_i[:2] == "0x": # Omit "0x at the start" if present
                c_i = c_i[2:]
            print(c_i, len(c_i))
            if len(c_i) != 16:
                V = False
            if (bin(int(c_i, 16))[2:].zfill(64)[:16]) != w:
                W = False
            L.append(bytes.fromhex(c_i))
    d = hash_to_bin(L[0])[:n]
    for x in L:
        print(hash_to_bin(x)[:n])
        if d != (hash_to_bin(x)[:n]):
            num_violations = num_violations + 1
    if len(L) != 4 or len(set(L)) != 4:
        V = False
    print("Is coin valid?", V)
    print("Is watermark correct?", W)
    print("Do all blocks hash properly?", num_violations == 0)

verify_1a(sys.argv[2])
