from web3 import Web3
import brownie
from brownie import VotingContract
import random
from random import randint
from Crypto.Random import get_random_bytes
from tinyec import registry
import tinyec.ec as ec
import hashlib
import time
from eth_abi import encode_single
time.clock = time.time


def custom_hash(values):
    packed_data = b''.join(encode_single('uint256', i) for i in values)
    num = Web3.sha3(packed_data).hex()
    hextonum = int(num, 16)
    return hextonum


def generate_proof(v, C1, C2, k, n, G, y):
    if v == 1:
        j = randint(1, n - 1)
        c0 = randint(1, n - 1)
        f0 = randint(1, n - 1)

        a0 = (G * f0) - (C1 * c0)
        b0 = (y * f0) - (C2 * c0)

        a1 = G * j
        b1 = y * j

        c = custom_hash([C1.x, C1.y, C2.x, C2.y, a0.x, a0.y,
                        a1.x, a1.y, b0.x, b0.y, b1.x, b1.y]) % n
        c1 = (c - c0) % n
        f1 = j + (c1 * k)
        f1 = f1 % n
        return a0, a1, b0, b1, c0, c1, f0, f1
    else:
        j = randint(1, n - 1)
        c1 = randint(1, n - 1)
        f1 = randint(1, n - 1)

        a1 = (G * f1) - (C1 * c1)
        b1 = (y * f1) - (C2 - G) * c1
        a0 = G * j
        b0 = y * j
        c = custom_hash([C1.x, C1.y, C2.x, C2.y, a0.x, a0.y,
                        a1.x, a1.y, b0.x, b0.y, b1.x, b1.y]) % n
        c0 = (c - c1) % n
        f0 = j + c0 * k
        f0 = f0 % n
        return a0, a1, b0, b1, c0, c1, f0, f1


def to_contract_proof(proof):
    a0, a1, b0, b1, c0, c1, f0, f1 = proof
    proof = [
        a0.x, a0.y,  # Flatten point a0
        b0.x, b0.y,  # Flatten point b0
        a1.x, a1.y,  # Flatten point a1
        b1.x, b1.y,  # Flatten point b1
        c0,
        c1,
        f0,
        f1
    ]
    return proof


def encrypt(v, n, y, G):
    k = random.randint(1, n - 1)
    C1 = k * G
    C2 = k * y + G * v

    return C1, C2, to_contract_proof(generate_proof(v, C1, C2, k, n, G, y))


def decrypt(C1, C2, G, x):
    S = x * C1
    M = C2 - S
    i = 0
    while True:
        if i * G == M:
            return i
        i += 1


def genkey(G, n):
    x = int.from_bytes(get_random_bytes(32), "big") % n
    y = x * G
    return x, y


def main():
    accounts = brownie.accounts
    admin = accounts[0]
    voter1 = accounts[1]
    voter2 = accounts[2]
    curve = registry.get_curve("secp256r1")
    n = curve.field.n
    G = curve.g
    x, y = genkey(G, n)

    contract = VotingContract.deploy(y.x, y.y, {"from": admin})

    vote1 = 0
    stake1 = 100

    vote2 = 1
    stake2 = 400

    (vote1_c1, vote1_c2, proof1) = encrypt(vote1, n, y, G)
    (vote2_c1, vote2_c2, proof2) = encrypt(vote2, n, y, G)

    vote1_c1_x_hex = int(vote1_c1.x)
    vote1_c1_y_hex = int(vote1_c1.y)
    vote1_c2_x_hex = int(vote1_c2.x)
    vote1_c2_y_hex = int(vote1_c2.y)
    vote2_c1_x_hex = int(vote2_c1.x)
    vote2_c1_y_hex = int(vote2_c1.y)
    vote2_c2_x_hex = int(vote2_c2.x)
    vote2_c2_y_hex = int(vote2_c2.y)

    print("Casting vote:")
    contract.castVote(vote1_c1_x_hex, vote1_c1_y_hex, vote1_c2_x_hex,
                      vote1_c2_y_hex, proof1, stake1, {"from": voter1})
    contract.castVote(vote2_c1_x_hex, vote2_c1_y_hex, vote2_c2_x_hex,
                      vote2_c2_y_hex, proof2, stake2, {"from": voter2})

    (c1x, c1y), (c2x, c2y), _ = contract.encryptedSum()

    print("The encrypted sum is: ", c1x, c1y, c2x, c2y)
    c1 = ec.Point(curve, c1x, c1y)
    c2 = ec.Point(curve, c2x, c2y)

    cleartext = decrypt(c1, c2, G, x)
    print("The cleartext is: ", cleartext)
