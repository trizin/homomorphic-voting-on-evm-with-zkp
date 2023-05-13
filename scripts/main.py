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

# Accounts
accounts = brownie.accounts
admin = accounts[0]
voter1 = accounts[1]
voter2 = accounts[2]

# Curve parameters
curve = registry.get_curve("secp256r1")
n = curve.field.n
G = curve.g


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
    return C1, C2, k


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


def deploy_voting_contract():
    x, y = genkey(G, n)
    contract = VotingContract.deploy(y.x, y.y, {"from": admin})
    return x, y, contract


def cast_vote(voter, vote, contract, stake):
    (yx, yy) = contract.Y()
    y = ec.Point(curve, yx, yy)

    C1, C2, k = encrypt(vote, n, y, G)

    # generate a zkp to prove that the vote is either 1 or 0.
    proof = generate_proof(vote, C1, C2, k, n, G, y)
    proof_flat = to_contract_proof(proof)

    C1_x = int(C1.x)
    C1_y = int(C1.y)
    C2_x = int(C2.x)
    C2_y = int(C2.y)

    contract.castVote(C1_x, C1_y, C2_x, C2_y,
                      proof_flat, stake, {"from": voter})

    print(f"Voter {voter.address} casted their vote.")


def decrypt_weighted_sum(contract, x):
    C1, C2 = get_encrypted_sum(contract)
    return decrypt(C1, C2, G, x)


def get_encrypted_sum(contract):
    # Read the encrpyted sum from the contract
    (c1x, c1y), (c2x, c2y), _ = contract.encryptedSum()
    print("The encrypted sum is: ", c1x, c1y, c2x, c2y)
    C1 = ec.Point(curve, c1x, c1y)
    C2 = ec.Point(curve, c2x, c2y)
    return C1, C2


def main():
    x, y, contract = deploy_voting_contract()
    print(
        f"Generated keypair and deployed contract on address {contract.address}")

    vote1 = 0
    stake1 = 100

    vote2 = 1
    stake2 = 400

    vote3 = randint(0, 1)
    stake3 = randint(10, 300)

    print("Casting votes:")
    cast_vote(voter1, vote1, contract, stake1)
    cast_vote(voter2, vote2, contract, stake2)
    cast_vote(admin, vote3, contract, stake3)

    stake_weighted_sum = decrypt_weighted_sum(contract, x)
    print("The decrypted sum is: ", stake_weighted_sum)

    total_staked = contract.stakes()
    print("Total staked: ", total_staked)

    print("The result is: ", stake_weighted_sum / total_staked)
