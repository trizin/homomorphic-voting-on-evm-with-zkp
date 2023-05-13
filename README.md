# Homomorphic Voting on any EVM Chain

I've embarked on an exciting journey to illuminate the path for secure democracy in the blockchain world. Herein, you'll discover a demonstration of homomorphic voting on any Ethereum Virtual Machine (EVM) compatible blockchain. The secret to the security? It's a fascinating fusion of **Elliptic Curve Cryptography (ECC)** and the **ElGamal encryption scheme**.

Yet, the quest didn't end there. To validate each vote, I've integrated the **Disjunctive Chaum-Pedersen Zero-Knowledge Proof (ZKP)**. This mechanism allows for the verification of each vote, without revealing its substance, preserving the sanctity of individual choice.

As you traverse the code, remember - it's a demonstration, a prototype, a spark of what's possible. But, like any spark, it needs a forge. If you decide to shape this into a real-world application, please do so with care. Modify, enhance, and most importantly, implement rigorous security checks.

## Getting Started

Clone the repository and install the dependencies:

```shell
git clone https://github.com/trizin/homomorphic-on-chain-voting.git
pip install eth-brownie tinyec pycrypto
```

To experience the magic, simply execute the command:

```shell
brownie run scripts/main.py
```

The script executes a series of steps where participants' votes are encrypted, proofs are generated, and votes are submitted alongside stake amounts. The entire vote count is designed to be weighted based on these stake amounts. As each vote is cast, the homomorphically encrypted value within the smart contract is dynamically updated.

The script further showcases how to extract the encrypted stake-weighted sum and decrypt it, thus unveiling the final results of the voting process.
