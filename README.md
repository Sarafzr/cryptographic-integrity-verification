# Cryptographic Forgery & Integrity Verification

This project explores **cryptographic integrity, forgery detection, and authentication** through practical implementations of hashing, Merkle trees, and digital signatures. It demonstrates how cryptographic primitives can be used to **detect tampering and prevent forgery**, and how insecure verification logic can be exploited.

The repository is organized into small, focused modules, each highlighting a different integrity or authentication mechanism.

## Project Structure

```
.
├── hash_signatures/
│   ├── signature.py     # Digital signature generation and verification
│   ├── forgery.txt      # Example of forged content
│   └── test.py
├── merkle_tree/
│   ├── merkle.py        # Merkle tree construction and root verification
│   └── test.py          # Tests for tamper detection
├── watermark/
│   ├── generate.py      # Generates a hash-based watermark
│   ├── verify_coin.py   # Verifies integrity of a signed object
│   ├── coin.txt         # Authenticated object
│   └── forged-watermark.txt
└── README.md
```

## Components

### Merkle Tree Integrity
The `merkle_tree` module constructs a Merkle tree over data blocks and computes a root hash that commits to the entire dataset. Any modification to the underlying data produces a different root hash, making tampering detectable.

This approach enables efficient integrity verification without reprocessing all data.

### Digital Signatures
The `hash_signatures` module demonstrates how digital signatures provide:
- Authenticity
- Integrity
- Non-repudiation

Forgery examples show how modified data fails verification without the correct cryptographic proof.

### Watermark Verification
The `watermark` module illustrates how hash-based watermarking can be used to authenticate objects, and how poorly designed schemes can be forged if verification is not cryptographically sound.

## Running the Code

**Requirements**
- Python 3.8+
- No external dependencies

**Example**
```bash
python merkle_tree/test.py
python hash_signatures/test.py
python watermark/generate.py
python watermark/verify_coin.py
```

Each script outputs whether the data passes or fails integrity and authenticity checks.

## Key Takeaways

- Hashing alone is insufficient for authentication
- Verification logic must be designed adversarially
- Merkle trees enable scalable integrity checks
- Digital signatures are critical for preventing forgery
- Security failures often stem from incorrect assumptions, not broken algorithms


