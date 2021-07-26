# Merkle Tree Implementation with Python

## Explanation

In cryptography and computer science, a hash tree or Merkle tree is a tree in which every leaf node is labelled with the cryptographic hash of a data block, and every non-leaf node is labelled with the cryptographic hash of the labels of its child nodes. Hash trees allow efficient and secure verification of the contents of large data structures. Hash trees are a generalization of hash lists and hash chains.

Demonstrating that a leaf node is a part of a given binary hash tree requires computing a number of hashes proportional to the logarithm of the number of leaf nodes of the tree; this contrasts with hash lists, where the number is proportional to the number of leaf nodes itself. Merkle trees are therefore an efficient example of a cryptographic commitment scheme, in which the root of the Merkle tree is seen as a commitment and leaf nodes may be revealed and proven to be part of the original commitment. (Wikipedia)

## Supported functionality

To run the program:

    python3 merkleTree.py

Then type the function number and the parameters like so:

    <function number> <function parameters>

1. Adding a new leaf to the tree. Parameters: a string.
2. Calculating the root of the tree. Parameters: none.
3. Get proof of inclusion. Parameters: desired leaf number (starting from 0 to the left).
4. Checking proof of inclusion. Parameters: a string representing the leaf's information and a proof of inclusion (like function 3 output).
5. Creating RSA keys (private and public key). Parameters: none.
6. Signing the current tree root. Parameters: RSA private key.
7. Check signature. Parameters: public RSA key, signature, a text to compare to.

### Sparse merkle tree
8. Marking a leaf (turning it to 1). Parameters: leaf digest.
9. Calculating the current tree root. Parameters: none.
10. Creating a proof of inclusion. Parameters: leaf digest.
11. Checking proof of inclusion. Parameters: leaf digest, 0/1 and a proof of inclusion (like function 10 output). 
