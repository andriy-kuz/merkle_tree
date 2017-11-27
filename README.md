# MerkleTree

Merkle Tree data structure in Rust.
## Interface details
Inspired by "Mastering Bitcoin: merkle tree": implementation does not
own data and does not has reference to it.
MerkleTree::from_vec builds Merkle tree. Function accept reference to data of
any type which implements ByteEncodable trait - converting to Vec<u8> dump. Also
has generic parameter for hash algorithm type wich implement HashFunction trait.
This gives flexibility for clients - build merkle tree from any data type using
own hash function algorithm. Library has default HashFunction implementations for
openssl sha algorithms: Sha1, Sha224, Sha256, Sha384, Sha512.(using double hashing).

MerkleTree::get_proof function return vector of proof Nodes for given hash-leaf.
Nodes has hash and flag. Flag show is this is left or right node -
this important in order concatenation of hashes for hash function.
Client could check validity of root and leaf hashing proof result by his own -
just take into account order of nodes when concatenate.

Crate has verify_proof function which accept root hash, leaf, proof vector
and validate leaf according to root value.

Other MerkleTree functions described in source code documentation.

## Implementation details
MerkleTree represent binary tree like vector of hashes.
First element of vector - root of the tree. On my mind this is simple
and fast representation of binary tree for MerkleTree data structure. Because MerkleTree does
not need self balancing (this is not sorted binary search tree) and API does not
have add_leaf functionality(referenced to Mastering Bitcoin : MerkleTree used
for creating fingerprint (merkle root) of data and its verification - add_leaf useless),
which will be slove in this variant of implementation (neads to recalculate whole tree,
or go in a way - Node have pointer to parent and childs).

Also there could be another desing for MerkleTree, more data oriented:
it will hold also data (not only hashes), implements iterating thow data elements or/and hashes of tree
and add, remove and access data elements by index, hash and so one. I decided to design
it closer for it cryptographic and verifying functionality.

## Using example
Using example in testing section