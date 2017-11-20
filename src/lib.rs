use std::collections::LinkedList;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct MerkleTree<T: Hash> {
    nodes: Vec<[u8; 64]>,
    data: Vec<T>,
}

//add function verify_proof

impl<T: Hash> MerkleTree<T> {
    pub fn new(data: Vec<T>) -> MerkleTree<T> {
        MerkleTree::generate_merkle_tree(data)
    }

    pub fn branch(&mut self, data: &T) {} // return vector of hashes
    pub fn proof(&mut self, data: &T) {} // return vector of hashes

    fn generate_merkle_tree(data: Vec<T>) -> MerkleTree<T> {
        MerkleTree {
            nodes: Vec::new(),
            data,
        }
    }

    // add push leaf function
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
