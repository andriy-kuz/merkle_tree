#![feature(fixed_size_array)]
#![feature(associated_consts)]
#![deny(missing_docs, missing_debug_implementations, missing_copy_implementations, trivial_casts,
        trivial_numeric_casts, unsafe_code, unstable_features, unused_import_braces,
        unused_qualifications)]
//! MerkleTree data structure implementation
mod crypto;

extern crate core;
extern crate openssl;

use openssl::sha;

pub trait RawData {
    fn get_raw_data(&self) -> Vec<u8>;
}

type Bytes = Vec<u8>;
/// MerkleTree data struc
/// TODO: Maybe add push leaf function (needs is_odd flag)
pub struct MerkleTree {
    // vector of all nodes in tree
    tree: Vec<Bytes>,
    /// number of leaf nodes in the tree
    count: usize,
}

impl MerkleTree {
    pub fn from_vec<T: Into<Bytes>, H: crypto::HashFunction>(data: &Vec<T>) -> MerkleTree {
        let mut leafs = Vec::with_capacity(data.len());
        data.iter().map(|val| leafs.push(H::get_hash(val.into())));
        MerkleTree::generate_merkle_tree(leafs)
    }


    // last element - root value
    pub fn get_branch(&self, leaf: &[u8; 32]) -> Vec<[u8; 32]> {
        let index = self.tree.iter().position(|&x| x == *leaf);

        if let Some(mut index) = index {
            let mut result = Vec::new();

            while index > 0 {
                result.push(self.tree[index].clone());
                index = index / 2 - 1;
            }
            result.push(self.tree[index].clone());
            return result;
        }
        Vec::new()
    }
    // last element of vector on top in tree
    pub fn get_proof(&self, leaf: &[u8; 32]) -> Vec<[u8; 32]> {
        //TODO start from leaf position
        let index = self.tree.iter().position(|&x| x == *leaf);

        if let Some(mut index) = index {
            let mut result = Vec::new();

            while index > 0 {
                let brother = MerkleTree::get_brother(index);
                result.push(self.tree[brother].clone());
                index = MerkleTree::get_father(brother, index);
            }
            return result;
        }

        Vec::new()
    }

    fn root_hash(&self) -> &[u8; 32] {
        if let Some(&value) = self.tree.last() {
            return &value;
        }
        return [0; 32];
    }

    fn generate_merkle_tree(mut leafs: Vec<[u8; 32]>) -> MerkleTree {
        // keep leafs count even
        if leafs.len() % 2 != 0 {
            let leaf = leafs.last().unwrap().clone();
            leafs.push(leaf);
        }
        let leafs_count = leafs.len();
        let nodes_count = 2 * leafs_count - 1;
        let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(nodes_count);
        // in performance view
        nodes.resize(nodes_count - leafs_count, [0; 32]);
        //add leafs hashes
        nodes.append(&mut leafs);
        //create tree
        {
            let mut index = nodes.len() - 1;
            while index > 0 {
                let parent = index / 2 - 1;
                nodes[parent] = get_hash(&nodes[index], &nodes[index - 1]);
                index -= 2;
            }
        }
        MerkleTree {
            tree: nodes,
            count: leafs_count,
        }
    }

    fn get_brother(index: usize) -> usize {
        if index % 2 == 0 {
            return index - 1;
        }
        index + 1
    }
    fn get_father(lh: usize, rh: usize) -> usize {
        let index = lh.max(rh);
        index / 2 - 1
    }
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }
}

fn get_hash(lh: &[u8; 32], rh: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(lh);
    hasher.update(rh);
    hasher.finish()
}

fn verify_proof(root: &[u8; 32], data_hash: [u8; 32], proofs: &Vec<[u8; 32]>) -> bool {
    let mut hash = data_hash;
    for proof in proofs {
        hash = get_hash(&hash, proof);
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
