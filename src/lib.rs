extern crate hex;
extern crate openssl;

use openssl::sha;

pub trait SHA256Hash {
    fn hash(&self) -> [u8; 32];
}

// add push leaf function
// to support this add is_odd flag
pub struct MerkleTree {
    tree: Vec<[u8; 32]>,
    leafs_count: usize,
}

impl MerkleTree {
    pub fn new(leafs: Vec<[u8; 32]>) -> MerkleTree {
        MerkleTree::generate_merkle_tree(leafs)
    }

    pub fn new_from_data<T: SHA256Hash>(data: &Vec<T>) -> MerkleTree {
        let mut leafs = Vec::new();
        leafs.reserve(data.len());

        for val in data {
            leafs.push(val.hash());
        }
        MerkleTree::generate_merkle_tree(leafs)
    }

    // last element - root value
    pub fn branch(&self, hash: &[u8; 32]) -> Vec<[u8; 32]> {
        let index = self.tree.iter().position(|&x| x == *hash);

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
    pub fn proof(&self, hash: &[u8; 32]) -> Vec<[u8; 32]> {
        //TODO start from leaf position
        let index = self.tree.iter().position(|&x| x == *hash);

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

    fn root_value(&self) -> [u8; 32] {
        if let Some(&value) = self.tree.last() {
            return value.clone();
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
            leafs_count,
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
