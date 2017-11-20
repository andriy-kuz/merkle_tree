extern crate hex;
extern crate openssl;

use openssl::sha;
// Also could be used std::hash trait
pub trait SHA256Hash {
    fn hash(&self) -> [u8; 32];
}

pub struct MerkleTree<T: SHA256Hash> {
    nodes: Vec<[u8; 32]>,
    data: Vec<T>,
}

//add function verify_proof

impl<T: SHA256Hash> MerkleTree<T> {
    pub fn new(data: Vec<T>) -> MerkleTree<T> {
        MerkleTree::generate_merkle_tree(data)
    }

    // last element - root value
    pub fn branch(&self, data: &T) -> Vec<[u8; 32]> {
        let hash = data.hash();
        let index = self.nodes.iter().position(|&x| x == hash);

        if let Some(mut index) = index {
            let mut result = Vec::new();

            while index > 0 {
                result.push(self.nodes[index].clone());
                index = index / 2 - 1;
            }
            result.push(self.nodes[index].clone());
            return result;
        }
        Vec::new()
    }
    // last element of vector on top in tree
    pub fn proof(&self, data: &T) -> Vec<[u8; 32]> {
        let hash = data.hash();
        let index = self.nodes.iter().position(|&x| x == hash);

        if let Some(mut index) = index {
            let mut result = Vec::new();

            while index > 0 {
                let brother = MerkleTree::<T>::get_brother(index);
                result.push(self.nodes[brother].clone());
                index = MerkleTree::<T>::get_father(brother, index);
            }
            return result;
        }

        Vec::new()
    }

    fn generate_merkle_tree(data: Vec<T>) -> MerkleTree<T> {
        let nodes_count = 2 * data.len() - 1;
        let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(nodes_count);
        nodes.resize(nodes_count, [0; 32]);
        //add leafs hashes
        {
            let mut index = nodes_count - data.len();

            for value in &data {
                nodes[index] = value.hash();
                index += 1;
            }
        }
        //create tree
        {
            let mut index = nodes.len() - 1;
            while index > 0 {
                let parent = index / 2 - 1;
                nodes[parent] = get_hash(&nodes[index], &nodes[index - 1]);
                index -= 2;
            }
        }

        MerkleTree { nodes, data }
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
    // add push leaf function
}

fn get_hash(lh: &[u8; 32], rh: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(lh);
    hasher.update(rh);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
