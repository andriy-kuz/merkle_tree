#![deny(missing_docs, missing_debug_implementations, missing_copy_implementations, trivial_casts,
        trivial_numeric_casts, unsafe_code, unstable_features, unused_import_braces,
        unused_qualifications)]
//! MerkleTree data structure implementation
pub mod crypto;
use crypto::*;

extern crate bytevec;
use bytevec::ByteEncodable;
/// Tree node holds hash and node type
#[derive(Debug, Clone)]
pub struct Node {
    #[allow(missing_docs)]
    pub _hash: HashValue,
    /// Indicates left node if true, right if false.
    pub _left: bool,
}
/// MerkleTree data structure
#[derive(Debug)]
pub struct MerkleTree {
    // Binary tree represented by vector
    _tree: Vec<Node>,
    /// Count of leaf nodes in the tree
    _count: usize,
}

impl MerkleTree {
    /// Construct new Merkle Tree from vector of data.
    ///
    /// Data type <T> must support ByteEncodable trait
    /// Function generic specification <H> must implement crypto::HashFunction trait
    /// Note: Present crypto::HashFunction trait implementationfor openssl::sha::* algorithms
    ///
    pub fn from_vec<H: HashFunction, T: ByteEncodable>(data: &Vec<T>) -> MerkleTree {
        let mut leafs = Vec::with_capacity(data.len());

        for val in data {
            let buf = val.encode::<u32>().unwrap();
            leafs.push(H::get_hash(buf))
        }
        MerkleTree::generate_merkle_tree::<H>(leafs)
    }


    /// Return leaf's branch of hashes
    /// Last HashValue in result vector will be tree root
    pub fn get_branch(&self, leaf: &HashValue) -> Vec<Node> {
        let mut index = self._tree.iter().skip(self._tree.len() - self._count);
        let index = index.position(|x| x._hash == *leaf);

        if let Some(mut index) = index {
            // align index
            index += self._tree.len() - self._count;
            let mut result = Vec::new();

            while index > 0 {
                result.push(self._tree[index].clone());
                index = index / 2 - 1;
            }
            result.push(self._tree[index].clone());
            return result;
        }
        Vec::new()
    }
    /// Return leaf's check vector of hashes
    /// First HashValue of result vector - bottom of tree (leaf's brother)
    pub fn get_proof(&self, leaf: &HashValue) -> Vec<Node> {
        let mut index = self._tree.iter().skip(self._tree.len() - self._count);
        let index = index.position(|x| x._hash == *leaf);

        if let Some(mut index) = index {
            // align index
            index += self._tree.len() - self._count;
            let mut result = Vec::new();

            while index > 0 {
                let brother = MerkleTree::get_brother(index);
                result.push(self._tree[brother].clone());
                index = MerkleTree::get_father(brother, index);
            }
            return result;
        }
        Vec::new()
    }
    /// Return merkle's tree root hash value
    pub fn root(&self) -> Option<&Node> {
        return self._tree.first();
    }
    /// Return elements count tree
    pub fn len(&self) -> usize {
        self._tree.len()
    }
    /// Return leafs count in tree
    pub fn leafs(&self) -> usize {
        self._count
    }

    fn generate_merkle_tree<H: HashFunction>(leafs: Vec<HashValue>) -> MerkleTree {
        let leafs_count = leafs.len();
        let nodes_count = 2 * leafs_count - 1;
        let mut nodes: Vec<Node> = Vec::with_capacity(nodes_count);
        // in performance view
        nodes.resize(
            nodes_count - leafs_count,
            Node {
                _hash: Vec::new(),
                _left: true,
            },
        );
        // add nodes with leafs hashes and default left value
        for leaf in leafs.into_iter() {
            nodes.push(Node {
                _hash: leaf,
                _left: true,
            });
        }
        //create tree
        {
            let mut index = nodes.len() - 1;
            while index > 0 {
                let parent = index / 2 - 1;
                nodes[parent] = Node {
                    _hash: H::get_merge_hash(&nodes[index - 1]._hash, &nodes[index]._hash),
                    _left: true, //default left value for parent node
                };
                //right node
                nodes[index]._left = false;
                //left node
                nodes[index - 1]._left = true;
                index -= 2;
            }
        }
        MerkleTree {
            _tree: nodes,
            _count: leafs_count,
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
/// Verify validity of data to given root and proofs
pub fn verify_proof<H: HashFunction>(
    root: &HashValue,
    data_hash: &HashValue,
    proofs: &Vec<Node>,
) -> bool {
    let mut hash = data_hash.clone();
    for proof in proofs {
        if proof._left {
            hash = H::get_merge_hash(&proof._hash, &hash);
        } else {
            hash = H::get_merge_hash(&hash, &proof._hash);
        }
    }
    *root == hash
}

impl PartialEq for MerkleTree {
    fn eq(&self, other: &MerkleTree) -> bool {
        if let Some(ref lh_root) = self.root() {
            if let Some(ref rh_root) = other.root() {
                return lh_root._hash == rh_root._hash;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merkle_tree_data_test() {
        {
            let data = vec![
                String::from("data1"),
                String::from("data2"),
                String::from("data3"),
            ];
            let tree = MerkleTree::from_vec::<sha::Sha256, _>(&data);
            assert_eq!(tree.len(), 5);
            assert_eq!(tree.leafs(), 3);
        }
        {
            let data = vec![
                String::from("data1"),
                String::from("data2"),
                String::from("data3"),
                String::from("data4"),
            ];
            let tree = MerkleTree::from_vec::<sha::Sha256, _>(&data);
            assert_eq!(tree.len(), 7);
            assert_eq!(tree.leafs(), 4);
        }
        {
            let data = vec![
                String::from("data1"),
                String::from("data2"),
                String::from("data3"),
                String::from("data4"),
                String::from("data5"),
                String::from("data6"),
                String::from("data7"),
                String::from("data8"),
                String::from("data9"),
                String::from("data10"),
                String::from("data11"),
                String::from("data12"),
                String::from("data13"),
                String::from("data14"),
                String::from("data15"),
                String::from("data16"),
            ];
            let tree = MerkleTree::from_vec::<sha::Sha256, _>(&data);
            assert_eq!(tree.len(), 31);
            assert_eq!(tree.leafs(), 16);
        }
    }

    #[test]
    fn merkle_tree_crypto_test() {
        let data = vec![
            String::from("data1"),
            String::from("data2"),
            String::from("data3"),
            String::from("data4"),
            String::from("data5"),
            String::from("data6"),
            String::from("data7"),
            String::from("data8"),
            String::from("data9"),
            String::from("data10"),
            String::from("data11"),
            String::from("data12"),
            String::from("data13"),
            String::from("data14"),
            String::from("data15"),
            String::from("data16c"),
        ];
        let tree = MerkleTree::from_vec::<sha::Sha256, _>(&data);
        let mut leafs = Vec::with_capacity(data.len());
        for val in &data {
            leafs.push(<sha::Sha256 as HashFunction>::get_hash(
                val.encode::<u32>().unwrap(),
            ));
        }

        if let Some(root) = tree.root() {
            for leaf in &leafs {
                let proof = tree.get_proof(leaf);
                assert_eq!(verify_proof::<sha::Sha256>(&root._hash, leaf, &proof), true);
            }
        }
    }
}
