use sha3::Digest;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

type Bytes = [u8];
type MerkleProof<T: Hasher> = Vec<T::Hash>;

pub struct MerkleTree<T: Hasher> {
    leaves: Vec<T::Hash>,
    layers: Vec<Vec<T::Hash>>,
    phantom: PhantomData<T>,
}

impl<T: Hasher> MerkleTree<T> {
    pub fn new(leaves: &[&Bytes]) -> Self {
        // Hash and sort leaves
        let mut leaves: Vec<T::Hash> = leaves.iter().map(|l| MerkleTree::<T>::hash(l)).collect();
        leaves.sort();

        // todo: deduplicate

        // Initialise layers with leaves
        let mut layers = vec![leaves.clone()];

        let mut nodes = leaves.clone();
        while nodes.len() > 1 {
            let layer_index = layers.len();

            // Add next layer for resulting nodes
            layers.push(vec![]);

            // Process nodes in pairs
            for i in (0..nodes.len()).step_by(2) {
                if i + 1 == nodes.len() {
                    if nodes.len() % 2 == 1 {
                        // push copy of hash and continue iteration
                        layers[layer_index].push(nodes[i]);
                        continue;
                    }
                }

                // Select pair and then sort
                let left = nodes[i];
                let right = if i + 1 == nodes.len() {
                    left
                } else {
                    nodes[i + 1]
                };
                let mut pair = [left, right];
                pair.sort();

                // Create hash from pair and add to layer
                let hash = MerkleTree::<T>::hash_pair(pair[0], pair[1]);
                layers[layer_index].push(hash)
            }

            // Process next layer
            nodes = layers[layer_index].clone()
        }

        Self {
            leaves,
            layers,
            phantom: PhantomData,
        }
    }

    pub fn root(&self) -> T::Hash {
        if self.layers.len() == 0 {
            return T::Hash::default();
        }
        self.layers[self.layers.len() - 1][0]
    }

    pub fn proof(&self, leaf: T::Hash) -> MerkleProof<T> {
        // Attempt to locate leaf index
        let mut index = None;
        for i in 0..self.leaves.len() {
            if leaf == self.leaves[i] {
                index = Some(i)
            }
        }

        if index.is_none() {
            return Default::default();
        }

        let mut index = index.unwrap();
        let mut proof = vec![];
        for i in 0..self.layers.len() {
            let layer = &self.layers[i];
            let right_node = (index % 2) > 0;
            let pair_index = if right_node { index - 1 } else { index + 1 };

            if pair_index < layer.len() {
                proof.push(layer[pair_index])
            }

            // set index to parent index
            index = (index / 2) | 0
        }

        return proof;
    }

    pub fn leaves(&self) -> &Vec<T::Hash> {
        &self.leaves
    }

    pub fn verify(&self, proof: MerkleProof<T>, leaf: T::Hash, root: T::Hash) -> bool {
        let mut hash = leaf.clone();

        for i in 0..proof.len() {
            let node = proof[i];

            if hash < node {
                hash = MerkleTree::<T>::hash_pair(hash, node);
            } else {
                hash = MerkleTree::<T>::hash_pair(node, hash);
            }
        }

        hash == root
    }

    fn layers_hex_encoded(&self) -> Vec<Vec<String>> {
        self.layers
            .iter()
            .map(|layer| {
                layer
                    .iter()
                    .map(|hash| format!("0x{}", hex::encode(&hash)))
                    .collect()
            })
            .collect()
    }

    fn hash(value: &[u8]) -> T::Hash {
        T::hash(value)
    }

    fn hash_pair(left: T::Hash, right: T::Hash) -> T::Hash {
        let mut combined: Vec<u8> = left.into();
        let mut right: Vec<u8> = right.into();
        combined.append(&mut right);
        T::hash(&combined)
    }
}

impl<T: Hasher> Display for MerkleTree<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Loop through layers, building nodes
        let layers = self.layers_hex_encoded();
        let mut nodes = vec![];
        for i in 0..self.layers.len() {
            let mut temp = vec![];
            for j in 0..self.layers[i].len() {
                // Create node
                let mut node = Node {
                    hash: layers[i][j].clone(),
                    nodes: Default::default(),
                };

                if nodes.len() > 0 {
                    // Remove node from previous layer and add as child
                    node.nodes.push(nodes.remove(0));

                    if nodes.len() > 0 {
                        // Remove node from previous layer and add as child
                        node.nodes.push(nodes.remove(0));
                    }
                }

                temp.push(node);
            }

            for a in temp {
                nodes.push(a)
            }
        }

        #[derive(Debug)]
        struct Node {
            hash: String,
            nodes: Vec<Node>,
        }

        // Recursively output the nodes as a tree
        fn output(
            nodes: &Vec<Node>,
            level: usize,
            peers: usize,
            f: &mut Formatter<'_>,
        ) -> std::fmt::Result {
            const INDENTATION: &str = "  ";

            let length = nodes.len();
            for (i, node) in nodes.iter().enumerate() {
                // Handle level indentations
                for l in 0..level {
                    let prefix = if l > 0 && l <= peers { "|" } else { " " };
                    write!(f, "{}{}", prefix, INDENTATION)?;
                }

                // Write output with appropriate prefix
                let prefix = if i == length - 1 { "└" } else { "├" };
                write!(f, "{}─ {}\n", prefix, node.hash)?;

                // Update peer tally and then output child nodes
                let peers = if i != length - 1 { peers + 1 } else { peers };
                output(&node.nodes, level + 1, peers, f)?;
            }

            write!(f, "")
        }

        output(&nodes, 0, 0, f)
    }
}

pub trait Hasher: Default {
    type Hash: Copy + PartialEq + Into<Vec<u8>> + TryFrom<Vec<u8>> + Ord + Default + AsRef<[u8]>;

    fn hash(value: &[u8]) -> Self::Hash;
}

pub struct Keccak256 {}

impl Default for Keccak256 {
    fn default() -> Self {
        Self {}
    }
}

impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash(value: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Keccak256::default();
        hasher.update(value);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Bytes, Keccak256, MerkleTree};
    use primitive_types::H160;

    #[test]
    fn letters() {
        let leaves: Vec<&Bytes> = ["a", "b", "c"].iter().map(|x| x.as_bytes()).collect();
        test(leaves, 2)
    }

    #[test]
    fn numbers() {
        let leaves: Vec<&Bytes> = ["1", "2", "3", "4", "5"]
            .iter()
            .map(|x| x.as_bytes())
            .collect();
        test(leaves, 1)
    }

    #[test]
    fn addresses() {
        let addresses = vec![
            H160::from_low_u64_be(1),
            H160::from_low_u64_be(2),
            H160::from_low_u64_be(3),
        ];
        test(addresses.iter().map(|a| a.as_bytes()).collect(), 0)
    }

    fn test(leaves: Vec<&Bytes>, index: usize) {
        let tree = MerkleTree::<Keccak256>::new(&leaves);
        let root = tree.root();
        println!("Root\n0x{}\n", hex::encode(root));

        let leaves = tree.leaves();
        let leaf = leaves[index];
        println!(
            "Leaves\n{:?}\n",
            leaves
                .iter()
                .map(|hash| format!("0x{}", hex::encode(hash)))
                .collect::<Vec<String>>()
        );

        let proof = tree.proof(leaf);
        println!(
            "Proof for 0x{}\n{:?}\n",
            hex::encode(leaf),
            proof
                .iter()
                .map(|hash| format!("0x{}", hex::encode(hash)))
                .collect::<Vec<String>>()
        );

        println!("Tree:\n{}", tree);

        // Verify the proof
        assert_eq!(tree.verify(proof.clone(), leaf, root), true);

        // Check other leaves cannot be verified
        for i in 0..leaves.len() {
            if i == index {
                continue;
            }

            assert_eq!(tree.verify(proof.clone(), leaves[i], root), false);
        }
    }
}
