use sha3::Digest;

pub trait HashFunction: Default {
    type Hash: Copy + PartialEq + Into<Vec<u8>> + TryFrom<Vec<u8>> + Ord + Default + AsRef<[u8]>;

    fn hash(value: &[u8]) -> Self::Hash;
}

pub struct Keccak256 {}

impl Default for Keccak256 {
    fn default() -> Self {
        Self {}
    }
}

impl HashFunction for Keccak256 {
    type Hash = [u8; 32];

    fn hash(value: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Keccak256::default();
        hasher.update(value);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use crate::hash_functions::Keccak256;
    use crate::HashFunction;
    use primitive_types::H160;

    #[test]
    fn hashes_address() {
        assert_eq!(
            hex::encode(Keccak256::hash(&H160::from_low_u64_be(1).as_bytes())),
            "1468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d"
        );
    }

    #[test]
    fn hashes_integer() {
        assert_eq!(
            hex::encode(Keccak256::hash(&1u8.to_ne_bytes())),
            "5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2"
        );
    }

    #[test]
    fn hashes_string() {
        assert_eq!(
            hex::encode(Keccak256::hash(&"a".as_bytes())),
            "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"
        );
    }
}
