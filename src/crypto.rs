//! Cryptographic util module
//! Crypto module use openssl library
//! and has implementation of HashFunction traits for
//! openssl sha algorithms: SHA1, SHA224, SHA256, SHA384, SHA512
extern crate openssl;
pub use self::openssl::sha;

/// Hash value alias
pub type HashValue = Vec<u8>;

/// Hash functions trait
pub trait HashFunction {
    /// Return hash value of input
    fn get_hash(Vec<u8>) -> HashValue;
    /// Return hash value of concatenated inputs
    fn get_merge_hash(&HashValue, &HashValue) -> HashValue;
}
//TODO: investigate how remove get_merge_hash code duplication
impl HashFunction for sha::Sha1 {
    fn get_hash(mut data: Vec<u8>) -> HashValue {
        data = sha::sha1(&data).to_vec();
        sha::sha1(&data).to_vec()
    }
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha1(&data).to_vec();
        sha::sha1(&data).to_vec()
    }
}

impl HashFunction for sha::Sha224 {
    fn get_hash(mut data: Vec<u8>) -> HashValue {
        data = sha::sha224(&data).to_vec();
        sha::sha224(&data).to_vec()
    }
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha224(&data).to_vec();
        sha::sha224(&data).to_vec()
    }
}

impl HashFunction for sha::Sha256 {
    fn get_hash(mut data: Vec<u8>) -> HashValue {
        data = sha::sha256(&data).to_vec();
        sha::sha256(&data).to_vec()
    }
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha256(&data).to_vec();
        sha::sha256(&data).to_vec()
    }
}

impl HashFunction for sha::Sha384 {
    fn get_hash(mut data: Vec<u8>) -> HashValue {
        data = sha::sha384(&data).to_vec();
        sha::sha384(&data).to_vec()
    }
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha384(&data).to_vec();
        sha::sha384(&data).to_vec()
    }
}

impl HashFunction for sha::Sha512 {
    fn get_hash(mut data: Vec<u8>) -> HashValue {
        data = sha::sha512(&data).to_vec();
        sha::sha512(&data).to_vec()
    }
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha512(&data).to_vec();
        sha::sha512(&data).to_vec()
    }
}
