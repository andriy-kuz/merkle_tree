#![deny(missing_docs, missing_debug_implementations, missing_copy_implementations, trivial_casts,
        trivial_numeric_casts, unsafe_code, unstable_features, unused_import_braces,
        unused_qualifications)]
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
    fn get_hash(&Vec<u8>) -> HashValue;
    /// Return hash value of concatenated inputs
    fn get_merge_hash(lh: &HashValue, rh: &HashValue) -> HashValue {
        let mut data = Vec::with_capacity(lh.len() + rh.len());
        data.extend(lh);
        data.extend(rh);
        Self::get_hash(&data)
    }
}

impl HashFunction for sha::Sha1 {
    fn get_hash(data: &Vec<u8>) -> HashValue {
        let data = sha::sha1(data).to_vec();
        sha::sha1(&data).to_vec()
    }
}

impl HashFunction for sha::Sha224 {
    fn get_hash(data: &Vec<u8>) -> HashValue {
        let data = sha::sha224(data).to_vec();
        sha::sha224(&data).to_vec()
    }
}

impl HashFunction for sha::Sha256 {
    fn get_hash(data: &Vec<u8>) -> HashValue {
        let data = sha::sha256(data).to_vec();
        sha::sha256(&data).to_vec()
    }
}

impl HashFunction for sha::Sha384 {
    fn get_hash(data: &Vec<u8>) -> HashValue {
        let data = sha::sha384(data).to_vec();
        sha::sha384(&data).to_vec()
    }
}

impl HashFunction for sha::Sha512 {
    fn get_hash(data: &Vec<u8>) -> HashValue {
        let data = sha::sha512(data).to_vec();
        sha::sha512(&data).to_vec()
    }
}
