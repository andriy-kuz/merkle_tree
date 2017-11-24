extern crate openssl;

use openssl::sha;

pub trait HashFunction {
    fn get_hash(Vec<u8>) -> Vec<u8>;
}

impl HashFunction for sha::Sha1 {
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        sha::sha1(&data).to_vec()
    }
}

impl HashFunction for sha::Sha224 {
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        sha::sha224(&data).to_vec()
    }
}

impl HashFunction for sha::Sha256 {
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        sha::sha256(&data).to_vec()
    }
}

impl HashFunction for sha::Sha384 {
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        sha::sha384(&data).to_vec()
    }
}

impl HashFunction for sha::Sha512 {
    fn get_hash(data: Vec<u8>) -> Vec<u8> {
        sha::sha512(&data).to_vec()
    }
}
