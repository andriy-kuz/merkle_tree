extern crate openssl;

use openssl::sha;

pub trait HashFunction {
    fn get_hash(Vec<u8>) -> Vec<u8>;
    fn get_merge_hash(&Vec<u8>, &Vec<u8>) -> Vec<u8>;
}
//TODO: investigate how remove get_merge_hash code duplication
impl HashFunction for sha::Sha1 {
    fn get_hash(mut data: Vec<u8>) -> Vec<u8> {
        data = sha::sha1(&data).to_vec();
        sha::sha1(&data).to_vec()
    }
    fn get_merge_hash(lh: &Vec<u8>, rh: &Vec<u8>) -> Vec<u8> {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha1(&data).to_vec();
        sha::sha1(&data).to_vec()
    }
}

impl HashFunction for sha::Sha224 {
    fn get_hash(mut data: Vec<u8>) -> Vec<u8> {
        data = sha::sha224(&data).to_vec();
        sha::sha224(&data).to_vec()
    }
    fn get_merge_hash(lh: &Vec<u8>, rh: &Vec<u8>) -> Vec<u8> {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha224(&data).to_vec();
        sha::sha224(&data).to_vec()
    }
}

impl HashFunction for sha::Sha256 {
    fn get_hash(mut data: Vec<u8>) -> Vec<u8> {
        data = sha::sha256(&data).to_vec();
        sha::sha256(&data).to_vec()
    }
    fn get_merge_hash(lh: &Vec<u8>, rh: &Vec<u8>) -> Vec<u8> {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha256(&data).to_vec();
        sha::sha256(&data).to_vec()
    }
}

impl HashFunction for sha::Sha384 {
    fn get_hash(mut data: Vec<u8>) -> Vec<u8> {
        data = sha::sha384(&data).to_vec();
        sha::sha384(&data).to_vec()
    }
    fn get_merge_hash(lh: &Vec<u8>, rh: &Vec<u8>) -> Vec<u8> {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha384(&data).to_vec();
        sha::sha384(&data).to_vec()
    }
}

impl HashFunction for sha::Sha512 {
    fn get_hash(mut data: Vec<u8>) -> Vec<u8> {
        data = sha::sha512(&data).to_vec();
        sha::sha512(&data).to_vec()
    }
    fn get_merge_hash(lh: &Vec<u8>, rh: &Vec<u8>) -> Vec<u8> {
        let mut data = lh.clone();
        data.append(&mut rh.clone());
        data = sha::sha512(&data).to_vec();
        sha::sha512(&data).to_vec()
    }
}
