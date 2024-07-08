use std::ops::Mul;
//use ark_ec::bls12::Bls12;
//use ark_ff::Field;
use ark_ff::BigInteger256;
use ark_bls12_381::{G1Projective as G1,Fr};
use ark_std::UniformRand;
use sha2::{Sha256,Digest};
//use ark_ec::hashing::HashToCurve;
//use ark_serialize::CanonicalSerializeHashExt;
//use object::read::elf::section::SectionHeader;
//use std::hash::Hash;


#[allow(non_snake_case)]
pub fn keyGen()-> (Fr, G1, G1) {
    let mut rng1 = ark_std::test_rng();
    let mut rng2 = ark_std::test_rng();
    let secret_key = Fr::rand(&mut rng1);
    let g = G1::rand(&mut rng2) ;
    let public_key = g.mul(secret_key) ;
    (secret_key, public_key, g)
}

pub fn sign(message: &[u8], sk: &Fr, g: &G1)-> (G1, Fr) {
    let mut rng = ark_std::test_rng() ;
    let k = Fr::rand(&mut rng) ; //random nonce 
    #[allow(non_snake_case)]
    let R = g.mul(k) ;
    #[allow(non_snake_case)]
    let k_mul_G = g.mul(k).to_string() ;


    let input = [message,k_mul_G.as_bytes()].concat() ;


    let mut hasher = Sha256::digest(&input);
    hasher[31] = 0u8 ;
    let hash_bytes = hasher.as_slice() ;

    let mut hash_values: [u64;4] = [0;4] ;
    hash_values[0] = u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap());
    hash_values[1] = u64::from_le_bytes(hash_bytes[8..16].try_into().unwrap());
    hash_values[2] = u64::from_le_bytes(hash_bytes[16..24].try_into().unwrap());
    hash_values[3] = u64::from_le_bytes(hash_bytes[24..32].try_into().unwrap());
    //let hash_value = hasher.hash_to_field(&input, 1) ;

    let bi = BigInteger256::new(hash_values) ;
    let c = Fr::from(bi);

    let u = k - (sk * &c) ;

    (R,u)
}
#[allow(non_snake_case)]
pub fn verify(R: &G1, u: &Fr, pk: &G1, message: &[u8], g: &G1) -> bool {
    let input = [message,R.to_string().as_bytes()].concat() ;

    let mut hasher = Sha256::digest(&input);
    hasher[31] = 0u8 ;
    
    let hash_bytes = hasher.as_slice() ;

    let mut hash_values: [u64;4] = [0;4] ;
    hash_values[0] = u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap());
    hash_values[1] = u64::from_le_bytes(hash_bytes[8..16].try_into().unwrap());
    hash_values[2] = u64::from_le_bytes(hash_bytes[16..24].try_into().unwrap());
    hash_values[3] = u64::from_le_bytes(hash_bytes[24..32].try_into().unwrap());
    //let hash_value = hasher.hash_to_field(&input, 1) ;

    let bi = BigInteger256::new(hash_values) ;
    let c = Fr::from(bi) ;
    #[allow(non_snake_case)]
    let u_mul_G = g.mul(u) ;
    let c_mul_pk = pk.mul(c) ;

    let lhs = u_mul_G + c_mul_pk ;
    &lhs == R

}