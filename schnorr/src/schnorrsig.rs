#![allow(non_snake_case)]

use core::ops::Neg;

use crate::{
    signature::Signature,
    taggedhash::{HashAdd, Tagged},
    xonly::XOnly,
};
use digest::Digest;
use secp256k1::{
    curve::{Affine, Jacobian, Scalar, ECMULT_CONTEXT},
    Message, PublicKey, SecretKey,
};

/// Construct schnorr sig challenge
/// hash(R_x|P_x|msg)
pub fn schnorrsig_challenge(rx: &XOnly, pkx: &XOnly, msg: &Message) -> Scalar {
    let mut bytes = [0u8; 32];
    let hash = sha2::Sha256::default().tagged(b"BIP0340/challenge");
    let tagged = hash.add(rx).add(pkx).add(&msg.0).finalize();

    bytes.copy_from_slice(tagged.as_slice());
    let mut scalar = Scalar::default();
    let _ = scalar.set_b32(&bytes);
    scalar
}

/// Generate nonce k and nonce point R
pub fn nonce_function_bip340(
    bip340_sk: &SecretKey,
    bip340_pkx: &XOnly,
    msg: &Message,
    aux: &Message,
) -> (Scalar, Affine) {
    let aux_hash = sha2::Sha256::default().tagged(b"BIP0340/aux");
    let aux_tagged = aux_hash.add(&aux.0).finalize();
    let sec_bytes: [u8; 32] = bip340_sk.serialize();
    let mut aux_bytes = [0u8; 32];
    aux_bytes.copy_from_slice(&aux_tagged);

    // bitwise xor the hashed randomness with secret
    for (i, byte) in aux_bytes.iter_mut().enumerate() {
        *byte ^= sec_bytes[i]
    }

    let nonce_hash = sha2::Sha256::default().tagged(b"BIP0340/nonce");
    let nonce_tagged = nonce_hash
        .add(&aux_bytes)
        .add(bip340_pkx)
        .add(&msg.0)
        .finalize();

    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(nonce_tagged.as_slice());
    let mut scalar = Scalar::default();
    let _ = scalar.set_b32(&nonce_bytes);
    let k = SecretKey::parse(&scalar.b32()).unwrap();
    let R = PublicKey::from_secret_key(&k);
    (k.into(), R.into())
}

/// Sign a message using the secret key with aux
pub fn sign_with_aux(
    msg: Message,
    aux: Message,
    seckey: SecretKey,
    pubkey: PublicKey,
) -> Signature {
    let mut pk: Affine = pubkey.into();

    let pkx = XOnly::from_field(&mut pk.x).unwrap();

    // Get nonce k and nonce point R
    let (k, mut R) = nonce_function_bip340(&seckey, &pkx, &msg, &aux);
    R.y.normalize();
    R.x.normalize();
    let k_even = if R.y.is_odd() { k.neg() } else { k };

    // Generate s = k + tagged_hash("BIP0340/challenge", R_x|P_x|msg) * d
    let rx = XOnly::from_bytes(R.x.b32()).unwrap();
    let h = schnorrsig_challenge(&rx, &pkx, &msg);
    let s = k_even + h * seckey.into();

    // Generate sig = R_x|s
    Signature { rx, s }
}

/// Sign a message with context
pub fn sign_with_context() {
    unimplemented!()
}

/// Verify a schnorr signature
pub fn verify(sig: &Signature, msg: &Message, pubkey: PublicKey) -> bool {
    let (rx, s) = sig.as_tuple();

    let pj = Jacobian::default();

    let mut P: Affine = pubkey.into();

    let pkx = XOnly::from_field(&mut P.x).unwrap();

    let h = schnorrsig_challenge(rx, &pkx, msg);

    let mut rj = Jacobian::default();
    ECMULT_CONTEXT.ecmult(&mut rj, &pj, &h, s);

    let mut R = Affine::from_gej(&rj);

    if R.is_infinity() {
        return false;
    }
    // S == R + h * P
    let Rx = XOnly::from_field(&mut R.x).unwrap();

    *rx == Rx
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    /// Check if the function is available
    #[test]
    fn test_sign_with_aux() {
        let msg = Sha256::digest(b"message");
        let aux = Sha256::digest(b"random auxiliary data");

        let m = Message::parse_slice(msg.as_slice()).unwrap();
        let a = Message::parse_slice(aux.as_slice()).unwrap();

        let mut sec_slice = [0u8; 32];
        sec_slice.copy_from_slice(
            &hex::decode("08a345c3478a200f1cb2709165b3ef556fd493cee6e64af5637cd57fb7adc1a2")
                .unwrap()[..],
        );
        let seckey = SecretKey::parse_slice(&sec_slice).unwrap();

        let pubkey = PublicKey::from_secret_key(&seckey);

        let sig = sign_with_aux(m, a, seckey, pubkey);

        assert_eq!(hex::encode(sig.to_bytes()), "7a2724ce5b5e9f53f81e377e614fafd8f44902711c3eb641c7c1091aaa1aa08a63a6cd5fd3b636c0f48b4a957cf9ac1e576912d20d898f274041986e1e842bd7");
    }
}
