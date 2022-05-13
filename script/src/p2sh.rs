use crate::{Builder, Error, Opcode, Script};
#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use light_bitcoin_crypto::dhash160;
use light_bitcoin_keys::{Address, AddressTypes, Network, Public, Type};

pub fn generate_redeem_script(mut pubkeys: Vec<Public>, sig_num: u32) -> Result<Script, Error> {
    // construct the public key of all people
    pubkeys.sort_unstable();

    let sum = pubkeys.len() as u32;
    if sig_num > sum || sum > 15 {
        return Err(Error::InvalidRedeemLength);
    }

    let opcode = match Opcode::from_u8(Opcode::OP_1 as u8 + sig_num as u8 - 1) {
        Some(o) => o,
        None => return Err(Error::InvalidThreshold),
    };
    let mut build = Builder::default().push_opcode(opcode);
    for pubkey in pubkeys.iter() {
        build = build.push_bytes(pubkey);
    }

    let opcode = match Opcode::from_u8(Opcode::OP_1 as u8 + sum as u8 - 1) {
        Some(o) => o,
        None => return Err(Error::InvalidThreshold),
    };
    Ok(build
        .push_opcode(opcode)
        .push_opcode(Opcode::OP_CHECKMULTISIG)
        .into_script())
}

pub fn generate_p2sh_address(redeem_script: &Script, network: Network) -> String {
    let address = Address {
        kind: Type::P2SH,
        network,
        hash: AddressTypes::Legacy(dhash160(&redeem_script)),
    };
    address.to_string()
}
