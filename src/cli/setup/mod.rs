use crate::crypto::vss::Vss;
use crate::errors::Error;
use bitcoin::{PrivateKey, PublicKey};

pub mod aggregate;
pub mod computesig;
pub mod create_key;
pub mod create_block_vss;
pub mod create_node_vss;
pub mod sign;
pub mod traits;

pub fn index_of(private_key: &PrivateKey, public_keys: &Vec<PublicKey>) -> usize {
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_private_key(&secp, private_key);
    let pos = public_keys
        .iter()
        .position(|pk| pk == &public_key)
        .expect("private_key or public_keys is invalid.");
    pos + 1
}

#[derive(Clone)]
pub struct IndexedVss {
    index: usize,
    vss: Vss,
}

impl std::str::FromStr for IndexedVss {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = s.split(':').collect();
        let index: usize = components[0]
            .parse()
            .map_err(|_| Error::InvalidArgs("vss".to_string()))?;
        let vss: Vss = Vss::from_str(components[1]).unwrap();
        Ok(IndexedVss {
            index: index,
            vss: vss,
        })
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct IndexedPublicKey {
    index: usize,
    public_key: PublicKey,
}

impl std::str::FromStr for IndexedPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components: Vec<&str> = s.split(':').collect();
        let index: usize = components[0]
            .parse()
            .map_err(|_| Error::InvalidArgs("vss".to_string()))?;
        let public_key: PublicKey = PublicKey::from_str(components[1]).map_err(|_| Error::InvalidKey)?;
        Ok(IndexedPublicKey {
            index: index,
            public_key: public_key,
        })
    }

}