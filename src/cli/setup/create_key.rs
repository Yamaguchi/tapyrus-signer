use crate::cli::setup::traits::Response;
use crate::errors::Error;
use bitcoin::network::constants::Network;
use bitcoin::{PrivateKey, PublicKey};
use clap::{App, ArgMatches, SubCommand};
use secp256k1::rand::thread_rng;
use secp256k1::Secp256k1;
use std::fmt;

pub struct CreateKeyResponse {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl CreateKeyResponse {
    fn new(private_key: PrivateKey, public_key: PublicKey) -> Self {
        CreateKeyResponse {
            private_key: private_key,
            public_key: public_key,
        }
    }
}

impl Response for CreateKeyResponse {}

impl fmt::Display for CreateKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.private_key.to_wif(),
            hex::encode(&self.public_key.key.serialize()[..]),
        )
    }
}

pub struct CreateKeyCommand {}

impl<'a> CreateKeyCommand {
    pub fn execute(_matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let s = Secp256k1::new();
        let mut rng = thread_rng();
        let private_key = bitcoin::PrivateKey {
            compressed: true,
            network: Network::Testnet,
            key: s.generate_keypair(&mut rng).0,
        };
        let public_key = PublicKey::from_private_key(&s, &private_key);
        Ok(Box::new(CreateKeyResponse::new(private_key, public_key)))
    }
    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("createkey")
    }
}
