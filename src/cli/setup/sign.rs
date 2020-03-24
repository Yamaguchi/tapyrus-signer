// tapyrus-setup sign
//      -block_vss=1:<block_vss[1, i]>
//      -block_vss=2:<block_vss[2, i]> ... -block_vss=t:<block_vss[n, i]>
//      -node_vss=1:<node_vss[1, i]>
//      -node_vss=2:<node_vss[2, i]> ... -node_vss=t:<node_vss[n, i]>
//      -aggregated_public_key=<aggregated_public_key>
//      -nodesecret=<node_secret_share[i]>
//      -private_key=<node_private_key[i]> 
//      -block=<block>
//      -threshold=<threshold>
// output: <local_sig[i]>

use crate::blockdata::Block;
use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::crypto::vss::Vss;
use crate::crypto::multi_party_schnorr::LocalSig;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::signer_node::SharedSecret;
use crate::signer_node::ToSharedSecretMap;
use crate::util::jacobi;

use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use std::fmt;
use std::str::FromStr;

pub struct SignResponse {
    local_sig: LocalSig,
    public_key: PublicKey,
}

impl SignResponse {
    fn new(local_sig: LocalSig, public_key: PublicKey) -> Self {
        SignResponse {
            local_sig: local_sig,
            public_key: public_key,
        }
    }
}

impl Response for SignResponse {}

impl fmt::Display for SignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:0>64}{:0>64}{:0>66}",
            self.local_sig.gamma_i.to_big_int().to_hex(),
            self.local_sig.e.to_big_int().to_hex(),
            hex::encode(&self.public_key.key.serialize()[..]),
        )
    }
}

pub struct SignCommand {}

impl<'a> SignCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private_key".to_string()))?;

        let threshold: usize = matches
            .value_of("threshold")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error::InvalidArgs("threshold".to_string()))?;

        let block: Block = matches
            .value_of("block")
            .and_then(|s| Some(Block::new(hex::decode(s).expect("failed to decode block"))))
            .ok_or(Error::InvalidArgs("block".to_string()))?;

        let node_secret_share: FE = matches
            .value_of("node_secret_share")
            .and_then(|s| {
                // let bytes = hex::decode(hex).expect("node_secret_share is invalid");
                Some(ECScalar::from(&BigInt::from_str(s).expect("node_secret_share is invalid")))
            })
            .ok_or(Error::InvalidArgs("node_secret_share".to_string()))?;

        let aggregated_public_key: PublicKey = matches
            .value_of("aggregated_public_key")
            .and_then(|hex| PublicKey::from_str(hex).ok())
            .ok_or(Error::InvalidArgs("aggregated_public_key".to_string()))?;

        // let mut node_vss_vec: Vec<IndexedVss> = matches
        //     .values_of("node_vss")
        //     .ok_or(Error::InvalidArgs("node_vss is invalid".to_string()))?
        //     .map(|s| IndexedVss::from_str(s))
        //     .collect::<Result<Vec<IndexedVss>, _>>()?;
        // node_vss_vec.sort_by(|a, b| a.index.cmp(&b.index));

        let block_vss_vec: Vec<Vss> = matches
            .values_of("block_vss")
            .ok_or(Error::InvalidArgs("block_vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s))
            .collect::<Result<Vec<Vss>, _>>()?;
        // block_vss_vec.sort_by(|a, b| a.index.cmp(&b.index));

        let mut public_keys: Vec<PublicKey> = block_vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect();
        public_keys.sort();

        // println!("{}, {}, {:?}", index, private_key.to_wif(), public_keys);

        let index = index_of(&private_key, &public_keys);

        let params = ShamirSecretSharing {
            threshold: (threshold - 1) as usize,
            share_count: public_keys.len(),
        };
        let mut shared_block_secrets = BidirectionalSharedSecretMap::new();
        for vss in block_vss_vec.iter() {
            shared_block_secrets.insert(
                SignerID {
                    pubkey: vss.sender_public_key,
                },
                (
                    SharedSecret {
                        secret_share: vss.positive_secret,
                        vss: VerifiableSS {
                            parameters: params.clone(),
                            commitments: vss
                                .positive_commitments
                                .iter()
                                .map(|c| c.to_point())
                                .collect(),
                        },
                    },
                    SharedSecret {
                        secret_share: vss.negative_secret,
                        vss: VerifiableSS {
                            parameters: params.clone(),
                            commitments: vss
                                .negative_commitments
                                .iter()
                                .map(|c| c.to_point())
                                .collect(),
                        },
                    },
                ),
            );
        }

        let bytes: Vec<u8> = aggregated_public_key.key.serialize_uncompressed().to_vec();
        let point = GE::from_bytes(&bytes[1..]).expect("failed to convert to point");
        let priv_shared_keys = SharedKeys {
            y: point,
            x_i: node_secret_share,
        };

        let shared_keys_for_positive = Sign::verify_vss_and_construct_key(
            &shared_block_secrets.for_positive(),
            &index,
        )?;
        
        let local_sig_for_positive = Sign::sign(
            &shared_keys_for_positive,
            &priv_shared_keys,
            block.sighash(),
        );

        let shared_keys_for_negative = Sign::verify_vss_and_construct_key(
            &shared_block_secrets.for_negative(),
            &index,
        )?;
        let local_sig_for_negative = Sign::sign(
            &shared_keys_for_negative,
            &priv_shared_keys,
            block.sighash(),
        );

        let p = BigInt::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .unwrap();
        let is_positive = jacobi(&shared_keys_for_positive.y.y_coor().unwrap(), &p) == 1;
        let (_shared_keys, local_sig) = if is_positive {
            (shared_keys_for_positive, local_sig_for_positive)
        } else {
            (shared_keys_for_negative, local_sig_for_negative)
        };

        let secp = secp256k1::Secp256k1::new();
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        Ok(Box::new(SignResponse::new(local_sig, public_key)))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("sign").args(&[
            Arg::with_name("private_key")
                .long("private_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("threshold")
                .long("threshold")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("block")
                .long("block")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("node_secret_share")
                .long("node_secret_share")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("aggregated_public_key")
                .long("aggregated_public_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
            Arg::with_name("block_vss")
                .long("block_vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
        ])
    }
}

