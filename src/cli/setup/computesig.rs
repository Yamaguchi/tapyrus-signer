use crate::blockdata::Block;
use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::crypto::multi_party_schnorr::LocalSig;
use crate::crypto::multi_party_schnorr::SharedKeys;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::signer_node::SharedSecret;
use crate::signer_node::ToSharedSecretMap;
use crate::signer_node::ToVerifiableSS;
use crate::signer_node::SharedSecretMap;
use crate::signer_node::message_processor::process_blocksig::aggregate_and_verify_signature;
use crate::util::jacobi;

use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE, GE};
use std::fmt;
use std::str::FromStr;
use crate::signer_node::utils::sender_index;
use std::collections::BTreeMap;

pub struct ComputeSigResponse {
    block_with_signature: Block,
}

impl ComputeSigResponse {
    fn new(block_with_signature: Block) -> Self {
        ComputeSigResponse {
            block_with_signature: block_with_signature,
        }
    }
}

impl Response for ComputeSigResponse {}

impl fmt::Display for ComputeSigResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.block_with_signature.hex())
    }
}

pub struct ComputeSigCommand {}

impl<'a> ComputeSigCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private_key".to_string()))?;

        let threshold: usize = matches
            .value_of("threshold")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(Error::InvalidArgs("threshold".to_string()))?;

        let aggregated_public_key: PublicKey = matches
            .value_of("aggregated_public_key")
            .and_then(|hex| PublicKey::from_str(hex).ok())
            .ok_or(Error::InvalidArgs("aggregated_public_key".to_string()))?;

        let node_secret_share: FE = matches
            .value_of("node_secret_share")
            .and_then(|s| {
                // let bytes = hex::decode(hex).expect("node_secret_share is invalid");
                Some(ECScalar::from(&BigInt::from_str(s).expect("node_secret_share is invalid")))
            })
            .ok_or(Error::InvalidArgs("node_secret_share".to_string()))?;

        let block: Block = matches
            .value_of("block")
            .and_then(|s| Some(Block::new(hex::decode(s).expect("failed to decode block"))))
            .ok_or(Error::InvalidArgs("block".to_string()))?;

        let mut node_vss_vec: Vec<Vss> = matches
            .values_of("node_vss")
            .ok_or(Error::InvalidArgs("node_vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s))
            .collect::<Result<Vec<Vss>, _>>()?;
        node_vss_vec.sort_by(|a, b| a.sender_public_key.cmp(&b.sender_public_key));

        let mut block_vss_vec: Vec<Vss> = matches
            .values_of("block_vss")
            .ok_or(Error::InvalidArgs("block_vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s))
            .collect::<Result<Vec<Vss>, _>>()?;
        block_vss_vec.sort_by(|a, b| a.sender_public_key.cmp(&b.sender_public_key));

        let mut keyed_local_sigs: Vec<(FE, FE, PublicKey)> = matches
            .values_of("sig")
            .ok_or(Error::InvalidArgs("local_sig is invalid".to_string()))?
            .map(|s| {
                let gamma_i = ECScalar::from(
                    &BigInt::from_str_radix(&s[0..64], 16).expect("value gamma is invalid"),
                );
                let e = ECScalar::from(
                    &BigInt::from_str_radix(&s[64..128], 16).expect("value e is invalid"),
                );
                let public_key = PublicKey::from_str(&s[128..]).expect("public_key is invalid");
                (gamma_i, e, public_key)
            })
            .collect::<Vec<(FE, FE, PublicKey)>>();
        keyed_local_sigs.sort_by(|a, b| a.2.cmp(&b.2));
        let local_sigs: Vec<LocalSig> = keyed_local_sigs.iter().map(|l| LocalSig { gamma_i: l.0, e: l.1 }).collect();

        let mut public_keys: Vec<PublicKey> = block_vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect();
        public_keys.sort();
        
        let index = index_of(&private_key, &public_keys);

        let params = ShamirSecretSharing {
            threshold: threshold - 1,
            share_count: public_keys.len(),
        };
        let mut shared_block_secrets = BidirectionalSharedSecretMap::new();
        for vss in block_vss_vec.iter() {
            // let node_vss: IndexedVss = node_vss_vec[i].clone();
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

        let result_for_positive = Sign::sign(
            &shared_keys_for_positive,
            &priv_shared_keys,
            block.sighash(),
        );

        let shared_keys_for_negative = Sign::verify_vss_and_construct_key(
            &shared_block_secrets.for_negative(),
            &index,
        )?;
        let result_for_negative = Sign::sign(
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
        let (block_shared_keys, _result) = if is_positive {
            (shared_keys_for_positive, result_for_positive)
        } else {
            (shared_keys_for_negative, result_for_negative)
        };

        let mut shared_secrets = SharedSecretMap::new();
        for node_vss in &node_vss_vec {
            shared_secrets.insert(
                SignerID { pubkey: node_vss.sender_public_key }, 
                SharedSecret {
                    vss: VerifiableSS {
                        parameters: params.clone(),
                        commitments: node_vss
                            .positive_commitments
                            .iter()
                            .map(|c| c.to_point())
                            .collect(),
                    },
                    secret_share: node_vss.positive_secret,
                }
            );
        }
        let mut signatures = BTreeMap::new();
        for (gamma, e, public_key) in keyed_local_sigs {
            signatures.insert(SignerID { pubkey: public_key }, (gamma, e));
        }
        let result = aggregate_and_verify_signature(
            &block,
            signatures,
            &public_keys,
            &shared_secrets,
            &Some((is_positive, block_shared_keys.x_i, block_shared_keys.y)),
            &shared_block_secrets,
            &priv_shared_keys,
        );
        println!("{}", result.is_ok());

        let key_gen_vss_vec: Vec<VerifiableSS> = node_vss_vec
            .iter()
            .map(|vss| VerifiableSS {
                parameters: params.clone(),
                commitments: vss
                    .positive_commitments
                    .iter()
                    .map(|c| c.to_point())
                    .collect(),
            })
            .collect();
        let eph_vss_vec: Vec<VerifiableSS> = if is_positive {
            shared_block_secrets.for_positive().to_vss()
        } else {
            shared_block_secrets.for_negative().to_vss()
        };

        let parties = shared_block_secrets
            .keys()
            .map(|k| sender_index(k, &public_keys))
            .collect::<Vec<usize>>();
        let vss_sum =
            LocalSig::verify_local_sigs(&local_sigs, &parties[..], &key_gen_vss_vec, &eph_vss_vec)?;

        let signature = Sign::aggregate(&vss_sum, &local_sigs, &parties[..], block_shared_keys.y);
        let public_key = priv_shared_keys.y;
        let hash = block.sighash().into_inner();
        signature.verify(&hash, &public_key)?;
        let sig_hex = Sign::format_signature(&signature);
        let new_block: Block = block.add_proof(hex::decode(sig_hex).unwrap());
        Ok(Box::new(ComputeSigResponse::new(new_block)))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("computesig").args(&[
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
            Arg::with_name("node_vss")
                .long("node_vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("block_vss")
                .long("block_vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("sig")
                .long("sig")
                .required(true)
                .multiple(true)
                .takes_value(true),
        ])
    }
}

