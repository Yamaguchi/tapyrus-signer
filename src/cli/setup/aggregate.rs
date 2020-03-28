use crate::cli::setup::index_of;
use crate::cli::setup::traits::Response;
use crate::crypto::vss::Vss;
use crate::errors::Error;
use crate::net::SignerID;
use crate::sign::Sign;
use crate::signer_node::SharedSecret;
use crate::signer_node::SharedSecretMap;
use bitcoin::{PrivateKey, PublicKey};
use clap::{App, Arg, ArgMatches, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::FE;
use std::fmt;
use std::str::FromStr;

pub struct CreateAggregateResponse {
    aggregated_public_key: PublicKey,
    node_shared_secret: FE,
}

impl CreateAggregateResponse {
    fn new(aggregated_public_key: PublicKey, node_shared_secret: FE,) -> Self {
        CreateAggregateResponse {
            aggregated_public_key: aggregated_public_key,
            node_shared_secret: node_shared_secret,
        }
    }
}

impl Response for CreateAggregateResponse {}

impl fmt::Display for CreateAggregateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.aggregated_public_key,
            self.node_shared_secret.to_big_int(),
        )
    }
}

pub struct CreateAggregateCommand {}

impl<'a> CreateAggregateCommand {
    pub fn execute(matches: &ArgMatches) -> Result<Box<dyn Response>, Error> {
        let private_key: PrivateKey = matches
            .value_of("private_key")
            .and_then(|key| PrivateKey::from_wif(key).ok())
            .ok_or(Error::InvalidArgs("private_key".to_string()))?;

        let vss_vec: Vec<Vss> = matches
            .values_of("vss")
            .ok_or(Error::InvalidArgs("vss is invalid".to_string()))?
            .map(|s| Vss::from_str(s).map_err(|_| Error::InvalidKey))
            .collect::<Result<Vec<Vss>, _>>()?;

        let mut public_keys = vss_vec
            .iter()
            .map(|vss| vss.sender_public_key)
            .collect::<Vec<PublicKey>>();
        public_keys.sort();

        let mut vss_map = SharedSecretMap::new();
        for vss in &vss_vec {
            vss_map.insert(
                SignerID::new(vss.sender_public_key.clone()),
                SharedSecret {
                    vss: VerifiableSS {
                        // threshold is not used in 'aggregate' command
                        parameters: ShamirSecretSharing {
                            threshold: 1,
                            share_count: vss_vec.len(),
                        },
                        commitments: vss
                            .positive_commitments
                            .iter()
                            .cloned()
                            .map(|c| c.to_point())
                            .collect(),
                    },
                    secret_share: vss.positive_secret,
                },
            );
        }

        let index = index_of(&private_key, &public_keys);
        let shared_keys = Sign::verify_vss_and_construct_key(&vss_map, &index)?;

        let public_key = PublicKey {
            compressed: true,
            key: shared_keys.y.get_element(),
        };

        Ok(Box::new(CreateAggregateResponse::new(
            public_key,
            shared_keys.x_i,
        )))
    }

    pub fn args<'b>() -> App<'a, 'b> {
        SubCommand::with_name("aggregate").args(&[
            Arg::with_name("vss")
                .long("vss")
                .required(true)
                .multiple(true)
                .takes_value(true),
            Arg::with_name("private_key")
                .long("private_key")
                .required(true)
                .number_of_values(1)
                .takes_value(true),
        ])
    }
}
