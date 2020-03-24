mod process_blockparticipants;
pub mod process_blocksig;
mod process_blockvss;
mod process_candidateblock;
mod process_completedblock;
mod process_nodevss;
pub use process_blockparticipants::process_blockparticipants;
pub use process_blocksig::process_blocksig;
pub use process_blockvss::process_blockvss;
pub use process_candidateblock::process_candidateblock;
pub use process_completedblock::process_completedblock;
pub use process_nodevss::process_nodevss;

use crate::blockdata::hash::SHA256Hash;
use crate::blockdata::Block;
use crate::crypto::multi_party_schnorr::Keys;
use crate::crypto::multi_party_schnorr::{LocalSig, SharedKeys};
use crate::errors::Error;
use crate::net::BlockGenerationRoundMessageType;
use crate::net::ConnectionManager;
use crate::net::Message;
use crate::net::MessageType;
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use crate::sign::Sign;
use crate::signer_node::{BidirectionalSharedSecretMap, NodeParameters, NodeState};
use crate::signer_node::{SharedSecret, ToSharedSecretMap};
use crate::util::jacobi;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, FE};

pub fn get_valid_block(state: &NodeState, blockhash: SHA256Hash) -> Result<&Block, Error> {
    let block_opt = match state {
        NodeState::Master {
            candidate_block, ..
        } => candidate_block,
        NodeState::Member {
            candidate_block, ..
        } => candidate_block,
        _ => {
            log::error!("Invalid node state: {:?}", state);
            return Err(Error::InvalidNodeState);
        }
    };
    match block_opt {
        None => {
            log::error!("Invalid message received. candidate block is not set.");
            Err(Error::InvalidBlock)
        }
        Some(block) if block.sighash() != blockhash => {
            log::error!("Invalid message received. Received message is based different block. expected: {:?}, actual: {:?}", block.sighash(), blockhash);
            Err(Error::InvalidBlock)
        }
        Some(block) => Ok(block),
    }
}

/// Create own VSSs and send to each other signers.
/// Returns
///     * own random key pair
///     * a VSS for itself(for positive and negative)
///     * own commitments
pub fn create_block_vss<T, C>(
    block: Block,
    params: &NodeParameters<T>,
    conman: &C,
) -> (Keys, SharedSecret, SharedSecret)
where
    T: TapyrusApi,
    C: ConnectionManager,
{
    let sharing_params = params.sharing_params();
    let key = Sign::create_key(params.self_node_index + 1, None);

    let parties = (0..sharing_params.share_count)
        .map(|i| i + 1)
        .collect::<Vec<usize>>();

    let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &key.u_i,
        &parties,
    );
    let order: BigInt = FE::q();
    let (vss_scheme_for_negative, secret_shares_for_negative) = VerifiableSS::share_at_indices(
        sharing_params.threshold,
        sharing_params.share_count,
        &(ECScalar::from(&(order - key.u_i.to_big_int()))),
        &parties,
    );

    for i in 0..params.pubkey_list.len() {
        // Skip broadcasting if it is vss for myself. Just return this.
        if i == params.self_node_index {
            continue;
        }

        conman.send_message(Message {
            message_type: MessageType::BlockGenerationRoundMessages(
                BlockGenerationRoundMessageType::Blockvss(
                    block.sighash(),
                    vss_scheme.clone(),
                    secret_shares[i],
                    vss_scheme_for_negative.clone(),
                    secret_shares_for_negative[i],
                ),
            ),
            sender_id: params.signer_id,
            receiver_id: Some(SignerID {
                pubkey: params.pubkey_list[i],
            }),
        });
    }

    (
        key,
        SharedSecret {
            vss: vss_scheme.clone(),
            secret_share: secret_shares[params.self_node_index],
        },
        SharedSecret {
            vss: vss_scheme_for_negative.clone(),
            secret_share: secret_shares_for_negative[params.self_node_index],
        },
    )
}

fn generate_local_sig<T>(
    blockhash: SHA256Hash,
    shared_block_secrets: &BidirectionalSharedSecretMap,
    priv_shared_keys: &SharedKeys,
    prev_state: &NodeState,
    params: &NodeParameters<T>,
) -> Result<(bool, SharedKeys, LocalSig), Error>
where
    T: TapyrusApi,
{
    log::trace!(
        "number of shared_block_secrets: {:?}",
        shared_block_secrets.len()
    );
    let block = get_valid_block(prev_state, blockhash)?;
    let shared_keys_for_positive = Sign::verify_vss_and_construct_key(
        &shared_block_secrets.for_positive(),
        &(params.self_node_index + 1),
    )?;

    let result_for_positive =
        Sign::sign(&shared_keys_for_positive, priv_shared_keys, block.sighash());

    let shared_keys_for_negative = Sign::verify_vss_and_construct_key(
        &shared_block_secrets.for_negative(),
        &(params.self_node_index + 1),
    )?;
    let result_for_negative =
        Sign::sign(&shared_keys_for_negative, priv_shared_keys, block.sighash());

    let p = BigInt::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();
    let is_positive = jacobi(&shared_keys_for_positive.y.y_coor().unwrap(), &p) == 1;
    let (shared_keys, local_sig) = if is_positive {
        (shared_keys_for_positive, result_for_positive)
    } else {
        (shared_keys_for_negative, result_for_negative)
    };

    return Ok((is_positive, shared_keys, local_sig));
}

fn broadcast_localsig<C: ConnectionManager>(
    sighash: SHA256Hash,
    local_sig: &LocalSig,
    conman: &C,
    signer_id: &SignerID,
) {
    conman.broadcast_message(Message {
        message_type: MessageType::BlockGenerationRoundMessages(
            BlockGenerationRoundMessageType::Blocksig(
                sighash,
                local_sig.gamma_i.clone(),
                local_sig.e.clone(),
            ),
        ),
        sender_id: signer_id.clone(),
        receiver_id: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_node::node_state::builder::{Builder, Master, Member};
    use crate::tests::helper::node_state_builder::BuilderForTest;

    const BLOCK: &str = "01000000a8b61e31f3d6b655eb8fc387a22d139f141a14cb79c3a12a18192aa4d25941dfcb2edbbd1385a5d5c3bd037b6fd0ca8d691c13875fa74014a115f096a59be33a3447345d02f1420d9f5bc070aa00dc2bcb201ef470842fa5ec4f5c9986345ee91ae23b5e00000101000000010000000000000000000000000000000000000000000000000000000000000000260000000401260101ffffffff0200f2052a010000001976a9145f3f3758e7a4cf159c7bdb441ae4ff80999c62e888ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000";
    const HASH: &str = "5b19db53903eb5d083a98e7d254f67b3985e7f2d2e5d9c138008e46059a83fa3";
    const INVALID_HASH: &str = "0000db53903eb5d083a98e7d254f67b3985e7f2d2e5d9c138008e46059a83fa3";

    #[test]
    fn test_get_valid_block_valid_for_master() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = SHA256Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_valid_for_member() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = SHA256Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert_eq!(*get_valid_block(&state, blockhash).unwrap(), block.unwrap());
    }

    #[test]
    fn test_get_valid_block_invalid_node_state() {
        let state = NodeState::Joining;
        let blockhash = SHA256Hash::from_slice(&hex::decode(HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_master() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Master::for_test().candidate_block(block.clone()).build();
        let blockhash = SHA256Hash::from_slice(&hex::decode(INVALID_HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }

    #[test]
    fn test_get_valid_block_invalid_blockhash_for_member() {
        let block = Some(Block::new(hex::decode(BLOCK).unwrap()));
        let state = Member::for_test().candidate_block(block.clone()).build();
        let blockhash = SHA256Hash::from_slice(&hex::decode(INVALID_HASH).unwrap()[..]).unwrap();
        assert!(get_valid_block(&state, blockhash).is_err());
    }
}
