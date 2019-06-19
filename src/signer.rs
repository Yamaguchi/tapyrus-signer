use serde::{Serialize, Deserialize, Serializer, Deserializer};
use crate::net::{MessageType, Message, SignerID, Signature};
use crate::serialize::ByteBufVisitor;
use crate::blockdata::Block;
use crate::net;

pub struct StateContext {
    pub current_state: NodeState,
}

/// When node don't know round status because of just now joining to signer network.
#[derive(Debug)]
pub enum NodeState {
    Joining,
    Master,
    Member
}

// state パターン
pub trait RoundState {
    fn process_candidateblock(&self, sender_id: &SignerID, block: &Block) -> NodeState;
    fn process_signature(&self, sender_id: &SignerID, signature: &Signature) -> NodeState;
    fn process_completedblock(&self, sender_id: &SignerID, block: &Block) -> NodeState;
    fn process_roundfailure(&self, sender_id: &SignerID) -> NodeState;
}
impl NodeState {
    pub fn process_message(&self, message: Message) -> NodeState {
        let state = match self {
            NodeState::Joining => Box::new(RoundStateJoining{}),
            _ => Box::new(RoundStateJoining),
        };

        match message {
            Message { sender_id: sender_id, message_type: MessageType::Candidateblock(block)} => {
                state.process_candidateblock(&sender_id, &block)
            },
            Message { sender_id: sender_id, message_type: MessageType::Signature(sig)} => {
                state.process_signature(&sender_id, &sig)
            },
            Message { sender_id: sender_id, message_type: MessageType::Completedblock(block)} => {
                state.process_completedblock(&sender_id, &block)
            },
            Message { sender_id: sender_id, message_type: MessageType::Roundfailure} => {
                state.process_roundfailure(&sender_id)
            },
        }
    }
}

impl StateContext {
    pub fn new(current_state: NodeState) -> StateContext {
        StateContext {
            current_state
        }
    }

    pub fn set_state(&mut self, s: NodeState) {
        self.current_state = s;
    }
}

struct RoundStateJoining;

impl RoundState for RoundStateJoining {
    fn process_candidateblock(&self, sender_id: &SignerID, block: &Block) -> NodeState {
        unimplemented!()
    }

    fn process_signature(&self, sender_id: &SignerID, signature: &Signature) -> NodeState {
        unimplemented!()
    }

    fn process_completedblock(&self, sender_id: &SignerID, block: &Block) -> NodeState {
        unimplemented!()
    }

    fn process_roundfailure(&self, sender_id: &SignerID) -> NodeState {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use crate::signer_node::{NodeParameters, SignerNode};
    use crate::net::{RedisManager, ConnectionManager, MessageType, Message, SignerID};
    use crate::test_helper::{TestKeys, create_message};
    use std::thread;
    use crate::signer::NodeState;
    use crate::rpc::Rpc;

    fn setup_node() -> thread::JoinHandle<()> {
        let testkeys = TestKeys::new();
        let pubkey_list = testkeys.pubkeys();
        let threshold = 2;
        let private_key = testkeys.key[0];

        let rpc = Rpc::new("http://localhost:1281".to_string(), Some("user".to_string()), Some("pass".to_string()));
        let params = NodeParameters::new(pubkey_list, private_key, threshold, rpc);
        let con = RedisManager::new();

        let mut node = SignerNode::new(con, params);
        thread::spawn(move || {
            node.start(NodeState::Member);
        })
    }
}