use blake2::{digest::consts::U32, Blake2b, Digest as _};
use libp2p::gossipsub::{Message, MessageId};

pub mod swarm_ext;

#[must_use]
pub fn compute_message_id(message: &Message) -> MessageId {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(&message.data);
    MessageId::from(hasher.finalize().to_vec())
}
