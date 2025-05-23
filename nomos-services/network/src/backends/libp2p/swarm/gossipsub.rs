use nomos_libp2p::{behaviour::gossipsub::swarm_ext::topic_hash, gossipsub};

use crate::backends::libp2p::{
    swarm::{exp_backoff, SwarmHandler, MAX_RETRY},
    Command, Event,
};

pub type Topic = String;

#[derive(Debug)]
#[non_exhaustive]
pub enum PubSubCommand {
    Broadcast {
        topic: Topic,
        message: Box<[u8]>,
    },
    Subscribe(Topic),
    Unsubscribe(Topic),
    #[doc(hidden)]
    RetryBroadcast {
        topic: Topic,
        message: Box<[u8]>,
        retry_count: usize,
    },
}

impl SwarmHandler {
    pub(super) fn handle_pubsub_command(&mut self, command: PubSubCommand) {
        match command {
            PubSubCommand::Broadcast { topic, message } => {
                self.broadcast_and_retry(topic, message, 0);
            }
            PubSubCommand::Subscribe(topic) => {
                tracing::debug!("subscribing to topic: {topic}");
                log_error!(self.swarm.subscribe(&topic));
            }
            PubSubCommand::Unsubscribe(topic) => {
                tracing::debug!("unsubscribing to topic: {topic}");
                self.swarm.unsubscribe(&topic);
            }
            PubSubCommand::RetryBroadcast {
                topic,
                message,
                retry_count,
            } => {
                self.broadcast_and_retry(topic, message, retry_count);
            }
        }
    }

    #[expect(
        clippy::cognitive_complexity,
        reason = "TODO: Address this at some point."
    )]
    pub(super) fn broadcast_and_retry(
        &mut self,
        topic: Topic,
        message: Box<[u8]>,
        retry_count: usize,
    ) {
        tracing::debug!("broadcasting message to topic: {topic}");

        match self.swarm.broadcast(&topic, message.to_vec()) {
            Ok(id) => {
                tracing::debug!("broadcasted message with id: {id} tp topic: {topic}");
                // self-notification because libp2p doesn't do it
                if self.swarm.is_subscribed(&topic) {
                    log_error!(self.events_tx.send(Event::Message(gossipsub::Message {
                        source: None,
                        data: message.into(),
                        sequence_number: None,
                        topic: topic_hash(&topic),
                    })));
                }
            }
            Err(gossipsub::PublishError::InsufficientPeers) if retry_count < MAX_RETRY => {
                let wait = exp_backoff(retry_count);
                tracing::error!("failed to broadcast message to topic due to insufficient peers, trying again in {wait:?}");

                let commands_tx = self.commands_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    let Some(new_retry_count) = retry_count.checked_add(1) else {
                        tracing::error!("retry count overflow.");
                        return;
                    };

                    commands_tx
                        .send(Command::PubSub(PubSubCommand::RetryBroadcast {
                            topic,
                            message,
                            retry_count: new_retry_count,
                        }))
                        .await
                        .unwrap_or_else(|_| tracing::error!("could not schedule retry"));
                });
            }
            Err(e) => {
                tracing::error!("failed to broadcast message to topic: {topic} {e:?}");
            }
        }
    }

    pub(super) fn handle_gossipsub_event(&self, event: nomos_libp2p::libp2p::gossipsub::Event) {
        if let nomos_libp2p::libp2p::gossipsub::Event::Message { message, .. } = event {
            let message = Event::Message(message);
            if let Err(e) = self.events_tx.send(message) {
                tracing::error!("Failed to send gossipsub message event: {}", e);
            }
        }
    }
}
