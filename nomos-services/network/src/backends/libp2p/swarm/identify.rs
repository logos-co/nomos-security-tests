use std::collections::HashSet;

use nomos_libp2p::libp2p::identify;

use crate::backends::libp2p::swarm::SwarmHandler;

impl SwarmHandler {
    pub(super) fn handle_identify_event(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info, .. } => {
                tracing::debug!(
                    "Identified peer {} with addresses {:?}",
                    peer_id,
                    info.listen_addrs
                );
                let kad_protocol_names = self
                    .swarm
                    .get_kademlia_protocol_names()
                    .collect::<HashSet<_>>();
                if info
                    .protocols
                    .iter()
                    .any(|p| kad_protocol_names.contains(&p))
                {
                    // we need to add the peer to the kademlia routing table
                    // in order to enable peer discovery
                    for addr in &info.listen_addrs {
                        self.swarm.kademlia_add_address(peer_id, addr.clone());
                    }
                }
            }
            event => {
                tracing::debug!("Identify event: {:?}", event);
            }
        }
    }
}
