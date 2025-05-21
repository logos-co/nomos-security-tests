pub mod behaviour;

#[cfg(test)]
mod test {
    use std::{collections::VecDeque, ops::Range, path::PathBuf, sync::LazyLock, time::Duration};

    use futures::StreamExt as _;
    use kzgrs_backend::testutils;
    use libp2p::{identity::Keypair, quic, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};
    use libp2p_swarm_test::SwarmExt as _;
    use log::{error, info};
    use nomos_da_messages::{common::Share, replication::ReplicationRequest};
    use tokio::sync::{mpsc, watch};
    use tracing_subscriber::{fmt::TestWriter, EnvFilter};

    use crate::{
        protocols::replication::behaviour::{
            ReplicationBehaviour, ReplicationConfig, ReplicationEvent,
        },
        test_utils::{start_udp_mutation_proxy, AllNeighbours, TamperingReplicationBehaviour},
    };

    type TestSwarm = Swarm<ReplicationBehaviour<AllNeighbours>>;

    fn get_swarm(key: Keypair, all_neighbours: AllNeighbours) -> TestSwarm {
        // libp2p_swarm_test::SwarmExt::new_ephemeral_tokio does not allow to inject
        // arbitrary keypair
        libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_other_transport(|keypair| quic::tokio::Transport::new(quic::Config::new(keypair)))
            .unwrap()
            .with_behaviour(|key| {
                ReplicationBehaviour::new(
                    ReplicationConfig {
                        seen_message_cache_size: 100,
                        seen_message_ttl: Duration::from_secs(60),
                    },
                    PeerId::from_public_key(&key.public()),
                    all_neighbours,
                )
            })
            .unwrap()
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(10)))
            .build()
    }

    fn make_neighbours(keys: &[&Keypair]) -> AllNeighbours {
        let neighbours = AllNeighbours::new();
        keys.iter()
            .for_each(|k| neighbours.add_neighbour(PeerId::from_public_key(&k.public())));
        neighbours
    }

    fn get_message(i: usize) -> ReplicationRequest {
        MESSAGES[i].clone()
    }

    async fn wait_for_incoming_connection(swarm: &mut TestSwarm, other: PeerId) {
        swarm
            .wait(|event| {
                matches!(event, SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == other)
                    .then_some(event)
            })
            .await;
    }

    async fn wait_for_messages(swarm: &mut TestSwarm, expected: Range<usize>) {
        let mut expected_messages = expected
            .into_iter()
            .map(|i| Box::new(get_message(i)))
            .collect::<VecDeque<Box<ReplicationRequest>>>();

        while let Some(expected_message) = expected_messages.front() {
            loop {
                if let SwarmEvent::Behaviour(ReplicationEvent::IncomingMessage {
                                                 message, ..
                                             }) = swarm.select_next_some().await
                {
                    if &message == expected_message {
                        break;
                    }
                }
            }

            expected_messages.pop_front().unwrap();
        }
    }

    static MESSAGES: LazyLock<Vec<ReplicationRequest>> = LazyLock::new(|| {
        // The fixture contains 20 messages seeded from values 0..20 for subnet 0
        // Ad-hoc generation of those takes about 12 seconds on a Ryzen3700x
        bincode::deserialize(include_bytes!("./fixtures/messages.bincode")).unwrap()
    });

    #[test]
    #[ignore = "Invoke to generate fixtures"]
    fn generate_fixtures() {
        let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("src/protocols/replication/fixtures/messages.bincode");
        let mut blob_id = [0u8; 32];

        let messages = (0..20u8)
            .map(|i| {
                blob_id[31] = i;
                ReplicationRequest {
                    share: Share {
                        blob_id,
                        data: {
                            let mut data = testutils::get_default_da_blob_data();
                            *data.last_mut().unwrap() = i;
                            testutils::get_da_share(Some(data))
                        },
                    },
                    subnetwork_id: 0,
                }
            })
            .collect::<Vec<_>>();
        let serialized = bincode::serialize(&messages).unwrap();
        std::fs::write(path, serialized).unwrap();
    }

    #[tokio::test]
    async fn test_replication_chain_in_both_directions() {
        // Scenario:
        // 0. Peer connections: A <- B -> C
        // 1. Alice is the initiator, Bob forwards to Charlie, message flow: A -> B -> C
        // 2. And then, within the same connections, Charlie is the initiator, Bob
        //    forwards to Alice, message flow: C -> B -> A
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .compact()
            .with_writer(TestWriter::default())
            .try_init();

        let k1 = Keypair::generate_ed25519();
        let k2 = Keypair::generate_ed25519();
        let k3 = Keypair::generate_ed25519();
        let peer_id1 = PeerId::from_public_key(&k1.public());
        let peer_id2 = PeerId::from_public_key(&k2.public());
        let peer_id3 = PeerId::from_public_key(&k3.public());
        let neighbours1 = make_neighbours(&[&k1, &k2]);
        let neighbours2 = make_neighbours(&[&k1, &k2, &k3]);
        let neighbours3 = make_neighbours(&[&k2, &k3]);
        let mut swarm_1 = get_swarm(k1, neighbours1);
        let mut swarm_2 = get_swarm(k2, neighbours2);
        let mut swarm_3 = get_swarm(k3, neighbours3);
        let (done_1_tx, mut done_1_rx) = mpsc::channel::<()>(1);
        let (done_2_tx, mut done_2_rx) = mpsc::channel::<()>(1);
        let (done_3_tx, mut done_3_rx) = mpsc::channel::<()>(1);

        let addr1: Multiaddr = "/ip4/127.0.0.1/udp/5054/quic-v1".parse().unwrap();
        let addr3: Multiaddr = "/ip4/127.0.0.1/udp/5055/quic-v1".parse().unwrap();
        let addr1_ = addr1.clone();
        let addr3_ = addr3.clone();
        let task_1 = async move {
            swarm_1.listen_on(addr1).unwrap();
            wait_for_incoming_connection(&mut swarm_1, peer_id2).await;

            (0..10usize).for_each(|i| swarm_1.behaviour_mut().send_message(&get_message(i)));

            wait_for_messages(&mut swarm_1, 10..20).await;

            done_1_tx.send(()).await.unwrap();
            swarm_1.loop_on_next().await;
        };
        let task_2 = async move {
            assert_eq!(swarm_2.dial_and_wait(addr1_).await, peer_id1);
            assert_eq!(swarm_2.dial_and_wait(addr3_).await, peer_id3);

            wait_for_messages(&mut swarm_2, 0..20).await;

            done_2_tx.send(()).await.unwrap();
            swarm_2.loop_on_next().await;
        };
        let task_3 = async move {
            swarm_3.listen_on(addr3).unwrap();
            wait_for_incoming_connection(&mut swarm_3, peer_id2).await;
            wait_for_messages(&mut swarm_3, 0..10).await;

            (10..20usize).for_each(|i| swarm_3.behaviour_mut().send_message(&get_message(i)));

            done_3_tx.send(()).await.unwrap();
            swarm_3.loop_on_next().await;
        };

        tokio::spawn(task_1);
        tokio::spawn(task_2);
        tokio::spawn(task_3);

        assert!(
            tokio::time::timeout(
                Duration::from_secs(10),
                futures::future::join3(done_1_rx.recv(), done_2_rx.recv(), done_3_rx.recv()),
            )
                .await
                .is_ok(),
            "Test timed out"
        );
    }

    #[tokio::test]
    async fn test_connects_and_receives_replication_messages() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .compact()
            .with_writer(TestWriter::default())
            .try_init();
        let k1 = Keypair::generate_ed25519();
        let k2 = Keypair::generate_ed25519();
        let peer_id2 = PeerId::from_public_key(&k2.public());

        let neighbours = make_neighbours(&[&k1, &k2]);
        let mut swarm_1 = get_swarm(k1, neighbours.clone());
        let mut swarm_2 = get_swarm(k2, neighbours);

        let msg_count = 10usize;
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/5053/quic-v1".parse().unwrap();
        let addr2 = addr.clone();
        // future that listens for messages and collects `msg_count` of them, then
        // returns them
        let task_1 = async move {
            swarm_1.listen_on(addr.clone()).unwrap();
            wait_for_incoming_connection(&mut swarm_1, peer_id2).await;
            swarm_1
                .filter_map(|event| async {
                    if let SwarmEvent::Behaviour(ReplicationEvent::IncomingMessage {
                                                     message,
                                                     ..
                                                 }) = event
                    {
                        Some(message)
                    } else {
                        None
                    }
                })
                .take(msg_count)
                .collect::<Vec<_>>()
                .await
        };
        let join1 = tokio::spawn(task_1);
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(10);
        let (terminate_sender, mut terminate_receiver) = tokio::sync::oneshot::channel::<()>();
        let task_2 = async move {
            swarm_2.dial_and_wait(addr2).await;
            let mut i = 0usize;
            loop {
                tokio::select! {
                    // send a message everytime that the channel ticks
                    _  = receiver.recv() => {
                        swarm_2.behaviour_mut().send_message(&get_message(i));
                        i += 1;
                    }
                    // print out events
                    event = swarm_2.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished{ peer_id,  connection_id, .. } = event {
                            info!("Connected to {peer_id} with connection_id: {connection_id}");
                        }
                    }
                    // terminate future
                    _ = &mut terminate_receiver => {
                        break;
                    }
                }
            }
        };
        let join2 = tokio::spawn(task_2);
        // send 10 messages
        for _ in 0..10 {
            sender.send(()).await.unwrap();
        }
        // await for task1 to have all messages, then terminate task 2
        tokio::select! {
            Ok(res) = join1 => {
                assert_eq!(res.len(), msg_count);
                terminate_sender.send(()).unwrap();
            }
            _ = join2 => {
                panic!("task two should not finish before 1");
            }
        }
    }

    #[tokio::test]
    async fn test_tampered_encrypted_quick_packet_detection() {
        // Components:
        //  - Swarm1 - message receiver
        //  - Swarm2 - message sender
        //  - UDP proxy which detects encrypted QUICK packets and modifies their payload
        // Steps:
        //   - Start UDP proxy
        //   - Start Swarm1 at proxy_addr and wait for connection
        //   - Start Swarm2 and connect to server_addr
        //   - Swarm2 receives connection acknowledgement
        //   - Connection Swarm1 <-> Proxy <-> Swarm2 is established
        //   - Swarm2 sends 10 messages to Swarm1
        //   - UDP proxy alters QUICK packets' payload
        // Expected result:
        //   - At first, connection between Swarm1 and Swarm2 is successfully
        //     established
        //   - Swarm1 never receives any messages(data) as they get altered
        //   -> We have confirmed that man-in-the-middle attack at transport level has
        // failed
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .compact()
            .with_writer(TestWriter::default())
            .try_init();
        let k1 = Keypair::generate_ed25519();
        let k2 = Keypair::generate_ed25519();
        let peer_id2 = PeerId::from_public_key(&k2.public());

        let neighbours = make_neighbours(&[&k1, &k2]);

        let proxy_addr: Multiaddr = "/ip4/127.0.0.1/udp/5058".parse().unwrap();
        let server_addr: Multiaddr = "/ip4/127.0.0.1/udp/5059".parse().unwrap();

        // Start UDP proxy
        tokio::spawn(start_udp_mutation_proxy(
            proxy_addr.clone(),
            server_addr.clone(),
        ));

        // Wait for roxy to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let addr: Multiaddr = format!("{server_addr}/quic-v1").parse().unwrap();
        let addr2: Multiaddr = format!("{proxy_addr}/quic-v1").parse().unwrap();

        let msg_count = 10usize;
        let mut swarm_1 = get_swarm(k1.clone(), neighbours.clone());
        let mut swarm_2 = get_swarm(k2.clone(), neighbours.clone());

        let (cancel_tx, mut cancel_rx) = watch::channel(false);

        let task_1 = tokio::spawn(async move {
            swarm_1.listen_on(addr.clone()).unwrap();
            wait_for_incoming_connection(&mut swarm_1, peer_id2).await;

            let mut received_count = 0;

            loop {
                tokio::select! {
                    event = swarm_1.select_next_some() => {
                        if let SwarmEvent::Behaviour(ReplicationEvent::IncomingMessage {
                            ..
                        }) = event {
                            received_count += 1;
                        }
                    }
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow() {
                            break;
                        }
                    }
                }

                if received_count >= msg_count {
                    break;
                }
            }
            received_count
        });

        let task_2 = async move {
            swarm_2.dial(addr2).unwrap();

            let mut i = 0;
            let mut swarms_connected = false;
            loop {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(50)) => {
                        let behaviour = swarm_2.behaviour_mut();
                        let msg = get_message(i);
                        behaviour.send_message(&msg);
                        i += 1;
                        if i >= msg_count { break; }
                    }
                    event = swarm_2.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionClosed { .. } => break,
                            SwarmEvent::ConnectionEstablished { peer_id,  connection_id, .. } => {
                                info!("Connected to {peer_id} with connection_id: {connection_id}");
                                swarms_connected = true;
                            },
                            _ => {}
                        }
                    }
                }
            }
            swarms_connected
        };

        // Wait for sender to send all 10 messages, check it has connected to the
        // receiving swarm
        let swarms_connected = task_2.await;
        assert!(swarms_connected);

        // Stop receiving task
        let _ = cancel_tx.send(true);

        // Check swarm 1 has not received any messages -> transport failed
        match task_1.await {
            Ok(count) => assert_ne!(count, 9),
            Err(e) => error!("Task1 - message receiver failed with {e}"),
        }
    }

    #[tokio::test]
    async fn test_tampered_message_content_detection() {
        // Components:
        //  - Swarm1 - message receiver
        //  - Swarm2 - message sender based on ReplicationBehaviour wrapper with a hook
        //    tampering messages
        // Steps:
        //   - Start Swarm1
        //   - Start Swarm2
        //   - Swarm2 receives connection acknowledgement
        //   - Connection Swarm1 <-> Swarm2 is established
        //   - Swarm2 sends 10 messages to Swarm1
        //   - Messages sent by Swarm2 are all modified by the tampering hook
        //   - Swarm1 receives 10 altered messages
        // Expected result:
        //   - Connection between Swarm1 and Swarm2 is successfully established
        //   - Swarm1 never receives messages without modification
        //   -> We have confirmed that man-in-the-middle attack at behaviour level is
        // possible
        //   -> Currently this is expected behavior as Nomos doesn't check message
        // integrity
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .compact()
            .with_writer(TestWriter::default())
            .try_init();
        let k1 = Keypair::generate_ed25519();
        let k2 = Keypair::generate_ed25519();
        let peer_id2 = PeerId::from_public_key(&k2.public());

        let neighbours = make_neighbours(&[&k1, &k2]);
        let mut swarm_1 = get_swarm(k1.clone(), neighbours.clone());

        let mut swarm_2_tampered = libp2p::SwarmBuilder::with_existing_identity(k2.clone())
            .with_tokio()
            .with_other_transport(|_keypair| quic::tokio::Transport::new(quic::Config::new(&k2)))
            .unwrap()
            .with_behaviour(|key| {
                let base = ReplicationBehaviour::new(
                    ReplicationConfig {
                        seen_message_cache_size: 100,
                        seen_message_ttl: Duration::from_secs(60),
                    },
                    PeerId::from_public_key(&key.public()),
                    neighbours.clone(),
                );
                let mut behaviour = TamperingReplicationBehaviour::new(base);
                behaviour.set_tamper_hook(|mut msg| {
                    msg.share.data.share_idx ^= 0xFF;
                    msg
                });
                behaviour
            })
            .unwrap()
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(10)))
            .build();

        let msg_count = 10usize;
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/5061/quic-v1".parse().unwrap();
        let addr2 = addr.clone();

        let task_1 = tokio::spawn(async move {
            swarm_1.listen_on(addr.clone()).unwrap();
            wait_for_incoming_connection(&mut swarm_1, peer_id2).await;

            let mut received_messages = 0;
            let mut all_messages_tampered = true;
            loop {
                if let SwarmEvent::Behaviour(ReplicationEvent::IncomingMessage {
                                                 message, ..
                                             }) = swarm_1.select_next_some().await
                {
                    received_messages += 1;
                    // Check all messages were tampered
                    if message.share.data.share_idx == 0 {
                        all_messages_tampered = false;
                    }
                    if received_messages >= msg_count {
                        break;
                    }
                }
            }
            (received_messages, all_messages_tampered)
        });

        let task_2 = async move {
            swarm_2_tampered.dial(addr2).unwrap();

            // Send 10 tampered messages after attempting a connection
            let mut i = 0;
            let mut swarms_connected = false;
            loop {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(50)) => {
                        let behaviour = swarm_2_tampered.behaviour_mut();
                        let msg = get_message(i);
                        behaviour.send_message(&msg);
                        i += 1;
                    }
                    event = swarm_2_tampered.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionClosed { .. } => break,
                            SwarmEvent::ConnectionEstablished { peer_id,  connection_id, .. } => {
                                info!("Connected to {peer_id} with connection_id: {connection_id}");
                                swarms_connected = true;
                            },
                            _ => {}
                        }
                    }
                }
            }
            swarms_connected
        };

        // Wait for sender to send all 10 messages, check it has connected to the
        // receiving swarm
        let swarms_connected = task_2.await;
        assert!(swarms_connected);

        // Wait for message receiver
        let task_1_result = task_1.await;

        let (received_messages, all_messages_tampered) = task_1_result.unwrap();
        assert_eq!(received_messages, msg_count);
        assert!(all_messages_tampered);
    }
}
