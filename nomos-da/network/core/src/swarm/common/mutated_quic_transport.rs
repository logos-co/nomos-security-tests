use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::poll_fn;
use futures::prelude::*;
use libp2p::core::muxing::StreamMuxer as _;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::core::{multiaddr::Multiaddr, PeerId};
use libp2p::quic::{tokio::Transport as QuicTransport, Config, Connection, Error, Stream};
use rand::{thread_rng, Rng as _};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Receiver, Sender};

// Mock DA layer types (replace with Nomos's actual DA types)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaShare {
    data: Bytes,
    merkle_proof: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaMessage {
    shares: Vec<DaShare>,
}

// Trait for mutating DA layer payloads
pub trait DaMutator: Send + Sync + Clone + 'static {
    fn mutate_da_message(&self, message: &mut DaMessage);
    fn process_incoming_da_message(&self, message: &mut DaMessage) -> bool;
}

// Trait for low-level packet mutation
pub trait PacketMutator: Send + Sync + Clone + 'static {
    fn mutate_outgoing(&self, data: &mut BytesMut);
    fn process_incoming(&self, data: &mut BytesMut) -> bool;
}

// Dynamic bit-flip mutator for QUIC packets
#[derive(Clone)]
pub struct DynamicBitFlipMutator {
    byte_index: usize,
    bit_position: u8,
    control_tx: Sender<(usize, u8)>,
}

impl DynamicBitFlipMutator {
    pub fn new(byte_index: usize, bit_position: u8) -> (Self, Receiver<(usize, u8)>) {
        let (control_tx, control_rx) = mpsc::channel(100);
        (
            Self {
                byte_index,
                bit_position,
                control_tx,
            },
            control_rx,
        )
    }

    pub async fn update_parameters(&self, byte_index: usize, bit_position: u8) -> io::Result<()> {
        self.control_tx
            .send((byte_index, bit_position))
            .await
            .map_err(|_e| io::Error::other("bitflip control channel closed"))
    }
}

impl PacketMutator for DynamicBitFlipMutator {
    fn mutate_outgoing(&self, data: &mut BytesMut) {
        if data.len() > self.byte_index {
            data[self.byte_index] ^= 1 << self.bit_position;
        }
    }

    fn process_incoming(&self, data: &mut BytesMut) -> bool {
        if data.len() > self.byte_index {
            data[self.byte_index] ^= 1 << self.bit_position;
            true
        } else {
            false
        }
    }
}

// DA-specific mutator for corrupting shares or proofs
#[derive(Clone)]
pub struct DaBitFlipMutator {
    corruption_probability: f64,
}

impl DaBitFlipMutator {
    pub const fn new(corruption_probability: f64) -> Self {
        Self {
            corruption_probability,
        }
    }
}

impl DaMutator for DaBitFlipMutator {
    fn mutate_da_message(&self, message: &mut DaMessage) {
        let mut rng = thread_rng();
        for share in &mut message.shares {
            if rng.gen::<f64>() < self.corruption_probability {
                let mut data = BytesMut::from(share.data.as_ref());
                if !data.is_empty() {
                    let index = rng.gen_range(0..data.len());
                    data[index] ^= 1;
                    share.data = data.freeze();
                }
            }
        }
    }

    fn process_incoming_da_message(&self, message: &mut DaMessage) -> bool {
        let mut rng = thread_rng();
        for _share in &mut message.shares {
            if rng.gen::<f64>() < self.corruption_probability {
                return false;
            }
        }
        true
    }
}

// Mutated QUIC Transport with DA layer mutation
pub struct MutatedQuicTransport<M: PacketMutator, D: DaMutator> {
    inner: QuicTransport,
    packet_mutator: M,
    da_mutator: D,
    control_rx: Option<Receiver<(usize, u8)>>,
}

impl<M: PacketMutator, D: DaMutator> MutatedQuicTransport<M, D> {
    pub fn new(
        config: Config,
        packet_mutator: M,
        da_mutator: D,
        control_rx: Option<Receiver<(usize, u8)>>,
    ) -> Self {
        Self {
            inner: QuicTransport::new(config),
            packet_mutator,
            da_mutator,
            control_rx,
        }
    }

    pub fn spawn_mutator_control(&mut self) -> io::Result<()> {
        self.control_rx.take().map_or_else(
            || Err(io::Error::other("No control channel provided")),
            |mut control_rx| {
                tokio::spawn(async move {
                    while let Some((byte_index, bit_position)) = control_rx.recv().await {
                        log::info!(
                            "Updated packet mutator: byte_index={byte_index}, bit_position={bit_position}");
                    }
                });
                Ok(())
            },
        )
    }
}

// Helper functions for stream handling
async fn open_outbound_stream(conn: &mut Connection) -> io::Result<Stream> {
    let mut pinned_conn = Pin::new(conn);
    poll_fn(|cx| pinned_conn.as_mut().poll_outbound(cx))
        .await
        .map_err(io::Error::other)
}

async fn accept_inbound_stream(conn: &mut Connection) -> io::Result<Stream> {
    let mut pinned_conn = Pin::new(conn);
    poll_fn(|cx| pinned_conn.as_mut().poll_inbound(cx))
        .await
        .map_err(io::Error::other)
}

// Helper function to map libp2p::quic::Error to io::Error
fn map_quic_error(error: Error) -> io::Error {
    match error {
        Error::Io(e) => e,
        Error::Connection(e) => io::Error::other(format!("QUIC connection error: {e}")),
        Error::Reach(e) => io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("QUIC reach error: {e}"),
        ),
        Error::HandshakeTimedOut => io::Error::new(
            io::ErrorKind::TimedOut,
            "QUIC handshake timed out",
        ),
        Error::NoActiveListenerForDialAsListener => io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "No active listener for dial as listener",
        ),
        Error::HolePunchInProgress(addr) => {
            io::Error::other(format!("QUIC hole punch in progress for address: {addr}"))
        }
    }
}

// Mutated dialer for QUIC connections
pub struct MutatedDial<M: PacketMutator, D: DaMutator> {
    inner: <QuicTransport as Transport>::Dial,
    packet_mutator: M,
    da_mutator: D,
}

impl<M: PacketMutator + Unpin, D: DaMutator + Unpin> Future for MutatedDial<M, D> {
    type Output = Result<(PeerId, Connection), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Reference fields to ensure they are used
        let _ = &this.packet_mutator;
        let _ = &this.da_mutator;
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok((peer_id, conn))) => Poll::Ready(Ok((peer_id, conn))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_quic_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Mutated upgrade for QUIC connections
pub struct MutatedUpgrade<M: PacketMutator, D: DaMutator> {
    inner: <QuicTransport as Transport>::ListenerUpgrade,
    packet_mutator: M,
    da_mutator: D,
}

impl<M: PacketMutator + Unpin, D: DaMutator + Unpin> Future for MutatedUpgrade<M, D> {
    type Output = Result<(PeerId, Connection), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Reference fields to ensure they are used
        let _ = &this.packet_mutator;
        let _ = &this.da_mutator;
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok((peer_id, conn))) => Poll::Ready(Ok((peer_id, conn))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_quic_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
impl<M: PacketMutator + Unpin, D: DaMutator + Unpin> Transport for MutatedQuicTransport<M, D> {
    type Output = (PeerId, Connection);
    type Error = io::Error;
    type ListenerUpgrade = MutatedUpgrade<M, D>;
    type Dial = MutatedDial<M, D>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr).map_err(|e| match e {
            TransportError::MultiaddrNotSupported(addr) => {
                TransportError::MultiaddrNotSupported(addr)
            }
            TransportError::Other(e) => TransportError::Other(map_quic_error(e)),
        })
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let dial = self.inner.dial(addr, opts).map_err(|e| match e {
            TransportError::MultiaddrNotSupported(addr) => {
                TransportError::MultiaddrNotSupported(addr)
            }
            TransportError::Other(e) => TransportError::Other(map_quic_error(e)),
        })?;
        Ok(MutatedDial {
            inner: dial,
            packet_mutator: self.packet_mutator.clone(),
            da_mutator: self.da_mutator.clone(),
        })
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(event) => {
                let mapped_event = match event {
                    TransportEvent::NewAddress {
                        listener_id,
                        listen_addr,
                    } => TransportEvent::NewAddress {
                        listener_id,
                        listen_addr,
                    },
                    TransportEvent::AddressExpired {
                        listener_id,
                        listen_addr,
                    } => TransportEvent::AddressExpired {
                        listener_id,
                        listen_addr,
                    },
                    TransportEvent::Incoming {
                        upgrade,
                        listener_id,
                        local_addr,
                        send_back_addr,
                    } => {
                        let mutated_upgrade = MutatedUpgrade {
                            inner: upgrade,
                            packet_mutator: this.packet_mutator.clone(),
                            da_mutator: this.da_mutator.clone(),
                        };
                        TransportEvent::Incoming {
                            upgrade: mutated_upgrade,
                            listener_id,
                            local_addr,
                            send_back_addr,
                        }
                    }
                    TransportEvent::ListenerError { listener_id, error } => {
                        TransportEvent::ListenerError {
                            listener_id,
                            error: map_quic_error(error),
                        }
                    }
                    TransportEvent::ListenerClosed {
                        listener_id,
                        reason,
                    } => TransportEvent::ListenerClosed {
                        listener_id,
                        reason: reason.map_err(map_quic_error),
                    },
                };
                Poll::Ready(mapped_event)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// DA layer behaviour
pub struct DaBehaviour<D: DaMutator> {
    da_mutator: D,
}

impl<D: DaMutator> DaBehaviour<D> {
    pub const fn new(da_mutator: D) -> Self {
        Self { da_mutator }
    }

    pub async fn send_da_message<M: PacketMutator>(
        &self,
        conn: &mut Connection,
        mut message: DaMessage,
        packet_mutator: &M,
    ) -> io::Result<()> {
        self.da_mutator.mutate_da_message(&mut message);
        let serialized = bincode::serialize(&message).map_err(io::Error::other)?;
        let mut serialized = BytesMut::from(serialized.as_slice());
        packet_mutator.mutate_outgoing(&mut serialized);
        if self.da_mutator.process_incoming_da_message(&mut message) {
            let mut stream = open_outbound_stream(conn).await?;
            stream
                .write_all(&serialized)
                .await
                .map_err(io::Error::other)?;
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid DA message",
            ))
        }
    }

    pub async fn receive_da_message<M: PacketMutator>(
        &self,
        conn: &mut Connection,
        packet_mutator: &M,
    ) -> io::Result<DaMessage> {
        let mut stream = accept_inbound_stream(conn).await?;
        let mut buffer = BytesMut::with_capacity(1024);
        loop {
            let mut chunk = vec![0u8; 16384];
            match futures::io::AsyncReadExt::read(&mut stream, &mut chunk).await {
                Ok(0) => break, // EOF
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(io::Error::other(e)),
            }
        }
        if !packet_mutator.process_incoming(&mut buffer) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid packet data",
            ));
        }
        let mut message: DaMessage = bincode::deserialize(&buffer[..])
            .map_err(io::Error::other)?;
        if self.da_mutator.process_incoming_da_message(&mut message) {
            Ok(message)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid DA message",
            ))
        }
    }
}

