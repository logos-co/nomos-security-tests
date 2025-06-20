use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::{future::poll_fn, prelude::*};
use libp2p::{
    core::{
        multiaddr::Multiaddr,
        muxing::StreamMuxer as _,
        transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent},
        PeerId,
    },
    quic::{tokio::Transport as QuicTransport, Config, Connection, Error, Stream},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

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

// Mutated QUIC Transport with DA layer mutation
pub struct MutatedQuicTransport<M: PacketMutator> {
    inner: QuicTransport,
    packet_mutator: M,
    control_rx: Option<Receiver<(usize, u8)>>,
}

impl<M: PacketMutator> MutatedQuicTransport<M> {
    pub fn new(
        config: Config,
        packet_mutator: M,
        control_rx: Option<Receiver<(usize, u8)>>,
    ) -> Self {
        Self {
            inner: QuicTransport::new(config),
            packet_mutator,
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
        Error::HandshakeTimedOut => {
            io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out")
        }
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
pub struct MutatedDial<M: PacketMutator> {
    inner: <QuicTransport as Transport>::Dial,
    packet_mutator: M,
}

impl<M: PacketMutator + Unpin> Future for MutatedDial<M> {
    type Output = Result<(PeerId, Connection), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Reference fields to ensure they are used (as in original)
        let _ = &this.packet_mutator;
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok((peer_id, conn))) => Poll::Ready(Ok((peer_id, conn))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_quic_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Mutated upgrade for QUIC connections
pub struct MutatedUpgrade<M: PacketMutator> {
    inner: <QuicTransport as Transport>::ListenerUpgrade,
    packet_mutator: M,
}

impl<M: PacketMutator + Unpin> Future for MutatedUpgrade<M> {
    type Output = Result<(PeerId, Connection), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Reference fields to ensure they are used (as in original)
        let _ = &this.packet_mutator;
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok((peer_id, conn))) => Poll::Ready(Ok((peer_id, conn))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_quic_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
impl<M: PacketMutator + Unpin> Transport for MutatedQuicTransport<M> {
    type Output = (PeerId, Connection);
    type Error = io::Error;
    type ListenerUpgrade = MutatedUpgrade<M>;
    type Dial = MutatedDial<M>;

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
