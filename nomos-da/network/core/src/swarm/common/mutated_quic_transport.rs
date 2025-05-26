use async_trait::async_trait;
use bytes::BytesMut;
use libp2p::core::{
    transport::{Transport, TransportError, TransportEvent, ListenerId},
    multiaddr::Multiaddr,
    muxing::StreamMuxerBox,
};
use libp2p::quic::{Config, Connection, Stream};
use libp2p::quic::tokio::Transport as QuicTransport;
use std::io;
use futures::prelude::*;
use tokio::sync::mpsc::{self, Sender, Receiver};

// Trait for defining packet mutation strategies.
pub trait PacketMutator: Send + Sync + 'static {
    // Mutates outgoing packet data.
    fn mutate_outgoing(&self, data: &mut BytesMut);
    // Validates or processes incoming mutated packet data.
    fn process_incoming(&self, data: &mut BytesMut) -> bool;
}

// Dynamic bit-flip mutator controlled via a Tokio channel.
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
            DynamicBitFlipMutator {
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
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

// Mutated QUIC Transport with Tokio-based async.
pub struct MutatedQuicTransport<M: PacketMutator> {
    inner: QuicTransport,
    mutator: M,
    control_rx: Option<Receiver<(usize, u8)>>,
}

impl<M: PacketMutator> MutatedQuicTransport<M> {
    pub fn new(config: Config, mutator: M, control_rx: Option<Receiver<(usize, u8)>>) -> Self {
        MutatedQuicTransport {
            inner: QuicTransport::new(config),
            mutator,
            control_rx,
        }
    }

    // Spawns a Tokio task to handle dynamic mutator updates.
    pub fn spawn_mutator_control(&mut self) -> io::Result<()> {
        if let Some(mut control_rx) = self.control_rx.take() {
            tokio::spawn(async move {
                while let Some((byte_index, bit_position)) = control_rx.recv().await {
                    log::info!("Updated mutator: byte_index={}, bit_position={}", byte_index, bit_position);
                }
            });
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "No control channel provided"))
        }
    }
}

#[async_trait]
impl<M: PacketMutator> Transport for MutatedQuicTransport<M> {
    type Output = (MutatedConnection<M>, StreamMuxerBox);
    type Error = io::Error;
    type Dial = MutatedDial<M>;

    fn listen_on(&mut self, id: ListenerId, addr: Multiaddr) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let dial = self.inner.dial(addr)?;
        Ok(MutatedDial {
            inner: dial,
            mutator: self.mutator,
        })
    }

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<TransportEvent<Self::Output, Self::Error>> {
        match self.inner.poll(cx) {
            std::task::Poll::Ready(event) => {
                let mapped_event = match event {
                    TransportEvent::NewAddress { listener_id, addr } => {
                        TransportEvent::NewAddress { listener_id, addr }
                    }
                    TransportEvent::AddressExpired { listener_id, addr } => {
                        TransportEvent::AddressExpired { listener_id, addr }
                    }
                    TransportEvent::ConnectionEstablished { output: (conn, muxer), listener_id, addr } => {
                        let mutated_conn = MutatedConnection {
                            inner: conn,
                            mutator: self.mutator.clone(),
                        };
                        TransportEvent::ConnectionEstablished {
                            output: (mutated_conn, muxer),
                            listener_id,
                            addr,
                        }
                    }
                    TransportEvent::ListenerError { listener_id, err } => {
                        TransportEvent::ListenerError { listener_id, err }
                    }
                    TransportEvent::ListenerClosed { listener_id, reason } => {
                        TransportEvent::ListenerClosed { listener_id, reason }
                    }
                };
                std::task::Poll::Ready(mapped_event)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Dialer for mutated QUIC connections.
pub struct MutatedDial<M: PacketMutator> {
    inner: <QuicTransport as Transport>::Dial,
    mutator: M,
}

impl<M: PacketMutator> Future for MutatedDial<M> {
    type Output = Result<<MutatedQuicTransport<M> as Transport>::Output, io::Error>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match self.inner.poll_unpin(cx) {
            std::task::Poll::Ready(Ok((conn, muxer))) => {
                let mutated_conn = MutatedConnection {
                    inner: conn,
                    mutator: self.mutator.clone(),
                };
                std::task::Poll::Ready(Ok((mutated_conn, muxer)))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Connection wrapper that applies mutations to streams.
pub struct MutatedConnection<M: PacketMutator> {
    inner: Connection,
    mutator: M,
}

impl<M: PacketMutator> MutatedConnection<M> {
    pub async fn open_stream(&self) -> io::Result<MutatedStream<M>> {
        let stream = self.inner.open_stream().await?;
        Ok(MutatedStream {
            inner: stream,
            mutator: self.mutator.clone(),
        })
    }

    pub async fn accept_stream(&self) -> io::Result<MutatedStream<M>> {
        let stream = self.inner.accept_stream().await?;
        Ok(MutatedStream {
            inner: stream,
            mutator: self.mutator.clone(),
        })
    }
}

// Stream wrapper that applies mutations to data.
pub struct MutatedStream<M: PacketMutator> {
    inner: Stream,
    mutator: M,
}

impl<M: PacketMutator> tokio::io::AsyncWrite for MutatedStream<M> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut data = BytesMut::from(buf);
        self.mutator.mutate_outgoing(&mut data);
        self.inner.poll_write(cx, &data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.inner.poll_close(cx)
    }
}

impl<M: PacketMutator> tokio::io::AsyncRead for MutatedStream<M> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut temp_buf = vec![0u8; buf.remaining()];
        match self.inner.poll_read(cx, &mut temp_buf) {
            std::task::Poll::Ready(Ok(n)) => {
                let mut data = BytesMut::from(&temp_buf[..n]);
                if self.mutator.process_incoming(&mut data) {
                    let data = data.freeze();
                    let len = data.len().min(buf.remaining());
                    buf.put_slice(&data[..len]);
                    std::task::Poll::Ready(Ok(()))
                } else {
                    std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid mutated packet",
                    )))
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}