use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    hash::Hash,
    io::ErrorKind,
    marker::PhantomData,
};

use bytes::Bytes;
use futures::{stream, Stream, StreamExt as _};
use nomos_core::{
    block::Block,
    da::blob::{LightShare, Share},
    header::HeaderId,
};
use nomos_storage::{
    api::da::DaConverter,
    backends::{rocksdb::RocksBackend, StorageSerde},
    StorageMsg, StorageService,
};
use overwatch::{
    services::{relay::OutboundRelay, AsServiceId, ServiceData},
    DynError,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::oneshot;

use crate::{http::storage::StorageAdapter, wait_with_timeout};

pub struct RocksAdapter<StorageOp, RuntimeServiceId>
where
    StorageOp: StorageSerde + Send + Sync + 'static,
{
    _storage_op: PhantomData<StorageOp>,
    _runtime_service_id: PhantomData<RuntimeServiceId>,
}

impl<StorageOp, RuntimeServiceId> RocksAdapter<StorageOp, RuntimeServiceId>
where
    StorageOp: StorageSerde + Send + Sync + 'static,
    <StorageOp as StorageSerde>::Error: Send + Sync,
    RuntimeServiceId: Debug + Sync + Display,
{
    async fn load_blob_shares_indices<Converter, DaShare>(
        storage_relay: &OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        blob_id: DaShare::BlobId,
    ) -> Result<HashSet<DaShare::ShareIndex>, crate::http::DynError>
    where
        Converter: DaConverter<RocksBackend<StorageOp>, Share = DaShare> + Send + Sync + 'static,
        DaShare: Share,
        DaShare::BlobId: Send + Sync + 'static,
        DaShare::ShareIndex: DeserializeOwned + Hash + Eq,
    {
        let (index_tx, index_rx) = oneshot::channel();
        storage_relay
            .send(StorageMsg::get_light_share_indexes_request::<Converter>(
                blob_id, index_tx,
            )?)
            .await
            .map_err(|(e, _)| Box::new(e) as crate::http::DynError)?;

        index_rx
            .await
            .map(|indexes| {
                indexes.map(|data| {
                    data.into_iter()
                        .map(|idx| Converter::share_index_from_storage(idx).unwrap())
                        .collect::<HashSet<_>>()
                })
            })
            .map_err(|e| Box::new(e) as crate::http::DynError)?
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    ErrorKind::NotFound,
                    "Blob index not found",
                )) as crate::http::DynError
            })
    }

    async fn load_and_process_share<Converter, DaShare>(
        storage_relay: OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        blob_id: <DaShare as Share>::BlobId,
        share_idx: DaShare::ShareIndex,
    ) -> Result<Bytes, crate::http::DynError>
    where
        Converter: DaConverter<RocksBackend<StorageOp>, Share = DaShare> + Send + Sync + 'static,
        DaShare: Share,
        DaShare::BlobId: Send + Sync + 'static,
        DaShare::LightShare: Serialize + DeserializeOwned,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        storage_relay
            .send(StorageMsg::get_light_share_request::<Converter>(
                blob_id, share_idx, reply_tx,
            )?)
            .await
            .map_err(|(e, _)| Box::new(e) as crate::http::DynError)?;

        let share = reply_rx
            .await
            .map_err(|e| Box::new(e) as crate::http::DynError)?
            .ok_or_else(|| {
                Box::new(std::io::Error::new(ErrorKind::NotFound, "Share not found"))
                    as crate::http::DynError
            })?;

        let share = Converter::share_from_storage(share)
            .map_err(|e| Box::new(e) as crate::http::DynError)?;

        let mut json =
            serde_json::to_vec(&share).map_err(|e| Box::new(e) as crate::http::DynError)?;
        json.push(b'\n');

        Ok(Bytes::from(json))
    }
}

#[async_trait::async_trait]
impl<StorageOp, RuntimeServiceId> StorageAdapter<StorageOp, RuntimeServiceId>
    for RocksAdapter<StorageOp, RuntimeServiceId>
where
    StorageOp: StorageSerde + Send + Sync + 'static,
    <StorageOp as StorageSerde>::Error: Send + Sync,
    RuntimeServiceId: Debug + Sync + Display + 'static,
{
    type Backend = RocksBackend<StorageOp>;

    async fn get_light_share<Converter, DaShare>(
        storage_relay: OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        blob_id: <DaShare as Share>::BlobId,
        share_idx: <DaShare as Share>::ShareIndex,
    ) -> Result<Option<<DaShare as Share>::LightShare>, DynError>
    where
        DaShare: Share,
        <DaShare as Share>::BlobId: Send + Sync + 'static,
        <DaShare as Share>::ShareIndex: Send + Sync + 'static,
        <DaShare as Share>::LightShare: DeserializeOwned + Send + Sync + 'static,
        Converter: DaConverter<RocksBackend<StorageOp>, Share = DaShare> + Send + Sync + 'static,
    {
        let (reply_tx, reply_rcv) = oneshot::channel();
        storage_relay
            .send(StorageMsg::get_light_share_request::<Converter>(
                blob_id, share_idx, reply_tx,
            )?)
            .await
            .map_err(|(e, _)| e)?;

        let result = wait_with_timeout(
            reply_rcv,
            "Timeout while waiting for light share".to_owned(),
        )
        .await?;

        result
            .map(|data| Converter::share_from_storage(data))
            .transpose()
            .map_err(DynError::from)
    }

    async fn get_shares<Converter, DaShare>(
        storage_relay: OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        blob_id: DaShare::BlobId,
        requested_shares: HashSet<DaShare::ShareIndex>,
        filter_shares: HashSet<DaShare::ShareIndex>,
        return_available: bool,
    ) -> Result<
        impl Stream<Item = Result<Bytes, crate::http::DynError>> + Send + Sync,
        crate::http::DynError,
    >
    where
        DaShare: Share + 'static,
        DaShare::BlobId: Clone + Send + Sync + 'static,
        DaShare::ShareIndex: DeserializeOwned + Hash + Eq + Send + Sync + 'static,
        DaShare::LightShare: LightShare<ShareIndex = DaShare::ShareIndex>
            + Serialize
            + DeserializeOwned
            + Send
            + Sync
            + 'static,
        Converter: DaConverter<RocksBackend<StorageOp>, Share = DaShare> + Send + Sync + 'static,
        RuntimeServiceId: Debug
            + Sync
            + Display
            + AsServiceId<StorageService<RocksBackend<StorageOp>, RuntimeServiceId>>,
    {
        let shares_indices =
            Self::load_blob_shares_indices::<Converter, DaShare>(&storage_relay, blob_id.clone())
                .await?;

        let filtered_shares = shares_indices.into_iter().filter(move |idx| {
            // If requested_shares contains the index, then ignore the filter_shares
            requested_shares.contains(idx) || (return_available && !filter_shares.contains(idx))
        });

        let stream = stream::iter(filtered_shares).then(move |share_idx| {
            Self::load_and_process_share::<Converter, DaShare>(
                storage_relay.clone(),
                blob_id.clone(),
                share_idx,
            )
        });

        Ok(stream)
    }
    async fn get_shared_commitments<Converter, DaShare>(
        storage_relay: OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        blob_id: <DaShare as Share>::BlobId,
    ) -> Result<Option<<DaShare as Share>::SharesCommitments>, DynError>
    where
        DaShare: Share,
        <DaShare as Share>::BlobId: Send + Sync + 'static,
        <DaShare as Share>::SharesCommitments: DeserializeOwned + Send + Sync + 'static,
        Converter: DaConverter<RocksBackend<StorageOp>, Share = DaShare> + Send + Sync + 'static,
    {
        let (reply_tx, reply_rcv) = oneshot::channel();
        storage_relay
            .send(StorageMsg::get_shared_commitments_request::<Converter>(
                blob_id, reply_tx,
            )?)
            .await
            .map_err(|(e, _)| e)?;

        let result = wait_with_timeout(
            reply_rcv,
            "Timeout while waiting for shared commitments".to_owned(),
        )
        .await?;

        result
            .map(|data| {
                Converter::commitments_from_storage(data)
                    .map_err(|e| Box::new(e) as crate::http::DynError)
            })
            .transpose()
    }

    async fn get_block<Tx>(
        storage_relay: OutboundRelay<
            <StorageService<RocksBackend<StorageOp>, RuntimeServiceId> as ServiceData>::Message,
        >,
        id: HeaderId,
    ) -> Result<Option<Block<Tx, kzgrs_backend::dispersal::BlobInfo>>, crate::http::DynError>
    where
        Tx: Serialize + DeserializeOwned + Clone + Eq + Hash,
    {
        let key: [u8; 32] = id.into();
        let (msg, receiver) = StorageMsg::new_load_message(Bytes::copy_from_slice(&key));
        storage_relay.send(msg).await.map_err(|(e, _)| e)?;

        wait_with_timeout(
            receiver.recv(),
            "Timeout while waiting for block".to_owned(),
        )
        .await
    }
}
