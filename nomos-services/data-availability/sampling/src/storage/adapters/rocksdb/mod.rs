use std::{marker::PhantomData, path::PathBuf};

use nomos_core::da::blob::Share;
use nomos_storage::{
    api::da::DaConverter,
    backends::{rocksdb::RocksBackend, StorageSerde},
    StorageMsg, StorageService,
};
use overwatch::{
    services::{relay::OutboundRelay, ServiceData},
    DynError,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::storage::DaStorageAdapter;

pub mod converter;

pub struct RocksAdapter<B, S, Converter>
where
    S: StorageSerde + Send + Sync + 'static,
{
    storage_relay: OutboundRelay<StorageMsg<RocksBackend<S>>>,
    share: PhantomData<B>,
    converter: PhantomData<Converter>,
}

#[async_trait::async_trait]
impl<B, S, Converter, RuntimeServiceId> DaStorageAdapter<RuntimeServiceId>
    for RocksAdapter<B, S, Converter>
where
    S: StorageSerde + Send + Sync + 'static,
    Converter: DaConverter<RocksBackend<S>, Share = B> + Send + Sync + 'static,
    B: Share + DeserializeOwned + Clone + Send + Sync + 'static,
    B::BlobId: Send + Sync + 'static,
    B::ShareIndex: Send + Sync + 'static,
    B::LightShare: DeserializeOwned + Clone + Send + Sync + 'static,
    B::SharesCommitments: DeserializeOwned + Clone + Send + Sync + 'static,
{
    type Backend = RocksBackend<S>;

    type Share = B;
    type Settings = RocksAdapterSettings;

    async fn new(
        storage_relay: OutboundRelay<
            <StorageService<Self::Backend, RuntimeServiceId> as ServiceData>::Message,
        >,
    ) -> Self {
        Self {
            storage_relay,
            share: PhantomData,
            converter: PhantomData,
        }
    }

    async fn get_commitments(
        &self,
        blob_id: <Self::Share as Share>::BlobId,
    ) -> Result<Option<<Self::Share as Share>::SharesCommitments>, DynError> {
        let (sc_reply_tx, sc_reply_rx) = tokio::sync::oneshot::channel();
        self.storage_relay
            .send(StorageMsg::get_shared_commitments_request::<Converter>(
                blob_id,
                sc_reply_tx,
            )?)
            .await
            .expect("Failed to send load request to storage relay");

        let shared_commitments = sc_reply_rx.await?;
        let shared_commitments = shared_commitments
            .map(|sc| Converter::commitments_from_storage(sc))
            .transpose()
            .map_err(DynError::from)?;

        Ok(shared_commitments)
    }

    async fn get_light_share(
        &self,
        blob_id: <Self::Share as Share>::BlobId,
        share_idx: <Self::Share as Share>::ShareIndex,
    ) -> Result<Option<<Self::Share as Share>::LightShare>, DynError> {
        let (reply_channel, reply_rx) = tokio::sync::oneshot::channel();
        self.storage_relay
            .send(StorageMsg::get_light_share_request::<Converter>(
                blob_id,
                share_idx,
                reply_channel,
            )?)
            .await
            .expect("Failed to send request to storage relay");

        let result = reply_rx.await.map_err(DynError::from)?;
        result
            .map(|data| Converter::share_from_storage(data))
            .transpose()
            .map_err(DynError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocksAdapterSettings {
    pub blob_storage_directory: PathBuf,
}
