use blake2::{digest::consts::U32, Blake2b, Digest as _};
use kzgrs::Proof;
use nomos_core::da::blob;
use serde::{Deserialize, Serialize};

use super::{build_blob_id, ShareIndex};
use crate::common::{
    deserialize_canonical, deserialize_vec_canonical, serialize_canonical, serialize_vec_canonical,
    Column, Commitment,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaShare {
    pub column: Column,
    pub share_idx: ShareIndex,
    #[serde(
        serialize_with = "serialize_canonical",
        deserialize_with = "deserialize_canonical"
    )]
    pub combined_column_proof: Proof,
    #[serde(
        serialize_with = "serialize_vec_canonical",
        deserialize_with = "deserialize_vec_canonical"
    )]
    pub rows_commitments: Vec<Commitment>,
}

impl DaShare {
    #[must_use]
    pub fn blob_id(&self) -> Vec<u8> {
        build_blob_id(&self.rows_commitments).into()
    }

    #[must_use]
    pub fn column_id(&self) -> Vec<u8> {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(self.column.as_bytes());
        hasher.finalize().as_slice().to_vec()
    }

    #[must_use]
    pub fn column_len(&self) -> usize {
        self.column.as_bytes().len()
    }
}

impl blob::Share for DaShare {
    type BlobId = [u8; 32];
    type ShareIndex = [u8; 2];
    type LightShare = DaLightShare;
    type SharesCommitments = DaSharesCommitments;

    fn blob_id(&self) -> Self::BlobId {
        self.blob_id()
            .try_into()
            .expect("Blob ID should be 32 bytes")
    }

    fn share_idx(&self) -> Self::ShareIndex {
        self.share_idx.to_be_bytes()
    }

    fn into_share_and_commitments(self) -> (Self::LightShare, Self::SharesCommitments) {
        (
            DaLightShare {
                share_idx: self.share_idx,
                column: self.column,
                combined_column_proof: self.combined_column_proof,
            },
            DaSharesCommitments {
                rows_commitments: self.rows_commitments,
            },
        )
    }

    fn from_share_and_commitments(
        light_share: Self::LightShare,
        shares_commitments: Self::SharesCommitments,
    ) -> Self {
        Self {
            column: light_share.column,
            share_idx: light_share.share_idx,
            combined_column_proof: light_share.combined_column_proof,
            rows_commitments: shares_commitments.rows_commitments,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaLightShare {
    pub share_idx: ShareIndex,
    pub column: Column,
    #[serde(
        serialize_with = "serialize_canonical",
        deserialize_with = "deserialize_canonical"
    )]
    pub combined_column_proof: Proof,
}

impl blob::LightShare for DaLightShare {
    type ShareIndex = [u8; 2];

    fn share_idx(&self) -> Self::ShareIndex {
        self.share_idx.to_be_bytes()
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaSharesCommitments {
    #[serde(
        serialize_with = "serialize_vec_canonical",
        deserialize_with = "deserialize_vec_canonical"
    )]
    pub rows_commitments: Vec<Commitment>,
}
