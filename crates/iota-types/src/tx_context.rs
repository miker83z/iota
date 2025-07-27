// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

use enum_dispatch::enum_dispatch;
use move_binary_format::{CompiledModule, file_format::SignatureToken};
use move_bytecode_utils::resolve_struct;
use move_core_types::{account_address::AccountAddress, ident_str, identifier::IdentStr};
use serde::{Deserialize, Serialize};

use crate::{
    IOTA_FRAMEWORK_ADDRESS,
    base_types::{IotaAddress, ObjectID},
    epoch_data::EpochData,
    error::{ExecutionError, ExecutionErrorKind},
    messages_checkpoint::CheckpointTimestamp,
};
pub use crate::{
    committee::EpochId,
    digests::{ObjectDigest, TransactionDigest, TransactionEffectsDigest},
};

pub const TX_CONTEXT_MODULE_NAME: &IdentStr = ident_str!("tx_context");
pub const TX_CONTEXT_STRUCT_NAME: &IdentStr = ident_str!("TxContext");

#[enum_dispatch(TxContextAPI)]
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum TxContext {
    V1(TxContextV1),
    V2(TxContextV2),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxContextV1 {
    /// Signer/sender of the transaction
    sender: AccountAddress,
    /// Digest of the current transaction
    digest: Vec<u8>,
    /// The current epoch number
    epoch: EpochId,
    /// Timestamp that the epoch started at
    epoch_timestamp_ms: CheckpointTimestamp,
    /// Number of `ObjectID`'s generated during execution of the current
    /// transaction
    ids_created: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TxContextV2 {
    /// Signer/sender of the transaction
    sender: AccountAddress,
    /// Digest of the current transaction
    digest: Vec<u8>,
    /// The current epoch number
    epoch: EpochId,
    /// Timestamp that the epoch started at
    epoch_timestamp_ms: CheckpointTimestamp,
    /// Number of `ObjectID`'s generated during execution of the current
    /// transaction
    ids_created: u64,
    // gas price passed to transaction as input
    gas_price: u64,
    // gas budget passed to transaction as input
    gas_budget: u64,
    // address of the sponsor if any
    sponsor: Option<AccountAddress>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum TxContextKind {
    // No TxContext
    None,
    // &mut TxContext
    Mutable,
    // &TxContext
    Immutable,
}

impl TxContext {
    pub fn new(
        sender: &IotaAddress,
        digest: &TransactionDigest,
        epoch_id: &EpochId,
        epoch_timestamp_ms: u64,
        gas_price: u64,
        gas_budget: u64,
        sponsor: Option<IotaAddress>,
    ) -> Self {
        Self::V2(TxContextV2::new_from_components(
            sender,
            digest,
            epoch_id,
            epoch_timestamp_ms,
            gas_price,
            gas_budget,
            sponsor,
        ))
    }

    pub fn new_v1(
        sender: &IotaAddress,
        digest: &TransactionDigest,
        epoch_id: &EpochId,
        epoch_timestamp_ms: u64,
    ) -> Self {
        Self::V1(TxContextV1::new_from_components(
            sender,
            digest,
            epoch_id,
            epoch_timestamp_ms,
        ))
    }

    pub fn random_v1_for_testing_only() -> Self {
        Self::V1(TxContextV1::random_for_testing_only())
    }

    /// Updates state of the context instance. It's intended to use
    /// when mutable context is passed over some boundary via
    /// serialize/deserialize and this is the reason why this method
    /// consumes the other context..
    pub fn update_state(&mut self, other: TxContext) -> Result<(), ExecutionError> {
        if self.sender() != other.sender()
            || self.digest() != other.digest()
            || other.ids_created() < self.ids_created()
        {
            return Err(ExecutionError::new_with_source(
                ExecutionErrorKind::InvariantViolation,
                "Immutable fields for TxContext changed",
            ));
        }
        self.set_ids(other.ids_created());
        Ok(())
    }

    /// Returns whether the type signature is &mut TxContext, &TxContext, or
    /// none of the above.
    pub fn kind(view: &CompiledModule, s: &SignatureToken) -> TxContextKind {
        use SignatureToken as S;
        let (kind, s) = match s {
            S::MutableReference(s) => (TxContextKind::Mutable, s),
            S::Reference(s) => (TxContextKind::Immutable, s),
            _ => return TxContextKind::None,
        };

        let S::Datatype(idx) = &**s else {
            return TxContextKind::None;
        };

        let (module_addr, module_name, struct_name) = resolve_struct(view, *idx);
        let is_tx_context_type = module_name == TX_CONTEXT_MODULE_NAME
            && module_addr == &IOTA_FRAMEWORK_ADDRESS
            && struct_name == TX_CONTEXT_STRUCT_NAME;

        if is_tx_context_type {
            kind
        } else {
            TxContextKind::None
        }
    }
}

impl TxContextAPI for TxContextV1 {
    fn sender(&self) -> IotaAddress {
        IotaAddress::from(self.sender)
    }

    /// Return the transaction digest, to include in new objects
    fn digest(&self) -> TransactionDigest {
        TransactionDigest::new(self.digest.clone().try_into().unwrap())
    }

    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn epoch_timestamp_ms(&self) -> CheckpointTimestamp {
        self.epoch_timestamp_ms
    }

    fn ids_created(&self) -> u64 {
        self.ids_created
    }

    fn gas_price(&self) -> u64 {
        unimplemented!("Not supported by V1");
    }

    fn gas_budget(&self) -> u64 {
        unimplemented!("Not supported by V1");
    }

    fn sponsor(&self) -> Option<IotaAddress> {
        unimplemented!("Not supported by V1");
    }

    /// Derive a globally unique object ID by hashing self.digest |
    /// self.ids_created
    fn fresh_id(&mut self) -> ObjectID {
        let id = ObjectID::derive_id(self.digest(), self.ids_created);

        self.ids_created += 1;
        id
    }

    fn to_vec(&self) -> Vec<u8> {
        bcs::to_bytes(&self).unwrap()
    }

    fn set_ids(&mut self, other: u64) {
        self.ids_created = other;
    }
}

impl TxContextV1 {
    pub fn new_from_components(
        sender: &IotaAddress,
        digest: &TransactionDigest,
        epoch_id: &EpochId,
        epoch_timestamp_ms: u64,
    ) -> Self {
        Self {
            sender: AccountAddress::new(sender.to_inner()),
            digest: digest.into_inner().to_vec(),
            epoch: *epoch_id,
            epoch_timestamp_ms,
            ids_created: 0,
        }
    }

    // Generate a random TxContext for testing.
    fn random_for_testing_only() -> Self {
        let epoch_data = &EpochData::new_test();
        Self::new_from_components(
            &IotaAddress::random_for_testing_only(),
            &TransactionDigest::random(),
            &epoch_data.epoch_id(),
            epoch_data.epoch_start_timestamp(),
        )
    }
}

impl TxContextAPI for TxContextV2 {
    fn sender(&self) -> IotaAddress {
        IotaAddress::from(self.sender)
    }

    /// Return the transaction digest, to include in new objects
    fn digest(&self) -> TransactionDigest {
        TransactionDigest::new(self.digest.clone().try_into().unwrap())
    }

    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn epoch_timestamp_ms(&self) -> CheckpointTimestamp {
        self.epoch_timestamp_ms
    }

    fn ids_created(&self) -> u64 {
        self.ids_created
    }

    fn gas_price(&self) -> u64 {
        self.gas_price
    }

    fn gas_budget(&self) -> u64 {
        self.gas_budget
    }

    fn sponsor(&self) -> Option<IotaAddress> {
        self.sponsor.map(IotaAddress::from)
    }

    /// Derive a globally unique object ID by hashing self.digest |
    /// self.ids_created
    fn fresh_id(&mut self) -> ObjectID {
        let id = ObjectID::derive_id(self.digest(), self.ids_created);

        self.ids_created += 1;
        id
    }

    fn to_vec(&self) -> Vec<u8> {
        bcs::to_bytes(&self).unwrap()
    }

    fn set_ids(&mut self, other: u64) {
        self.ids_created = other;
    }
}

impl TxContextV2 {
    pub fn new_from_components(
        sender: &IotaAddress,
        digest: &TransactionDigest,
        epoch_id: &EpochId,
        epoch_timestamp_ms: u64,
        gas_price: u64,
        gas_budget: u64,
        sponsor: Option<IotaAddress>,
    ) -> Self {
        Self {
            sender: AccountAddress::new(sender.to_inner()),
            digest: digest.into_inner().to_vec(),
            epoch: *epoch_id,
            epoch_timestamp_ms,
            ids_created: 0,
            gas_price,
            gas_budget,
            sponsor: sponsor.map(|s| s.into()),
        }
    }
}

#[enum_dispatch]
pub trait TxContextAPI {
    fn sender(&self) -> IotaAddress;
    fn digest(&self) -> TransactionDigest;
    fn epoch(&self) -> EpochId;
    fn epoch_timestamp_ms(&self) -> CheckpointTimestamp;
    fn ids_created(&self) -> u64;
    fn gas_price(&self) -> u64;
    fn gas_budget(&self) -> u64;
    fn sponsor(&self) -> Option<IotaAddress>;
    /// Derive a globally unique object ID by hashing self.digest |
    /// self.ids_created
    fn fresh_id(&mut self) -> ObjectID;
    fn to_vec(&self) -> Vec<u8>;
    fn set_ids(&mut self, other: u64);
}
