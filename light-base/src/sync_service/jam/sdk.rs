// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! In-process SDK primitives. No RPC node is consulted; every value is checked
//! against a root from the trusted anchor, a GRANDPA proof, or an authenticated
//! child. The latter is explicitly provisional and requires opt-in.

use super::{
    JamSyncService, State,
    reads::{StateRead, StateReadError, StateReadResult, Trust},
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use smoldot::jam::{
    chain_spec::JamChainSpec, finality::VerifiedFinality, trie::StateRequest, types::Hash,
};

const HISTORY_COUNT: usize = 512;
const HISTORY_BYTES: usize = 4 * 1024 * 1024;
const READ_BYTES: u32 = 32 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Record {
    pub hash: Hash,
    pub parent: Hash,
    pub slot: u32,
    pub root: Hash,
    pub level: &'static str,
    pub encoded: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct SdkState {
    genesis: Hash,
    pub(super) continuous: bool,
    records: BTreeMap<Hash, Record>,
}

impl SdkState {
    pub(super) fn from_spec(spec: &JamChainSpec) -> Self {
        let header = spec.genesis_header();
        let hash = header.hash(spec.params());
        let mut state = Self {
            genesis: hash,
            continuous: spec.jamsdk_disable_warp(),
            records: BTreeMap::new(),
        };
        if let Some(root) = spec.genesis_state_root() {
            state.remember(Record {
                hash,
                parent: header.parent,
                slot: header.slot,
                root,
                level: "trusted_anchor",
                encoded: header.encode(spec.params()),
            });
        }
        if let Some(checkpoint) = spec.checkpoint()
            && let Some(root) = checkpoint.state_root
        {
            let header = &checkpoint.header;
            state.remember(Record {
                hash: header.hash(spec.params()),
                parent: header.parent,
                slot: header.slot,
                root,
                level: "trusted_anchor",
                encoded: header.encode(spec.params()),
            });
        }
        state
    }

    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            genesis: [0; 32],
            continuous: false,
            records: BTreeMap::new(),
        }
    }

    pub(super) fn certified_root(&self, hash: &Hash) -> Option<Hash> {
        self.records.get(hash).map(|r| r.root)
    }

    pub(super) fn remember(&mut self, record: Record) {
        self.records.insert(record.hash, record);
        while self.records.len() > HISTORY_COUNT
            || self
                .records
                .values()
                .map(|r| r.encoded.len())
                .sum::<usize>()
                > HISTORY_BYTES
        {
            let Some(hash) = self
                .records
                .values()
                .min_by_key(|r| (r.slot, r.hash))
                .map(|r| r.hash)
            else {
                break;
            };
            self.records.remove(&hash);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SdkError {
    pub code: i32,
    pub message: &'static str,
}
fn invalid() -> SdkError {
    SdkError {
        code: -32602,
        message: "invalid JAM SDK parameters",
    }
}
fn unavailable() -> SdkError {
    SdkError {
        code: -32040,
        message: "verification unavailable for exact block",
    }
}
fn unknown() -> SdkError {
    SdkError {
        code: -32801,
        message: "historical header unavailable",
    }
}
fn b64<const N: usize>(value: &Value) -> Result<[u8; N], SdkError> {
    let text = value.as_str().ok_or_else(invalid)?;
    let bytes = STANDARD.decode(text).map_err(|_| invalid())?;
    if STANDARD.encode(&bytes) != text {
        return Err(invalid());
    }
    bytes.try_into().map_err(|_| invalid())
}
fn flag(value: &Value) -> Result<bool, SdkError> {
    value.as_bool().ok_or_else(invalid)
}

pub(super) struct Request {
    pub method: String,
    pub params: Value,
    pub send_back: futures_channel::oneshot::Sender<Result<QueryResult, SdkError>>,
}
pub(super) enum QueryResult {
    Value(Value),
    Read {
        receiver: futures_channel::oneshot::Receiver<Result<StateReadResult, StateReadError>>,
        at: Hash,
        root: Hash,
        key: [u8; 31],
        allow: bool,
    },
}

impl JamSyncService {
    /// Dropping the request future drops the receiver owning any pending CE129
    /// query. The driver's next reservation/response releases that exact read.
    pub(crate) async fn sdk_request(
        &self,
        method: String,
        params: Value,
    ) -> Result<Value, SdkError> {
        let (send_back, response) = futures_channel::oneshot::channel();
        self.to_sdk
            .as_ref()
            .ok_or_else(unavailable)?
            .send(Request {
                method,
                params,
                send_back,
            })
            .await
            .map_err(|_| unavailable())?;
        match response.await.map_err(|_| unavailable())?? {
            QueryResult::Value(value) => Ok(value),
            QueryResult::Read {
                receiver,
                at,
                root,
                key,
                allow,
            } => {
                let answer =
                    receiver
                        .await
                        .map_err(|_| unavailable())?
                        .map_err(|error| match error {
                            StateReadError::Unavailable => unavailable(),
                            StateReadError::InvalidProof => SdkError {
                                code: -32043,
                                message: "state proof verification failed",
                            },
                        })?;
                if answer.at != at || answer.root != root {
                    return Err(unavailable());
                }
                // Reject a proof whose provisional root was superseded by a
                // finality certificate while the request was in flight.
                let context = self.sdk_request_context(at, allow).await?;
                if b64::<32>(&context["state_root"])? != root {
                    return Err(unavailable());
                }
                if answer.range.complete_to < key {
                    return Err(unavailable());
                }
                Ok(answer
                    .range
                    .entries
                    .into_iter()
                    .find(|(k, _)| *k == key)
                    .map_or(Value::Null, |(_, value)| {
                        Value::String(STANDARD.encode(value))
                    }))
            }
        }
    }

    async fn sdk_request_context(&self, at: Hash, allow: bool) -> Result<Value, SdkError> {
        let (send_back, response) = futures_channel::oneshot::channel();
        self.to_sdk
            .as_ref()
            .ok_or_else(unavailable)?
            .send(Request {
                method: "jam_verificationContext".into(),
                params: json!([STANDARD.encode(at), allow]),
                send_back,
            })
            .await
            .map_err(|_| unavailable())?;
        match response.await.map_err(|_| unavailable())?? {
            QueryResult::Value(value) => Ok(value),
            _ => Err(unavailable()),
        }
    }
}

impl State {
    fn sdk_header(&self, hash: &Hash) -> Result<(Hash, u32, Vec<u8>), SdkError> {
        if let Some(header) = self.tree.get(hash) {
            return Ok((header.parent(), header.slot(), header.encoded().to_vec()));
        }
        self.sdk
            .records
            .get(hash)
            .map(|r| (r.parent, r.slot, r.encoded.clone()))
            .ok_or_else(unknown)
    }

    pub(super) fn sdk_context(&self, hash: &Hash, allow: bool) -> Result<Record, SdkError> {
        if let Some(record) = self.sdk.records.get(hash) {
            return Ok(record.clone());
        }
        let (parent, slot, encoded) = self.sdk_header(hash)?;
        if !allow {
            return Err(unavailable());
        }
        let mut root = None;
        for child in self
            .tree
            .ancestry_order()
            .filter(|child| child.parent() == *hash)
        {
            let candidate: Hash = child
                .encoded()
                .get(32..64)
                .ok_or_else(unavailable)?
                .try_into()
                .map_err(|_| unavailable())?;
            if root.is_some_and(|known| known != candidate) {
                return Err(unavailable());
            }
            root = Some(candidate);
        }
        Ok(Record {
            hash: *hash,
            parent,
            slot,
            encoded,
            root: root.ok_or_else(unavailable)?,
            level: "provisional",
        })
    }

    /// Collect before pruning, but install only after tree.finalize succeeds.
    pub(super) fn sdk_finality_records(&self, proof: &VerifiedFinality) -> Vec<Record> {
        let mut records = Vec::new();
        let mut hash = proof.target().hash;
        let mut root = proof.target().state_root;
        for _ in 0..HISTORY_COUNT {
            let Some(header) = self.tree.get(&hash) else {
                break;
            };
            records.push(Record {
                hash,
                parent: header.parent(),
                slot: header.slot(),
                root,
                level: "finalized",
                encoded: header.encoded().to_vec(),
            });
            if hash == self.tree.finalized().hash() {
                break;
            }
            hash = header.parent();
            let Some(bytes) = header.encoded().get(32..64) else {
                break;
            };
            root = match bytes.try_into() {
                Ok(root) => root,
                Err(_) => break,
            };
        }
        records
    }

    fn sdk_descriptor(&self, hash: Hash) -> Result<Value, SdkError> {
        let (_, slot, _) = self.sdk_header(&hash)?;
        Ok(json!({"header_hash":STANDARD.encode(hash), "slot":slot}))
    }

    pub(super) fn sdk_query(
        &mut self,
        method: &str,
        params: &Value,
    ) -> Result<QueryResult, SdkError> {
        if !self.sdk.continuous {
            return Err(SdkError {
                code: -32042,
                message: "JAM SDK requires continuous ancestry; warp mode is not chain-bound",
            });
        }
        let p = params.as_array().ok_or_else(invalid)?;
        let value = match (method, p.as_slice()) {
            ("jam_parameters", []) => self.sdk_parameters(),
            ("jam_block", [selector]) => {
                let hash = match selector.as_str() {
                    Some("best") => self.tree.best().hash(),
                    Some("finalized") => self.tree.finalized().hash(),
                    _ => b64(selector)?,
                };
                self.sdk_descriptor(hash)?
            }
            ("jam_parent", [at]) => {
                let at = b64(at)?;
                let (parent, _, _) = self.sdk_header(&at)?;
                self.sdk_descriptor(parent)?
            }
            ("jam_header", [at]) => {
                let (_, _, encoded) = self.sdk_header(&b64(at)?)?;
                Value::String(hex::encode(encoded))
            }
            ("jam_verificationContext", [at, allow]) => {
                let context = self.sdk_context(&b64(at)?, flag(allow)?)?;
                json!({"genesis_hash":STANDARD.encode(self.sdk.genesis),
                    "header_hash":STANDARD.encode(context.hash), "state_root":STANDARD.encode(context.root),
                    "level":context.level})
            }
            ("jam_stateValue", [at, root, key, allow]) => {
                if self.stopped {
                    return Err(unavailable());
                }
                let at = b64(at)?;
                let root = b64(root)?;
                let key = b64(key)?;
                let allow = flag(allow)?;
                let context = self.sdk_context(&at, allow)?;
                if context.root != root {
                    return Err(unavailable());
                }
                let receiver = self
                    .reads
                    .start(StateRead {
                        at,
                        root,
                        trust: if context.level == "provisional" {
                            Trust::Authenticated
                        } else {
                            Trust::Finalized
                        },
                        root_header: Some(at),
                        request: StateRequest {
                            block: at,
                            start: key,
                            end: key,
                            max_size: READ_BYTES,
                        },
                    })
                    .map_err(|_| SdkError {
                        code: -32041,
                        message: "state proof reader busy",
                    })?;
                return Ok(QueryResult::Read {
                    receiver,
                    at,
                    root,
                    key,
                    allow,
                });
            }
            _ => return Err(invalid()),
        };
        Ok(QueryResult::Value(value))
    }

    /// Remove descendants whose prior commitment contradicts a newly signed root.
    /// Rebuild transactionally from retained verified headers; no new trust is introduced.
    pub(super) fn sdk_reconcile_tree(&mut self) -> Vec<Hash> {
        if !self.sdk.continuous
            || !self.tree.ancestry_order().skip(1).any(|header| {
                self.sdk
                    .certified_root(&header.parent())
                    .is_some_and(|root| header.encoded().get(32..64) != Some(root.as_slice()))
            })
        {
            return Vec::new();
        }
        let Ok(mut rebuilt) = smoldot::jam::tree::HeaderTree::new(
            self.params.clone(),
            self.tree.finalized().clone(),
            self.tree_config,
        ) else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        for header in self.tree.ancestry_order().skip(1) {
            if rebuilt.get(&header.parent()).is_none()
                || self
                    .sdk
                    .certified_root(&header.parent())
                    .is_some_and(|root| header.encoded().get(32..64) != Some(root.as_slice()))
            {
                removed.push(header.hash());
            } else if rebuilt.insert_verified(header.clone()).is_err() {
                // The same subset already fits the tree budget. A failure must
                // stop queries rather than continue on contradictory evidence.
                self.stopped = true;
                self.subscribers.clear();
                return Vec::new();
            }
        }
        self.tree = rebuilt;
        removed.reverse();
        removed
    }

    fn sdk_parameters(&self) -> Value {
        let p = &self.params;
        let count = self.tree.finalized().post_state().epoch().active.len();
        let limit = count / 3 + 1;
        let shards = (1..=limit).rev().find(|n| 2052 % n == 0).unwrap_or(1);
        json!({"V1":{
            "epoch_period":p.epoch_len,"slot_period_sec":p.slot_seconds,"core_count":p.core_count,
            "val_count":count,"basic_piece_len":2*shards,"segment_piece_count":4104/(2*shards),
            "epoch_tail_start":p.epoch_tail_start,"max_tickets_per_block":p.max_tickets_per_ext,
            "deposit_per_item":p.deposit_per_item,"deposit_per_byte":p.deposit_per_byte,
            "deposit_per_account":p.deposit_per_account,"min_turnaround_period":p.min_turnaround_period,
            "max_accumulate_gas":p.max_accumulate_gas,"max_is_authorized_gas":p.max_is_authorized_gas,
            "max_refine_gas":p.max_refine_gas,"block_gas_limit":p.block_gas_limit,
            "recent_block_count":p.recent_block_count,"max_work_items":p.max_work_items,
            "max_dependencies":p.max_dependencies,"max_lookup_anchor_age":p.max_lookup_anchor_age,
            "auth_window":p.auth_window,"auth_queue_len":p.auth_queue_len,"rotation_period":p.rotation_period,
            "max_extrinsics":p.max_extrinsics,"availability_timeout":p.availability_timeout,
            "max_authorizer_code_size":p.max_authorizer_code_size,"max_input":p.max_input,
            "max_service_code_size":p.max_service_code_size,"max_imports":p.max_imports,
            "max_report_elective_data":p.max_report_elective_data,"transfer_memo_size":p.transfer_memo_size,
            "max_exports":p.max_exports,
        }})
    }
}
