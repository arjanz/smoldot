// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Diagnose native JAM synchronization and a proof-verified C(11) state read.
//!
//! Usage: cargo run -p smoldot-light --no-default-features --features std \
//!   --example jam_native -- /path/to/trusted-jam-spec.json [seconds]
//! This opens native WebTransport peer connections, never a node JSON-RPC URL.
//! The local specification is the caller's trust anchor; this is a bounded
//! diagnostic for the pinned PolkaJAM light-client extension profile.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_lite::future;
use serde_json::{Value, json};
use smoldot_light::{AddChainConfig, AddChainConfigJsonRpc, Client, platform::DefaultPlatform};
use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: jam_native TRUSTED_SPEC [SECONDS]")?;
    let seconds: u64 = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(30);
    if seconds == 0 || seconds > 60 {
        return Err("duration must be between 1 and 60 seconds".into());
    }
    let mut spec: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    spec["jamsdk_disable_warp"] = Value::Bool(true);
    let spec = serde_json::to_string(&spec)?;
    let platform = DefaultPlatform::new("jamsdk-native-probe".into(), "0.1".into());
    let mut client = Client::new(platform.clone());
    let added = client
        .add_chain(AddChainConfig {
            user_data: (),
            specification: &spec,
            database_content: "",
            potential_relay_chains: std::iter::empty(),
            json_rpc: AddChainConfigJsonRpc::Enabled {
                max_pending_requests: NonZeroU32::new(64).unwrap(),
                max_subscriptions: 8,
            },
            max_pending_transactions: NonZeroU32::new(1).unwrap(),
            statement_protocol_config: None,
        })
        .map_err(|error| format!("cannot add JAM chain: {error:?}"))?;
    let id = added.chain_id;
    let mut responses = added
        .json_rpc_responses
        .ok_or("JSON-RPC response stream missing")?;
    client.json_rpc_request(
        json!({"jsonrpc":"2.0","id":10000,
        "method":"jamHead_unstable_follow","params":[]})
        .to_string(),
        id,
    )?;
    let until = Instant::now() + Duration::from_secs(seconds);
    let mut tick = Instant::now();
    let mut round = 0u64;
    let mut slot_key = [0u8; 31];
    slot_key[0] = 11; // GP-0.8.0 Appendix D, C(11).
    let slot_key = STANDARD.encode(slot_key);
    let mut verified_reads = 0u64;
    smol::block_on(async {
        loop {
            let now = Instant::now();
            if now >= until {
                break;
            }
            if now >= tick {
                for (offset, selector) in [(0, "best"), (1, "finalized")] {
                    client
                        .json_rpc_request(
                            json!({"jsonrpc":"2.0","id":round*4+offset,
                        "method":"jam_block","params":[selector]})
                            .to_string(),
                            id,
                        )
                        .unwrap();
                }
                round += 1;
                tick = now + Duration::from_secs(2);
            }
            let next = future::or(async { Some(responses.next().await) }, async {
                smol::Timer::at(tick.min(until)).await;
                None
            })
            .await;
            let Some(message) = next else {
                continue;
            };
            let Some(message) = message else {
                break;
            };
            println!("{message}");
            let Ok(value) = serde_json::from_str::<Value>(&message) else {
                continue;
            };
            let Some(request) = value["id"].as_u64().filter(|request| *request < 10000) else {
                continue;
            };
            if value.get("error").is_some() {
                continue;
            }
            let followup = match request % 4 {
                1 => value["result"]["header_hash"].as_str().map(|hash| json!({
                    "jsonrpc":"2.0","id":request+1,"method":"jam_verificationContext","params":[hash,false]})),
                2 => {
                    let context = &value["result"];
                    Some(json!({"jsonrpc":"2.0","id":request+1,"method":"jam_stateValue",
                        "params":[context["header_hash"],context["state_root"],slot_key,false]}))
                },
                3 => {
                    // C(11) is exactly a little-endian u32. Missing state or an
                    // unrelated successful response is not a verified slot read.
                    if value["result"].as_str().and_then(|value| STANDARD.decode(value).ok())
                        .is_some_and(|bytes| bytes.len() == 4)
                    {
                        verified_reads += 1;
                    }
                    None
                },
                _ => None,
            };
            if let Some(followup) = followup {
                client.json_rpc_request(followup.to_string(), id).unwrap();
            }
        }
    });
    let _ = client.remove_chain(id);
    drop(responses);
    drop(client);
    platform.shutdown()?;
    eprintln!("native probe finished: {verified_reads} proof-verified C(11) reads");
    if verified_reads == 0 {
        return Err("no proof-verified C(11) read completed".into());
    }
    Ok(())
}
