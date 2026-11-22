// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

fn enabled() -> State {
    let mut state = root_state();
    state.sdk.continuous = true;
    state
}

#[test]
fn sdk_requires_continuous_ancestry_and_preserves_ids_roots() {
    let mut state = root_state();
    assert_eq!(
        state
            .sdk_query("jam_parameters", &json!([]))
            .err()
            .unwrap()
            .code,
        -32042
    );
    state.sdk.continuous = true;
    let hash = state.tree.finalized().hash();
    assert_eq!(state.sdk_context(&hash, false).err().unwrap().code, -32040);
    let header = state.tree.finalized();
    state.sdk.remember(super::super::sdk::Record {
        hash,
        parent: header.parent(),
        slot: header.slot(),
        root: [7; 32],
        level: "trusted_anchor",
        encoded: header.encoded().to_vec(),
    });
    let super::super::sdk::QueryResult::Value(context) = state
        .sdk_query(
            "jam_verificationContext",
            &json!([STANDARD.encode(hash), false]),
        )
        .unwrap()
    else {
        panic!("context must be immediate")
    };
    assert_eq!(context["state_root"], STANDARD.encode([7; 32]));
    assert_eq!(context["level"], "trusted_anchor");
    assert_eq!(
        state
            .sdk_query(
                "jam_stateValue",
                &json!([
                    STANDARD.encode(hash),
                    STANDARD.encode([9; 32]),
                    STANDARD.encode([0; 31]),
                    false
                ])
            )
            .err()
            .unwrap()
            .code,
        -32040
    );
    assert!(state.reads.pending.is_none());
    let super::super::sdk::QueryResult::Value(params) =
        state.sdk_query("jam_parameters", &json!([])).unwrap()
    else {
        panic!("parameters immediate")
    };
    assert_eq!(params["V1"]["val_count"], 6);
    assert_eq!(params["V1"]["basic_piece_len"], 6);
    assert_eq!(params["V1"]["segment_piece_count"], 684);
}

#[test]
fn provisional_roots_require_opt_in_and_conflicting_siblings_fail_closed() {
    let mut state = enabled();
    let parent = state.tree.finalized().clone();
    let mut h = Header::decode(&state.params, parent.encoded()).unwrap();
    h.slot = 1;
    h.parent = parent.hash();
    h.prior_state_root = [7; 32];
    state
        .tree
        .insert_verified(assume_verified(
            &state.params,
            &h,
            parent.post_state().clone(),
        ))
        .unwrap();
    assert!(state.sdk_context(&parent.hash(), false).is_err());
    let provisional = state.sdk_context(&parent.hash(), true).unwrap();
    assert_eq!(provisional.root, [7; 32]);
    assert_eq!(provisional.level, "provisional");
    h.prior_state_root = [8; 32];
    state
        .tree
        .insert_verified(assume_verified(
            &state.params,
            &h,
            parent.post_state().clone(),
        ))
        .unwrap();
    assert!(state.sdk_context(&parent.hash(), true).is_err());
    // A retained signed root dominates every unfinalized child, including malicious ones.
    state.sdk.remember(super::super::sdk::Record {
        hash: parent.hash(),
        parent: parent.parent(),
        slot: 0,
        root: [9; 32],
        level: "finalized",
        encoded: parent.encoded().to_vec(),
    });
    assert_eq!(
        state.sdk_context(&parent.hash(), false).unwrap().root,
        [9; 32]
    );
    let removed = state.sdk_reconcile_tree();
    assert_eq!(removed.len(), 2);
    assert_eq!(state.tree.len(), 1);
    assert!(matches!(
        state.insert(h, 1_900_000_000),
        Err(InsertFailure::RootMismatch)
    ));
}

#[test]
fn native_certificate_retains_signed_posterior_root_after_pruning() {
    let fixture = fixture("polkajam-grandpa.json");
    let spec = parse(&fixture["spec"].to_string());
    let mut state = state(Config::from_spec(&spec).unwrap());
    for encoded in fixture["headers"].as_array().unwrap() {
        state
            .insert(
                Header::decode(&state.params, &bytes(encoded)).unwrap(),
                1_900_000_000,
            )
            .unwrap();
    }
    state.sdk.continuous = true;
    for encoded in fixture["justifications"].as_array().unwrap() {
        let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
        let proof = Justification::decode(&state.params, &bytes, state.proof_limits()).unwrap();
        let target = proof.target().clone();
        state.finalize(target.hash, &bytes).unwrap();
        let context = state.sdk_context(&target.hash, false).unwrap();
        assert_eq!(context.root, target.state_root);
        assert_eq!(context.level, "finalized");
        let read = state.finalized_read([0; 31], [0; 31], 100).unwrap();
        assert_eq!(read.root, target.state_root);
        assert_eq!(read.trust, Trust::Finalized);
    }
}

#[test]
fn sdk_queries_progress_offline_and_cancel_with_original_zero_id() {
    smol::block_on(async {
        let platform = platform(Control::default());
        let mut config = root_config();
        config.sdk.continuous = true;
        let header = config.tree.finalized();
        let hash = header.hash();
        config.sdk.remember(super::super::sdk::Record {
            hash,
            parent: header.parent(),
            slot: header.slot(),
            root: [7; 32],
            level: "trusted_anchor",
            encoded: header.encoded().to_vec(),
        });
        let sync = Arc::new(JamSyncService::new(
            platform.clone(),
            "sdk-offline".into(),
            config,
        ));
        let frontend = crate::json_rpc_service::service_jam(crate::json_rpc_service::JamConfig {
            platform,
            log_name: "sdk-offline".into(),
            sync_service: sync,
            max_pending_requests: core::num::NonZeroU32::new(8).unwrap(),
            max_subscriptions: 2,
            chain_name: "sdk-offline".into(),
            genesis_block_hash: [0; 32],
        });
        frontend
            .queue_rpc_request(
                json!({"jsonrpc":"2.0","id":1,
            "method":"jam_parameters","params":[]})
                .to_string(),
            )
            .unwrap();
        let response = future::or(frontend.next_json_rpc_response(), async {
            smol::Timer::after(Duration::from_secs(1)).await;
            panic!("local queries must not wait for network")
        })
        .await;
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["V1"]["core_count"], 2);
        for id in [0, 2] {
            frontend.queue_rpc_request(json!({"jsonrpc":"2.0","id":id,"method":"jam_stateValue",
                "params":[STANDARD.encode(hash),STANDARD.encode([7;32]),STANDARD.encode([0;31]),false]}).to_string()).unwrap();
            // No peer can serve this read. Cancelling it must release the exact
            // original request and allow a subsequent read without a leaked slot.
            frontend
                .queue_rpc_request(
                    json!({"jsonrpc":"2.0","method":"jam_cancel",
                "params":[id]})
                    .to_string(),
                )
                .unwrap();
            let response = future::or(frontend.next_json_rpc_response(), async {
                smol::Timer::after(Duration::from_secs(1)).await;
                panic!("cancel must acknowledge promptly")
            })
            .await;
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["id"], id);
            assert_eq!(response["error"]["code"], -32800);
        }
    });
}

#[test]
fn invalid_proof_is_distinct_from_peer_unavailability() {
    smol::block_on(async {
        let mut reads = StateReads::new(1);
        let read = StateRead {
            at: [1; 32],
            root: [7; 32],
            trust: Trust::Finalized,
            root_header: Some([1; 32]),
            request: StateRequest {
                block: [1; 32],
                start: [0; 31],
                end: [0; 31],
                max_size: 1000,
            },
        };
        let receiver = reads.start(read).unwrap();
        assert!(reads.reserve(0).is_some());
        assert!(
            reads
                .received(
                    0,
                    &StateResponse {
                        nodes: vec![],
                        entries: vec![]
                    }
                )
                .is_err()
        );
        assert_eq!(
            receiver.await.unwrap().unwrap_err(),
            StateReadError::InvalidProof
        );
    });
}

#[test]
fn sdk_requires_selected_anchor_root_and_rejects_shared_authority_wrong_genesis() {
    let mut full = fixture("chain-spec.polkajam.json");
    full["jamsdk_disable_warp"] = json!(true);
    let spec = parse(&full.to_string());
    let root = spec.genesis_state_root().expect("full trusted export");
    let first = Header::decode(
        spec.params(),
        &bytes(&fixture("headers/0000.json")["header_hex"]),
    )
    .unwrap();
    assert_eq!(first.prior_state_root, root);
    let mut correct = state(Config::from_spec(&spec).unwrap());
    correct.insert(first.clone(), 1_900_000_000).unwrap();

    // The header and initial finality authorities are identical across these
    // two states. Only a trusted posterior commitment distinguishes the chains.
    let mut wrong = full.clone();
    let key = hex::encode(trie::state_key(1));
    let mut value = bytes(&wrong["genesis_state"][&key]);
    value[0] ^= 1;
    wrong["genesis_state"][&key] = json!(hex::encode(value));
    let other = parse(&wrong.to_string());
    assert_eq!(other.genesis_header(), spec.genesis_header());
    assert_eq!(other.genesis_light_state(), spec.genesis_light_state());
    assert_ne!(other.genesis_state_root(), Some(root));
    let mut wrong = state(Config::from_spec(&other).unwrap());
    assert!(matches!(
        wrong.insert(first, 1_900_000_000),
        Err(InsertFailure::RootMismatch)
    ));
    assert_eq!(wrong.tree.len(), 1);

    let mut partial = full.clone();
    partial["genesis_state"]
        .as_object_mut()
        .unwrap()
        .remove(&key);
    assert!(matches!(
        Config::from_spec(&parse(&partial.to_string())),
        Err(ConfigError::MissingTrustedStateRoot)
    ));
    partial["jamsdk_disable_warp"] = json!(false);
    assert!(
        Config::from_spec(&parse(&partial.to_string())).is_ok(),
        "legacy browser prototype remains available"
    );

    let item = |index| full["genesis_state"][hex::encode(trie::state_key(index))].clone();
    full["checkpoint"] = json!({"header":full["genesis_header"],
        "state":{"safrole":item(4),"entropy":item(6),"active_validators":item(8),"slot":item(11)},
        "finality":{"set_id":0,"current":vec![hex::encode([1;32]);6],"next":vec![hex::encode([1;32]);6]}});
    assert!(
        matches!(
            Config::from_spec(&parse(&full.to_string())),
            Err(ConfigError::MissingTrustedStateRoot)
        ),
        "a full genesis commitment cannot substitute for the selected checkpoint posterior root"
    );
    full["checkpoint"]["state_root"] = json!(hex::encode([5; 32]));
    let trusted = parse(&full.to_string());
    let anchored = state(Config::from_spec(&trusted).unwrap());
    let context = anchored
        .sdk_context(&anchored.tree.finalized().hash(), false)
        .unwrap();
    assert_eq!(context.root, [5; 32]);
    assert_eq!(context.level, "trusted_anchor");
}
