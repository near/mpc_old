use std::str::FromStr;

use crate::actions::{self, add_latency, wait_for};
use crate::with_multichain_nodes;

use crypto_shared::{self, derive_epsilon, derive_key, x_coordinate, ScalarExt};
use integration_tests_chain_signatures::containers::{self, DockerClient};
use integration_tests_chain_signatures::MultichainConfig;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_contract::config::Config;
use mpc_contract::update::ProposeUpdateArgs;
use mpc_node::kdf::into_eth_sig;
use mpc_node::test_utils;
use mpc_node::types::LatestBlockHeight;
use mpc_node::util::NearPublicKeyExt;
use test_log::test;

pub mod nightly;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    let config = MultichainConfig::default();
    with_multichain_nodes(config.clone(), |mut ctx| {
        Box::pin(async move {
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state).await?;

            tracing::info!("!!! Add participant 3");
            assert!(ctx.add_participant(None).await.is_ok());
            let state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state).await?;

            tracing::info!("!!! Remove participant 0 and participant 2");
            let account_2 = near_workspaces::types::AccountId::from_str(
                state.participants.keys().nth(2).unwrap().clone().as_ref(),
            )
            .unwrap();
            assert!(ctx.remove_participant(Some(&account_2)).await.is_ok());
            let account_0 = near_workspaces::types::AccountId::from_str(
                state.participants.keys().next().unwrap().clone().as_ref(),
            )
            .unwrap();
            let node_cfg_0 = ctx.remove_participant(Some(&account_0)).await;
            assert!(node_cfg_0.is_ok());
            let node_cfg_0 = node_cfg_0.unwrap();
            let state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state).await?;

            tracing::info!("!!! Try remove participant 3, should fail due to threshold");
            assert!(ctx.remove_participant(None).await.is_err());

            tracing::info!("!!! Add participant 5");
            assert!(ctx.add_participant(None).await.is_ok());
            let state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state).await?;

            tracing::info!("!!! Add back participant 0");
            assert!(ctx.add_participant(Some(node_cfg_0)).await.is_ok());
            let state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_basic() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_rogue_responder(&ctx, &state_0).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_offline_node() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_mine_triples(&ctx, 2).await?;

            // Kill the node then have presignatures and signature generation only use the active set of nodes
            // to start generating presignatures and signatures.
            let account_id = near_workspaces::types::AccountId::from_str(
                state_0.participants.keys().last().unwrap().clone().as_ref(),
            )
            .unwrap();
            ctx.nodes.kill_node(&account_id).await;

            // This could potentially fail and timeout the first time if the participant set picked up is the
            // one with the offline node. This is expected behavior for now if a user submits a request in between
            // a node going offline and the system hasn't detected it yet.
            let presig_res = wait_for::has_at_least_mine_presignatures(&ctx, 1).await;
            let sig_res = actions::single_signature_production(&ctx, &state_0).await;

            // Try again if the first attempt failed. This second portion should not be needed when the NEP
            // comes in for resumeable MPC.
            if presig_res.is_err() || sig_res.is_err() {
                // Retry if the first attempt failed.
                wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
                actions::single_signature_production(&ctx, &state_0).await?;
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_key_derivation() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_presignatures(&ctx, 3).await?;

            for _ in 0..3 {
                let mpc_pk: k256::AffinePoint = state_0.public_key.clone().into_affine_point();
                let (_, payload_hashed, account, status) = actions::request_sign(&ctx).await?;
                let sig = wait_for::signature_responded(status).await?;

                let hd_path = "test";
                let derivation_epsilon = derive_epsilon(account.id(), hd_path);
                let user_pk = derive_key(mpc_pk, derivation_epsilon);
                let multichain_sig = into_eth_sig(
                    &user_pk,
                    &sig.big_r,
                    &sig.s,
                    k256::Scalar::from_bytes(payload_hashed).unwrap(),
                )
                .unwrap();

                // start recovering the address and compare them:
                let user_pk_x = x_coordinate(&user_pk);
                let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
                    1 => secp256k1::Parity::Odd,
                    0 => secp256k1::Parity::Even,
                    _ => unreachable!(),
                };
                let user_pk_x =
                    secp256k1::XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
                let user_secp_pk =
                    secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
                let user_addr = actions::public_key_to_address(&user_secp_pk);
                let r = x_coordinate(&multichain_sig.big_r.affine_point);
                let s = multichain_sig.s;
                let signature_for_recovery: [u8; 64] = {
                    let mut signature = [0u8; 64];
                    signature[..32].copy_from_slice(&r.to_bytes());
                    signature[32..].copy_from_slice(&s.scalar.to_bytes());
                    signature
                };
                let recovered_addr = web3::signing::recover(
                    &payload_hashed,
                    &signature_for_recovery,
                    multichain_sig.recovery_id as i32,
                )
                .unwrap();
                assert_eq!(user_addr, recovered_addr);
            }

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_persistence_for_generation() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        containers::Datastore::run(&docker_client, docker_network, gcp_project_id).await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple generation, the datastore triples are in sync with local generated triples
    test_utils::test_triple_generation(Some(datastore_url.clone())).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_triples_persistence_for_deletion() -> anyhow::Result<()> {
    let docker_client = DockerClient::default();
    let gcp_project_id = "test-triple-persistence";
    let docker_network = "test-triple-persistence";
    docker_client.create_network(docker_network).await?;
    let datastore =
        containers::Datastore::run(&docker_client, docker_network, gcp_project_id).await?;
    let datastore_url = datastore.local_address.clone();
    // verifies that @triple deletion, the datastore is working as expected
    test_utils::test_triple_deletion(Some(datastore_url)).await;
    Ok(())
}

#[test(tokio::test)]
async fn test_latest_block_height() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;

            let gcp_services = ctx.nodes.gcp_services().await?;
            for gcp_service in &gcp_services {
                let latest = LatestBlockHeight::fetch(gcp_service).await?;
                assert!(latest.block_height > 10);
            }

            // test manually updating the latest block height
            let gcp_service = gcp_services[0].clone();
            let latest = LatestBlockHeight {
                account_id: gcp_service.account_id.clone(),
                block_height: 1000,
            };
            latest.store(&gcp_service).await?;
            let new_latest = LatestBlockHeight::fetch(&gcp_service).await?;
            assert_eq!(new_latest.block_height, latest.block_height);

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature_offline_node_back_online() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 6).await?;
            wait_for::has_at_least_mine_triples(&ctx, 2).await?;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;

            // Kill node 2
            let account_id = near_workspaces::types::AccountId::from_str(
                state_0.participants.keys().last().unwrap().clone().as_ref(),
            )
            .unwrap();
            let killed_node_config = ctx.nodes.kill_node(&account_id).await;

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Start the killed node again
            ctx.nodes.restart_node(killed_node_config).await?;

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            wait_for::has_at_least_mine_triples(&ctx, 2).await?;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
            // retry the same payload multiple times because we might pick many presignatures not present in node 2 repeatedly until yield/resume time out
            actions::single_payload_signature_production(&ctx, &state_0).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_lake_congestion() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            // Currently, with a 10+-1 latency it cannot generate enough tripplets in time
            // with a 5+-1 latency it fails to wait for signature response
            add_latency(&ctx.nodes.proxy_name_for_node(0), true, 1.0, 2_000, 200).await?;
            add_latency(&ctx.nodes.proxy_name_for_node(1), true, 1.0, 2_000, 200).await?;
            add_latency(&ctx.nodes.proxy_name_for_node(2), true, 1.0, 2_000, 200).await?;

            // Also mock lake indexer in high load that it becomes slower to finish process
            // sig req and write to s3
            // with a 1s latency it fails to wait for signature response in time
            add_latency("lake-s3", false, 1.0, 100, 10).await?;

            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_rogue_responder(&ctx, &state_0).await?;
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_multichain_reshare_with_lake_congestion() -> anyhow::Result<()> {
    let config = MultichainConfig::default();
    with_multichain_nodes(config.clone(), |mut ctx| {
        Box::pin(async move {
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.threshold == 2);
            assert!(state.participants.len() == 3);

            // add latency to node1->rpc, but not node0->rpc
            add_latency(&ctx.nodes.proxy_name_for_node(1), true, 1.0, 1_000, 100).await?;
            // remove node2, node0 and node1 should still reach concensus
            // this fails if the latency above is too long (10s)
            assert!(ctx.remove_participant(None).await.is_ok());
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.participants.len() == 2);
            // Going below T should error out
            assert!(ctx.remove_participant(None).await.is_err());
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.participants.len() == 2);
            assert!(ctx.add_participant(None).await.is_ok());
            // add latency to node2->rpc
            add_latency(&ctx.nodes.proxy_name_for_node(2), true, 1.0, 1_000, 100).await?;
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.participants.len() == 3);
            assert!(ctx.remove_participant(None).await.is_ok());
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert!(state.participants.len() == 2);
            // make sure signing works after reshare
            let new_state = wait_for::running_mpc(&ctx, None).await?;
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_payload_signature_production(&ctx, &new_state).await
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_multichain_update_contract() -> anyhow::Result<()> {
    let config = MultichainConfig::default();
    with_multichain_nodes(config.clone(), |ctx| {
        Box::pin(async move {
            // Get into running state and produce a singular signature.
            let state = wait_for::running_mpc(&ctx, Some(0)).await?;
            wait_for::has_at_least_mine_triples(&ctx, 2).await?;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
            actions::single_payload_signature_production(&ctx, &state).await?;

            // Perform update to the contract and see that the nodes are still properly running and picking
            // up the new contract by first upgrading the contract, then trying to generate a new signature.
            let id = ctx.propose_update_contract_default().await;
            ctx.vote_update(id).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
            actions::single_payload_signature_production(&ctx, &state).await?;

            // Now do a config update and see if that also updates the same:
            let id = ctx
                .propose_update(ProposeUpdateArgs {
                    code: None,
                    config: Some(Config::default()),
                })
                .await;
            ctx.vote_update(id).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            wait_for::has_at_least_mine_presignatures(&ctx, 1).await?;
            actions::single_payload_signature_production(&ctx, &state).await?;

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_batch_random_signature() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            actions::batch_random_signature_production(&ctx, &state_0).await?;
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_batch_duplicate_signature() -> anyhow::Result<()> {
    with_multichain_nodes(MultichainConfig::default(), |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, Some(0)).await?;
            assert_eq!(state_0.participants.len(), 3);
            actions::batch_duplicate_signature_production(&ctx, &state_0).await?;
            Ok(())
        })
    })
    .await
}
