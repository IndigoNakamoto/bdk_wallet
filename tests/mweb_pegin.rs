//! Phase 1: BDK TxBuilder peg-in assembly + Core finalize recognition on regtest.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.

use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};
use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::Amount;
use bdk_wallet::chain::{is_mweb_bridge_output, mweb_pegin_script_pubkey};
use bdk_wallet::test_utils::get_funded_wallet_wpkh;
use bdk_wallet::SignOptions;

#[test]
fn bdk_assembles_pegin_from_finalizer_body_and_core_recognizes() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let mweb = env.rpc.get_new_mweb_address().expect("mweb");
    let peg_amount = Amount::from_btc(1.0).unwrap();

    // Core/mwebd finalize path: author kernel + mw_tx.
    let core_tx = env
        .finalize_mweb_pegin(&mweb, peg_amount)
        .expect("finalize");
    let mw_tx = core_tx.mw_tx.clone().expect("mw_tx");
    let pegin_out = core_tx
        .output
        .iter()
        .find(|o| {
            is_mweb_bridge_output(&o.script_pubkey)
                && o.script_pubkey.witness_version()
                    == Some(
                        bdk_wallet::bitcoin::blockdata::script::witness_version::WitnessVersion::V9,
                    )
        })
        .expect("v9 out");
    let mut kernel = [0u8; 32];
    kernel.copy_from_slice(&pegin_out.script_pubkey.as_bytes()[2..34]);

    // BDK builds + signs a transparent peg-in skeleton with that kernel/body.
    let (mut wallet, _) = get_funded_wallet_wpkh();
    let pegin_value = Amount::from_sat(10_000);
    let mut builder = wallet.build_tx();
    builder.add_mweb_pegin(kernel, pegin_value);
    builder.mweb_tx(mw_tx);
    builder.fee_absolute(Amount::from_sat(500));
    let (mut psbt, mw_body) = builder.finish_mweb_pegin().expect("BDK finish peg-in");
    let signed = wallet
        .sign(&mut psbt, SignOptions::default())
        .expect("sign");
    assert!(signed, "peg-in transparent inputs must be signed");
    let mut bdk_tx = psbt.extract_tx().expect("extract");
    #[allow(deprecated)]
    bdk_wallet::attach_mweb_tx(&mut bdk_tx, mw_body);
    assert!(bdk_tx.mw_tx.is_some());
    assert!(bdk_tx.output.iter().any(|o| {
        o.script_pubkey == mweb_pegin_script_pubkey(&kernel) && o.value == pegin_value
    }));

    // Core recognition of the finalize path (broadcast already done by sendtoaddress).
    env.mine_mweb_activation(&mining).expect("activate");
    env.mine_blocks(MWEB_PEGIN_MATURITY.saturating_sub(1), &mining)
        .expect("maturity");
    let received = env
        .rpc
        .list_received_by_mweb_address(&mweb, MWEB_PEGIN_MATURITY)
        .expect("received");
    assert_eq!(received, peg_amount);

    // Fixture vector from docs/MWEB_PEGIN.md still decodes.
    let hex = std::fs::read_to_string("../docs/mweb_pegin_regtest.hex").unwrap_or_default();
    if !hex.trim().is_empty() {
        let raw = Vec::from_hex(hex.trim()).unwrap();
        let fixture: bdk_wallet::bitcoin::Transaction = deserialize(&raw).unwrap();
        assert!(fixture.mw_tx.is_some());
    }
}
