//! Phase 6: combined balance + high-level MWEB facade helpers.
//!
//! Unit tests always run. Regtest E2E requires `LITECOIND_EXE` (skips when unset).

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::tx_builder::CHANGE_ADDRESS_INDEX;
use bdk_mweb::{scan_litecoin_tx_at, AddressBook, MwebCoin, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};
use bdk_wallet::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Amount, Network};
use bdk_wallet::test_utils::{get_funded_wallet_wpkh, get_test_wpkh_and_change_desc};
use bdk_wallet::{extract_prepared_mweb_pegin, KeychainKind, SignOptions, Wallet};

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn fixture_coin(amount: u64) -> MwebCoin {
    MwebCoin {
        output_id: {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&amount.to_le_bytes());
            id
        },
        commitment: [2; 33],
        amount,
        address_index: 2,
        blind: [3; 32],
        shared_secret: [4; 32],
        spend_key: Some([5; 32]),
        block_height: None,
        is_pegin: false,
        leaf_index: None,
    }
}

#[test]
fn balance_combined_sums_transparent_and_mweb() {
    let (wallet, _) = get_funded_wallet_wpkh();
    let transparent = wallet.balance();
    let tip = wallet.latest_checkpoint().height();
    let mut db = MwebCoinDatabase::new();
    db.insert(fixture_coin(12_345).with_block_height(tip));

    let combined = wallet.balance_combined(&db);
    assert_eq!(combined.transparent, transparent);
    assert_eq!(combined.mweb_confirmed, Amount::from_sat(12_345));
    assert_eq!(combined.mweb_untrusted_pending, Amount::ZERO);
    assert_eq!(
        combined.total(),
        transparent.total() + Amount::from_sat(12_345)
    );
    assert_eq!(
        combined.trusted_spendable(),
        transparent.trusted_spendable() + Amount::from_sat(12_345)
    );
}

#[test]
fn prepare_mweb_pegin_builds_psbt_and_body() {
    let (mut wallet, _) = get_funded_wallet_wpkh();
    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &seed,
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .unwrap();

    let prepared = wallet
        .prepare_mweb_pegin(
            &keys,
            2,
            Amount::from_sat(20_000),
            Amount::from_sat(1_000),
            Amount::from_sat(500),
            &secp,
        )
        .expect("prepare_mweb_pegin");

    assert_eq!(prepared.pegin_amount.to_sat(), 20_000);
    assert_eq!(prepared.kernel_id.len(), 32);
    assert!(!prepared.psbt.inputs.is_empty());
    assert_eq!(
        prepared.psbt.mweb_kernels.len(),
        1,
        "peg-in has one kernel map"
    );
    assert!(prepared.psbt.mweb_tx_offset.is_some());
}

#[test]
fn wallet_facade_pegin_pegout_roundtrip() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &seed,
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .unwrap();
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).unwrap();

    let (desc, change_desc) = get_test_wpkh_and_change_desc();
    let mut wallet = Wallet::create(desc.to_string(), change_desc.to_string())
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("wallet");

    // Confirm transparent funding at height 431. Mining 432 without a peg-in in the
    // mempool fails HogEx validation (bad-txns-vin-empty); activation comes after peg-in.
    let mining = env.rpc.get_new_address().expect("mining addr");
    let height = env.rpc.get_block_count().expect("height");
    const FUND_CONFIRM_HEIGHT: u32 = 431; // FIRST_MWEB_HEIGHT - 1
    if height < FUND_CONFIRM_HEIGHT - 1 {
        env.rpc
            .generate_to_address(FUND_CONFIRM_HEIGHT - 1 - height, &mining)
            .expect("mine to 430");
    }
    let fund_addr = wallet.peek_address(KeychainKind::External, 0).address;
    let _fund_txid = env
        .rpc
        .send_to_address(&fund_addr, Amount::from_btc(25.0).unwrap())
        .expect("fund wallet");
    env.mine_blocks(1, &mining).expect("confirm fund at 431");

    // Sync wallet to tip so the funding UTXO is spendable.
    let tip = env.rpc.get_block_count().expect("height");
    assert_eq!(tip, FUND_CONFIRM_HEIGHT);
    let start = wallet.latest_checkpoint().height();
    for h in (start + 1)..=tip {
        let hash = env.rpc.get_block_hash(h).expect("hash");
        let block = env.rpc.get_block(&hash).expect("block");
        wallet.apply_block(&block, h).expect("apply_block");
    }
    assert!(
        wallet.balance().confirmed.to_sat() >= Amount::from_btc(25.0).unwrap().to_sat(),
        "wallet must see funding; balance={:?}",
        wallet.balance()
    );

    let pegin_amount = Amount::from_btc(1.0).unwrap();
    let mweb_fee = Amount::from_sat(50_000);
    let transparent_fee = Amount::from_sat(1_000);

    let mut prepared = wallet
        .prepare_mweb_pegin(&keys, 2, pegin_amount, mweb_fee, transparent_fee, &secp)
        .expect("prepare_mweb_pegin");
    let signed = wallet
        .sign(&mut prepared.psbt, SignOptions::default())
        .expect("sign");
    assert!(signed);
    let tx = extract_prepared_mweb_pegin(&prepared.psbt).expect("mweb psbt extract");
    env.rpc.send_raw_transaction(&tx).expect("broadcast peg-in");

    // Block 432 activates MWEB and requires a peg-in in the mempool.
    env.mine_mweb_activation(&mining).expect("activate");
    env.mine_blocks(MWEB_PEGIN_MATURITY, &mining)
        .expect("maturity");

    // Sync peg-in confirmation into the transparent wallet (v9 is not spendable).
    let tip = env.rpc.get_block_count().expect("height");
    let start = wallet.latest_checkpoint().height();
    for h in (start + 1)..=tip {
        let hash = env.rpc.get_block_hash(h).expect("hash");
        let block = env.rpc.get_block(&hash).expect("block");
        wallet.apply_block(&block, h).expect("apply_block");
    }

    let mut db = MwebCoinDatabase::new();
    // Tag at peg-in inclusion height (MWEB activation), not tip — maturity gates spend.
    const PEGIN_HEIGHT: u32 = 432; // FIRST_MWEB_HEIGHT on regtest
    let found =
        scan_litecoin_tx_at(&keys, &book, &tx, &mut db, &secp, Some(PEGIN_HEIGHT)).expect("scan");
    let receive_amt = pegin_amount.to_sat() - mweb_fee.to_sat();
    assert_eq!(db.balance(), receive_amt);
    assert!(found
        .iter()
        .any(|c| c.address_index == 2 && c.amount == receive_amt));
    assert!(
        db.unspent()
            .any(|c| c.is_pegin && c.is_spendable(tip, MWEB_PEGIN_MATURITY)),
        "pegin should be mature at tip={tip}"
    );

    let combined = wallet.balance_combined(&db);
    assert_eq!(combined.mweb_confirmed, Amount::from_sat(receive_amt));
    assert_eq!(combined.mweb_untrusted_pending, Amount::ZERO);
    assert!(combined.total() > combined.transparent.total());

    let pegout_addr = env.rpc.get_new_address().expect("pegout addr");
    let pegout_amt = Amount::from_btc(0.3).unwrap();
    let pegout_fee = Amount::from_sat(50_000);

    // In-PSBT fund → sign → extract (no attach_mweb_tx, no pre-built mw_tx).
    let mut funded = wallet
        .fund_mweb_pegout(
            &db,
            &keys,
            pegout_addr.script_pubkey(),
            pegout_amt,
            pegout_fee,
            CHANGE_ADDRESS_INDEX,
            &secp,
        )
        .expect("fund_mweb_pegout");
    assert!(funded.psbt.mweb_tx_offset.is_none());
    let (pegout_tx, _change) = wallet
        .sign_and_extract_funded_mweb(&mut funded, &keys, &secp)
        .expect("sign_and_extract");
    assert!(pegout_tx.mw_tx.is_some());
    assert!(funded
        .psbt
        .mweb_outputs
        .iter()
        .any(|o| o.stealth_address.is_some() || o.commit.is_some()));

    let (allowed, reason) = env
        .rpc
        .test_mempool_accept(&pegout_tx)
        .expect("testmempoolaccept");
    assert!(allowed, "reject-reason={reason:?}");
    env.rpc
        .send_raw_transaction(&pegout_tx)
        .expect("send peg-out");
    env.mine_blocks(1, &mining).expect("confirm peg-out");

    let tip = env.rpc.get_block_count().expect("height");
    let tip_hash = env.rpc.get_block_hash(tip).expect("tip hash");
    let tip_block = env.rpc.get_block(&tip_hash).expect("tip block");
    let hogex = tip_block.txdata.last().expect("hogex");
    assert!(hogex.is_hog_ex);
    assert!(
        hogex
            .output
            .iter()
            .any(|o| { o.value == pegout_amt && o.script_pubkey == pegout_addr.script_pubkey() }),
        "HogEx must credit peg-out"
    );
    let received = env
        .rpc
        .call(
            "getreceivedbyaddress",
            serde_json::json!([pegout_addr.to_string(), 1]),
        )
        .expect("getreceivedbyaddress");
    assert_eq!(
        Amount::from_btc(received.as_f64().unwrap()).unwrap(),
        pegout_amt
    );
}
