//! Regtest walkthrough: peg-in → tip seam → LIP-0006 verified sync → peg-out.
//!
//! ```bash
//! export LITECOIND_EXE=/path/to/litecoind
//! cargo run -p bdk_wallet --example mweb_regtest --features "mweb,file_store,test-utils"
//! ```
//!
//! Tip seam (Electrum/Esplora/RPC stay outside `bdk_mweb`):
//! ```text
//! apply_block / apply_update → tip = wallet.latest_checkpoint()
//!   → (on shorter tip) MwebStore::disconnect_from(new_tip + 1)
//!   → sync_at_tip(TcpMwebPeer, tip_hash, tip_height, HeaderAndPmmr)
//! ```
//!
//! Production apps should encrypt the MWEB store (`bdk_mweb::seal` /
//! `seal_changeset`) and keep it beside the wallet DB — never in `Wallet::ChangeSet`.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::VerifyMode;
use bdk_mweb::lip0006_tcp::TcpMwebPeer;
use bdk_mweb::tx_builder::CHANGE_ADDRESS_INDEX;
use bdk_mweb::{AddressBook, MWEB_PEGIN_MATURITY, DEFAULT_GAP_LIMIT};
use bdk_testenv::try_node_from_env;
use bdk_wallet::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Amount, Network};
use bdk_wallet::test_utils::get_test_wpkh_and_change_desc;
use bdk_wallet::{extract_pegin_with_mweb_psbt, KeychainKind, MwebStore, SignOptions, Wallet};

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MWEB_MAGIC: &[u8] = b"bdk_mweb_v2";
const FUND_CONFIRM_HEIGHT: u32 = 431;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = try_node_from_env().expect("node harness") else {
        eprintln!("skip: set LITECOIND_EXE to run this example");
        return Ok(());
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX)?;
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)?;
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp)?;

    let (desc, change_desc) = get_test_wpkh_and_change_desc();
    let mut wallet = Wallet::create(desc.to_string(), change_desc.to_string())
        .network(Network::Regtest)
        .create_wallet_no_persist()?;

    let mining = env.rpc.get_new_address()?;
    let height = env.rpc.get_block_count()?;
    if height < FUND_CONFIRM_HEIGHT - 1 {
        env.rpc
            .generate_to_address(FUND_CONFIRM_HEIGHT - 1 - height, &mining)?;
    }
    let fund_addr = wallet.peek_address(KeychainKind::External, 0).address;
    env.rpc
        .send_to_address(&fund_addr, Amount::from_btc(25.0)?)?;
    env.mine_blocks(1, &mining)?;

    let tip = env.rpc.get_block_count()?;
    let start = wallet.latest_checkpoint().height();
    for h in (start + 1)..=tip {
        let hash = env.rpc.get_block_hash(h)?;
        let block = env.rpc.get_block(&hash)?;
        wallet.apply_block(&block, h)?;
    }
    println!("transparent confirmed: {}", wallet.balance().confirmed);

    let dir = tempfile::tempdir()?;
    let (mut store, mut file_store) =
        MwebStore::load_file_store(MWEB_MAGIC, dir.path().join("mweb.db"))?;

    let pegin_amount = Amount::from_btc(1.0)?;
    let mweb_fee = Amount::from_sat(50_000);
    let transparent_fee = Amount::from_sat(1_000);
    let mut prepared =
        wallet.prepare_mweb_pegin(&keys, 2, pegin_amount, mweb_fee, transparent_fee, &secp)?;
    assert!(wallet.sign(&mut prepared.psbt, SignOptions::default())?);
    let tx = extract_pegin_with_mweb_psbt(prepared.psbt, &prepared.pegin)?;
    env.rpc.send_raw_transaction(&tx)?;
    env.mine_mweb_activation(&mining)?;
    env.mine_blocks(MWEB_PEGIN_MATURITY, &mining)?;

    let tip = env.rpc.get_block_count()?;
    let start = wallet.latest_checkpoint().height();
    for h in (start + 1)..=tip {
        let hash = env.rpc.get_block_hash(h)?;
        let block = env.rpc.get_block(&hash)?;
        wallet.apply_block(&block, h)?;
    }

    // Tip seam identical to Electrum/Esplora: checkpoint hash + height.
    let tip_height = wallet.latest_checkpoint().height();
    let tip_hash = env.rpc.get_block_hash(tip_height)?;

    // Reorg seam: clear heights at/after tip (noop on empty store), then verified sync.
    store.disconnect_from(tip_height);

    let mut peer = TcpMwebPeer::connect(env.p2p_addr(), Network::Regtest)?;
    let result = store.sync_at_tip(
        &mut peer,
        &keys,
        &book,
        tip_hash,
        tip_height,
        VerifyMode::HeaderAndPmmr,
        &secp,
    )?;
    // Peg-in outputs need maturity metadata (LIP UTXO batches omit kernels).
    for coin in &result.found {
        if let Some(mut c) = store.db().get(&coin.output_id).cloned() {
            c.is_pegin = true;
            store.db_mut().insert(c);
        }
    }
    store.persist_file_store(&mut file_store)?;

    let combined = wallet.balance_combined_store(&store);
    let spendable = store
        .db()
        .unspent_spendable(tip_height, MWEB_PEGIN_MATURITY);
    println!(
        "LIP sync downloaded={} found={}; mweb_confirmed={} spendable_coins={}",
        result.downloaded,
        result.found.len(),
        combined.mweb_confirmed,
        spendable.len()
    );

    let pegout_addr = env.rpc.get_new_address()?;
    let mut funded = wallet.fund_mweb_pegout(
        store.db(),
        &keys,
        pegout_addr.script_pubkey(),
        Amount::from_btc(0.3)?,
        Amount::from_sat(50_000),
        CHANGE_ADDRESS_INDEX,
        &secp,
    )?;
    let (tx, _change) = wallet.sign_and_extract_funded_mweb(&mut funded, &keys, &secp)?;
    env.rpc.send_raw_transaction(&tx)?;
    env.mine_blocks(1, &mining)?;
    println!("peg-out broadcast; example complete");
    Ok(())
}
