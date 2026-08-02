//! Mainnet MWEB operator CLI for BDK ↔ Nexus.
//!
//! ```bash
//! cd bdk_wallet
//! # Requires existing transparent wallet from mainnet_receive:
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- address
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- pegin --amount 0.001
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- send --to ltcmweb1… --amount 0.0005
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- scan-tx --hex <rawtx>
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- pegout --amount 0.0005
//! cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- balance
//! ```
//!
//! Env:
//! - `LITECOIN_P2P` — litecoind P2P for LIP-0006 sync (default `127.0.0.1:9333`; comma-separated)
//! - `LITECOIN_RPC_URL` — preferred for MWEB-only `sendrawtransaction` (print **wtxid**)
//! - `LITECOIN_RPC_USER` / `LITECOIN_RPC_PASS` or cookie via URL userinfo
//! - `MWEB_FINE_SYNC` — `tip` | `fast` (500) | `1`/`full` (4000); default tip-only on first sync
//! - `MWEB_TIP_POLL_SECS` — poll interval for `sync --follow` (default 30)

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::mweb_sync::{
    fine_sample_heights, DatingMode, FixedHeaderProvider, MwebSyncer, PeerPool, PollingTipNotifier,
    ReadyNotifier, SyncNotifier, SyncState, FINE_WINDOW, FINE_WINDOW_FAST,
};
use bdk_mweb::tx_builder::CHANGE_ADDRESS_INDEX;
use bdk_mweb::{scan_litecoin_tx_at, AddressBook, DEFAULT_GAP_LIMIT, MWEB_PEGIN_MATURITY};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bdk_wallet::bitcoin::hex::{DisplayHex, FromHex};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, Network, NetworkKind, Transaction};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::template::Bip84;
use bdk_wallet::{
    extract_prepared_mweb_pegin, KeychainKind, MwebStore, PersistedWallet, SignOptions, Wallet,
};
use clap::{Parser, Subcommand};
use rand::RngCore;

const WALLET_DIR: &str = "mainnet-e2e-wallet";
const DB_PATH: &str = "mainnet-e2e-wallet/wallet.sqlite";
const SECRET_PATH: &str = "mainnet-e2e-wallet/SECRET_DO_NOT_SHARE.txt";
const MWEB_SECRET_PATH: &str = "mainnet-e2e-wallet/mweb_SECRET.txt";
const MWEB_INDEX_PATH: &str = "mainnet-e2e-wallet/mweb_receive_index.txt";
const MWEB_DB_PATH: &str = "mainnet-e2e-wallet/mweb.db";
const MWEB_SYNC_STATE_PATH: &str = "mainnet-e2e-wallet/mweb_sync.json";
const MWEB_MAGIC: &[u8] = b"bdk_mweb_v2"; // v2: MwebCoin.leaf_index (bincode incompatible with v1)
const ESPLORA_URL: &str = "https://litecoinspace.org/api";
const STOP_GAP: usize = 20;
const PARALLEL: usize = 5;
const DEFAULT_MWEB_FEE: Amount = Amount::from_sat(50_000);
const DEFAULT_TRANSPARENT_FEE: Amount = Amount::from_sat(1_000);

#[derive(Parser, Debug)]
#[command(name = "mainnet_mweb", about = "BDK ↔ Nexus mainnet MWEB loop")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print BDK `ltcmweb1…` receive address for Nexus to pay.
    Address {
        /// Force a specific address index (default: next unused from index file).
        #[arg(long)]
        index: Option<u32>,
    },
    /// Peg transparent LTC into MWEB (BDK-authored body).
    Pegin {
        /// Peg-in amount in LTC (e.g. 0.001). Transparent fee and MWEB fee are extra.
        #[arg(long)]
        amount: String,
        /// MWEB kernel fee in litoshis.
        #[arg(long, default_value_t = DEFAULT_MWEB_FEE.to_sat())]
        mweb_fee: u64,
        /// Transparent absolute fee in litoshis.
        #[arg(long, default_value_t = DEFAULT_TRANSPARENT_FEE.to_sat())]
        transparent_fee: u64,
    },
    /// Send MWEB → Nexus (or any `ltcmweb1…`).
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value_t = DEFAULT_MWEB_FEE.to_sat())]
        fee: u64,
    },
    /// mwebsync-shaped LIP-0006 sync (`LITECOIN_P2P`); dates UTXOs via fine header window.
    Sync {
        /// After each pass, wait for a new transparent tip (Esplora poll) and sync again.
        #[arg(long)]
        follow: bool,
    },
    /// Scan a raw Litecoin tx hex for owned MWEB outputs (Nexus payment paste).
    ScanTx {
        #[arg(long)]
        hex: String,
        /// Optional inclusion height to tag coins.
        #[arg(long)]
        height: Option<u32>,
    },
    /// Peg MWEB out to a transparent address (default: fresh BIP84 receive).
    Pegout {
        #[arg(long)]
        amount: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = DEFAULT_MWEB_FEE.to_sat())]
        fee: u64,
    },
    /// Combined transparent + MWEB balances.
    Balance,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(WALLET_DIR)?;
    let secp = Secp256k1::new();
    let keys = load_or_create_mweb_keys(&secp)?;
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp)?;
    let (mut store, mut file_store) = load_mweb_store()?;

    match cli.cmd {
        Cmd::Address { index } => {
            let idx = match index {
                Some(i) => i,
                None => next_receive_index()?,
            };
            let addr = keys.address(idx, NetworkKind::Main, &secp)?;
            println!("MWEB_RECEIVE_ADDRESS={addr}");
            println!("INDEX={idx}");
            println!("Paste into Nexus send (or share for receive).");
            if index.is_none() {
                // Advance only when we minted a fresh “next” address.
                set_receive_index(idx.saturating_add(1))?;
            }
        }
        Cmd::Pegin {
            amount,
            mweb_fee,
            transparent_fee,
        } => {
            let pegin_amount = parse_ltc(&amount)?;
            let (mut wallet, mut db) = load_transparent_wallet()?;
            let client = esplora_client::Builder::new(ESPLORA_URL).build_blocking();
            sync_transparent(&mut wallet, &client)?;
            wallet.persist(&mut db)?;

            let recv_idx = next_receive_index()?;
            let mut prepared = wallet.prepare_mweb_pegin(
                &keys,
                recv_idx,
                pegin_amount,
                Amount::from_sat(mweb_fee),
                Amount::from_sat(transparent_fee),
                &secp,
            )?;
            if !wallet.sign(&mut prepared.psbt, SignOptions::default())? {
                bail!("pegin PSBT not fully signed");
            }
            // Maps-first: MWEB already signed on PSBT; extract after transparent sign.
            let tx = extract_prepared_mweb_pegin(&prepared.psbt)?;
            let txid = broadcast_tx(&client, &tx)?;
            println!("Broadcast peg-in: https://litecoinspace.org/tx/{txid}");
            println!("kernel_id={}", prepared.kernel_id.to_lower_hex_string());

            let tip = wallet.latest_checkpoint().height();
            for mut coin in prepared.outputs {
                coin.is_pegin = true;
                coin.block_height = Some(tip);
                store.db_mut().insert(coin);
            }
            set_receive_index(recv_idx.saturating_add(1))?;
            store.persist_file_store(&mut file_store)?;
            wallet.persist(&mut db)?;
            println!(
                "Staged peg-in outputs at tip={tip}. Wait {MWEB_PEGIN_MATURITY} confirmations before send/pegout."
            );
        }
        Cmd::Send { to, amount, fee } => {
            let dest = Address::from_str(&to)?.require_network(Network::Bitcoin)?;
            let send_amount = parse_ltc(&amount)?;
            let (mut wallet, mut db) = load_transparent_wallet()?;
            let client = esplora_client::Builder::new(ESPLORA_URL).build_blocking();
            sync_transparent(&mut wallet, &client)?;
            wallet.persist(&mut db)?;

            let tip = wallet.latest_checkpoint().height();
            let spendable = store.db().unspent_spendable(tip, MWEB_PEGIN_MATURITY);
            println!(
                "spendable_coins={} tip={tip} maturity={MWEB_PEGIN_MATURITY}",
                spendable.len()
            );
            // In-PSBT path: fund maps → sign_mweb_components → extract (no attach / no pre-built mw_tx).
            let mut funded = wallet.fund_mweb_send(
                store.db(),
                &keys,
                dest,
                send_amount,
                Amount::from_sat(fee),
                CHANGE_ADDRESS_INDEX,
                &secp,
            )?;
            let spent_ids: Vec<_> = funded.spent_coins.iter().map(|c| c.output_id).collect();
            let (tx, change) = wallet.sign_and_extract_funded_mweb(&mut funded, &keys, &secp)?;
            let txid = broadcast_tx(&client, &tx)?;
            let wtxid = tx.compute_wtxid();
            println!("Broadcast MWEB send wtxid={wtxid} (explorer txid unreliable for pure MWEB)");
            println!("txid={txid}");
            for id in &spent_ids {
                let _ = store.db_mut().mark_spent(id);
            }
            if let Some(mut change) = change {
                change.block_height = None;
                store.db_mut().insert(change);
            }
            store.persist_file_store(&mut file_store)?;
        }
        Cmd::Sync { follow } => {
            let (mut wallet, mut db) = load_transparent_wallet()?;
            let client = esplora_client::Builder::new(ESPLORA_URL).build_blocking();
            let peers = p2p_addrs()?;
            println!("P2P PeerPool {:?}", peers);
            let mut pool = PeerPool::new(peers.clone());
            // Smoke-connect so we fail fast with a clear message if no peers are up.
            {
                let peer = pool.connect_next(Network::Bitcoin).with_context(|| {
                    format!(
                        "TcpMwebPeer connect to {peers:?}\n\
                         Start mainnet litecoind (P2P port 9333) or set LITECOIN_P2P=host:port[,host2:port2].\n\
                         Esplora cannot serve LIP-0006 mwebheader/leafset/utxos."
                    )
                })?;
                println!(" initial peer ok ({})", peer.addr_string());
            }

            let mut state = load_sync_state()?;
            let poll_secs: u64 = std::env::var("MWEB_TIP_POLL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30);

            loop {
                sync_transparent(&mut wallet, &client)?;
                wallet.persist(&mut db)?;

                let tip_height = wallet.latest_checkpoint().height();
                let tip_hash = wallet.latest_checkpoint().hash();
                println!(
                    "MWEB sync tip={tip_height} hash={tip_hash} last_peer={:?}",
                    pool.last_connected()
                );

                // First sync: tip-only (fast). Later: fine window 4000 (mwebsync). Overrides:
                // MWEB_FINE_SYNC=1|full → fine even on first; =fast → window 500; =tip → always tip-only.
                let first_sync = state.leafset.is_empty();
                let fine_env = std::env::var("MWEB_FINE_SYNC").ok();
                let syncer = if fine_env.as_deref() == Some("tip")
                    || (first_sync
                        && fine_env.as_deref() != Some("1")
                        && fine_env.as_deref() != Some("full"))
                {
                    println!(
                        "Dating: tip-only (set MWEB_FINE_SYNC=1 for fine window={FINE_WINDOW})"
                    );
                    MwebSyncer::tip_only()
                } else {
                    let mut s = MwebSyncer::new();
                    if fine_env.as_deref() == Some("fast") {
                        s.fine_window = FINE_WINDOW_FAST;
                    }
                    println!("Dating: fine window={}", s.fine_window);
                    s
                };

                let mut hashes = BTreeMap::new();
                hashes.insert(tip_height, tip_hash);
                let need: Vec<u32> = if matches!(syncer.dating, DatingMode::TipOnly) {
                    vec![tip_height]
                } else {
                    fine_sample_heights(tip_height, syncer.fine_window)
                        .into_iter()
                        .filter(|h| !state.height_map.contains_key(h))
                        .collect()
                };
                if need.len() > 1 {
                    println!(
                        "Fetching {} Esplora block hashes for fine-window dating…",
                        need.len()
                    );
                }
                for (i, h) in need.iter().enumerate() {
                    if need.len() > 1 && i % 50 == 0 {
                        print!("  hash {}/{}…\r", i + 1, need.len());
                        let _ = std::io::stdout().flush();
                    }
                    match client.get_block_hash(*h) {
                        Ok(hash) => {
                            hashes.insert(*h, hash);
                        }
                        Err(e) => {
                            eprintln!("\nwarn: esplora hash@{h}: {e}");
                        }
                    }
                }
                if need.len() > 1 {
                    println!("  hash {}/{} done", need.len(), need.len());
                }
                // Live tip fields via set_tip; fine hashes refreshed each pass.
                let mut headers = FixedHeaderProvider {
                    tip_hash,
                    tip_height,
                    hashes,
                };
                headers.set_tip(tip_hash, tip_height);
                let mut notifier = ReadyNotifier { tip_height };

                println!("Running differential LIP sync (PeerPool ban/rotate on hard errors)…");
                let result = pool
                    .with_failover(Network::Bitcoin, |peer| {
                        store.sync_differential_checkpointed(
                            &syncer,
                            &headers,
                            &mut notifier,
                            peer,
                            &mut state,
                            &keys,
                            &book,
                            &secp,
                            Some(&mut |state, db| {
                                if let Err(e) = save_sync_state(state) {
                                    eprintln!("warn: checkpoint sync state: {e}");
                                }
                                let staged = db.take_staged();
                                if let Err(e) = file_store.append(&staged) {
                                    eprintln!("warn: checkpoint mweb.db: {e}");
                                } else if state.utxo_cursor.is_some() {
                                    eprintln!(
                                        "  checkpointed cursor={:?} pending_tip={:?}",
                                        state.utxo_cursor, state.pending_tip_hash
                                    );
                                }
                            }),
                        )
                    })
                    .with_context(|| format!("MWEB sync failed; peers={peers:?}"))?;
                println!(
                    "downloaded={} found={} spent={} height_map={}",
                    result.downloaded,
                    result.found.len(),
                    result.spent.len(),
                    state.height_map.len()
                );
                for c in store.db().unspent() {
                    println!(
                        "  coin amount={} height={:?} leaf={:?}",
                        Amount::from_sat(c.amount),
                        c.block_height,
                        c.leaf_index
                    );
                }
                save_sync_state(&state)?;
                store.persist_file_store(&mut file_store)?;
                print_balances(&wallet, &store);

                if !follow {
                    break;
                }
                let tip_before = tip_height;
                println!("Waiting for tip > {tip_before} (poll {poll_secs}s)…");
                let mut tip_wait =
                    PollingTipNotifier::new(tip_before, Duration::from_secs(poll_secs), || {
                        client
                            .get_height()
                            .map_err(|e| bdk_mweb::Error::Crypto(format!("esplora tip: {e}")))
                    });
                tip_wait.wait_tip_changed(tip_before)?;
                println!("tip advanced to {}", tip_wait.tip_height);
            }
        }
        Cmd::ScanTx { hex, height } => {
            let raw = Vec::<u8>::from_hex(hex.trim())?;
            let tx: Transaction = deserialize(&raw)?;
            let found = scan_litecoin_tx_at(&keys, &book, &tx, store.db_mut(), &secp, height)?;
            store.persist_file_store(&mut file_store)?;
            println!("scanned txid={} found={}", tx.compute_txid(), found.len());
            for c in &found {
                println!(
                    "  output_id={} amount={} idx={} height={:?}",
                    c.output_id.to_lower_hex_string(),
                    Amount::from_sat(c.amount),
                    c.address_index,
                    c.block_height
                );
            }
        }
        Cmd::Pegout { amount, to, fee } => {
            let peg_amount = parse_ltc(&amount)?;
            let (mut wallet, mut db) = load_transparent_wallet()?;
            let client = esplora_client::Builder::new(ESPLORA_URL).build_blocking();
            sync_transparent(&mut wallet, &client)?;

            let dest_script = if let Some(to) = to {
                Address::from_str(&to)?
                    .require_network(Network::Bitcoin)?
                    .script_pubkey()
            } else {
                let a = wallet.next_unused_address(KeychainKind::External);
                println!("Peg-out to fresh receive idx={}: {}", a.index, a.address);
                wallet.persist(&mut db)?;
                a.address.script_pubkey()
            };

            let mut funded = wallet.fund_mweb_pegout(
                store.db(),
                &keys,
                dest_script,
                peg_amount,
                Amount::from_sat(fee),
                CHANGE_ADDRESS_INDEX,
                &secp,
            )?;
            let spent_ids: Vec<_> = funded.spent_coins.iter().map(|c| c.output_id).collect();
            let (tx, change) = wallet.sign_and_extract_funded_mweb(&mut funded, &keys, &secp)?;
            let txid = broadcast_tx(&client, &tx)?;
            let wtxid = tx.compute_wtxid();
            println!("Broadcast peg-out wtxid={wtxid}");
            println!("txid={txid}");
            println!("HogEx credits the transparent SPK after mining; re-run sync / mainnet_sync.");
            for id in &spent_ids {
                let _ = store.db_mut().mark_spent(id);
            }
            if let Some(mut change) = change {
                change.block_height = None;
                store.db_mut().insert(change);
            }
            store.persist_file_store(&mut file_store)?;
            wallet.persist(&mut db)?;
        }
        Cmd::Balance => {
            let (mut wallet, mut db) = load_transparent_wallet()?;
            let client = esplora_client::Builder::new(ESPLORA_URL).build_blocking();
            sync_transparent(&mut wallet, &client)?;
            wallet.persist(&mut db)?;
            print_balances(&wallet, &store);
        }
    }
    Ok(())
}

fn print_balances(wallet: &Wallet, store: &MwebStore) {
    let tip = wallet.latest_checkpoint().height();
    let combined = wallet.balance_combined_store(store);
    let spendable: u64 = store
        .db()
        .unspent_spendable(tip, MWEB_PEGIN_MATURITY)
        .iter()
        .map(|c| c.amount)
        .sum();
    let immature: u64 = store
        .db()
        .unspent()
        .filter(|c| c.is_pegin && !c.is_spendable(tip, MWEB_PEGIN_MATURITY))
        .map(|c| c.amount)
        .sum();
    println!(
        "transparent total={} confirmed={}",
        combined.transparent.total(),
        combined.transparent.confirmed
    );
    println!(
        "mweb confirmed={} (1+ conf) pending={} (unconfirmed height) spendable={} (mature)",
        combined.mweb_confirmed,
        combined.mweb_untrusted_pending,
        Amount::from_sat(spendable),
    );
    if immature > 0 {
        println!(
            "mweb peg-in immature={} (need {MWEB_PEGIN_MATURITY} confs; tip={tip})",
            Amount::from_sat(immature)
        );
    } else {
        println!("mweb tip={tip} peg-in maturity={MWEB_PEGIN_MATURITY}");
    }
}

fn parse_ltc(s: &str) -> anyhow::Result<Amount> {
    Amount::from_str_in(s, bdk_wallet::bitcoin::Denomination::Bitcoin)
        .map_err(|e| anyhow::anyhow!("amount: {e}"))
}

fn load_transparent_wallet() -> anyhow::Result<(PersistedWallet<Connection>, Connection)> {
    let xprv = load_master_xprv()?;
    let mut db = Connection::open(Path::new(DB_PATH))?;
    let wallet = Wallet::load()
        .descriptor(
            KeychainKind::External,
            Some(Bip84(xprv, KeychainKind::External)),
        )
        .descriptor(
            KeychainKind::Internal,
            Some(Bip84(xprv, KeychainKind::Internal)),
        )
        .extract_keys()
        .check_network(Network::Bitcoin)
        .load_wallet(&mut db)?
        .context("create transparent wallet first via mainnet_receive")?;
    Ok((wallet, db))
}

fn load_master_xprv() -> anyhow::Result<Xpriv> {
    let text = fs::read_to_string(SECRET_PATH)
        .with_context(|| format!("missing {SECRET_PATH}; run mainnet_receive first"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Master xprv:") {
            return Ok(Xpriv::from_str(rest.trim())?);
        }
    }
    bail!("Master xprv not found in {SECRET_PATH}");
}

fn load_or_create_mweb_keys(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> anyhow::Result<MasterKeys> {
    let path = PathBuf::from(MWEB_SECRET_PATH);
    if path.exists() {
        let text = fs::read_to_string(&path)?;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("Seed hex:") {
                let seed = Vec::<u8>::from_hex(rest.trim())?;
                return Ok(MasterKeys::from_seed(
                    &seed,
                    Network::Bitcoin,
                    MasterKeyScheme::LitecoinCore,
                    secp,
                )?);
            }
        }
        bail!("Seed hex not found in {}", path.display());
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let keys = MasterKeys::from_seed(&seed, Network::Bitcoin, MasterKeyScheme::LitecoinCore, secp)?;
    fs::write(
        &path,
        format!(
            "BDK Litecoin mainnet MWEB keys — KEEP PRIVATE\n\
             Scheme: LitecoinCore (Nexus/Core compatible)\n\
             Seed hex: {}\n\
             Store: {MWEB_DB_PATH}\n",
            seed.to_lower_hex_string()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }
    println!("Created MWEB secrets at {}", path.display());
    Ok(keys)
}

fn next_receive_index() -> anyhow::Result<u32> {
    let path = Path::new(MWEB_INDEX_PATH);
    if !path.exists() {
        return Ok(2);
    }
    let s = fs::read_to_string(path)?;
    Ok(s.trim().parse().unwrap_or(2))
}

fn set_receive_index(i: u32) -> anyhow::Result<()> {
    fs::write(MWEB_INDEX_PATH, format!("{i}\n"))?;
    Ok(())
}

fn sync_transparent(
    wallet: &mut PersistedWallet<Connection>,
    client: &esplora_client::BlockingClient,
) -> anyhow::Result<()> {
    print!("Syncing transparent...");
    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = BTreeSet::<KeychainKind>::new();
        move |k, i, _| {
            if once.insert(k) {
                print!("\nScanning [{k:?}]");
            }
            print!(" {i:<3}");
            stdout.flush().ok();
        }
    });
    let update = client.full_scan(request, STOP_GAP, PARALLEL)?;
    wallet.apply_update(update)?;
    println!();
    Ok(())
}

fn p2p_addrs() -> anyhow::Result<Vec<SocketAddr>> {
    let s = std::env::var("LITECOIN_P2P").unwrap_or_else(|_| "127.0.0.1:9333".into());
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(
            part.parse()
                .with_context(|| format!("parse LITECOIN_P2P entry {part}"))?,
        );
    }
    if out.is_empty() {
        bail!("LITECOIN_P2P empty");
    }
    Ok(out)
}

fn load_mweb_store() -> anyhow::Result<(MwebStore, bdk_file_store::Store<bdk_mweb::ChangeSet>)> {
    match MwebStore::load_file_store(MWEB_MAGIC, MWEB_DB_PATH) {
        Ok(pair) => Ok(pair),
        Err(e) => {
            // v1 stores (pre-leaf_index) fail bincode decode; wrong magic also lands here.
            let path = Path::new(MWEB_DB_PATH);
            if path.exists() {
                let bak = format!(
                    "{}.bak-{}",
                    MWEB_DB_PATH,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                );
                fs::rename(path, &bak).with_context(|| format!("rename broken store to {bak}"))?;
                eprintln!(
                    "warn: could not load {MWEB_DB_PATH} ({e}); moved aside to {bak} and starting empty.\n\
                     Re-run `sync` to rebuild coins from LIP-0006 (owned outputs are rediscovered)."
                );
            }
            MwebStore::load_file_store(MWEB_MAGIC, MWEB_DB_PATH)
                .map_err(|e2| anyhow::anyhow!("create fresh mweb store: {e2}"))
        }
    }
}

fn load_sync_state() -> anyhow::Result<SyncState> {
    let path = Path::new(MWEB_SYNC_STATE_PATH);
    if !path.exists() {
        return Ok(SyncState::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn save_sync_state(state: &SyncState) -> anyhow::Result<()> {
    let path = Path::new(MWEB_SYNC_STATE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(path, raw).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn broadcast_tx(
    client: &esplora_client::BlockingClient,
    tx: &Transaction,
) -> anyhow::Result<bdk_wallet::bitcoin::Txid> {
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    // Pure MWEB txs share an empty transparent skeleton: `compute_txid` ignores `mw_tx`, so
    // explorers that strip the extension accept a 12-byte shell under one colliding txid.
    // Always push MWEB bodies through litecoind when RPC is configured.
    let is_mweb = tx.mw_tx.is_some();
    if is_mweb {
        println!("mweb txid={txid} wtxid={wtxid} (use wtxid; txid ignores mw_tx)");
        if std::env::var_os("LITECOIN_RPC_URL").is_some() {
            let hex = serialize(tx).to_lower_hex_string();
            rpc_sendrawtransaction(&hex)?;
            println!("Broadcast via Litecoin RPC OK");
            return Ok(txid);
        }
        eprintln!(
            "warn: LITECOIN_RPC_URL unset; Esplora often drops mw_tx on MWEB-only broadcasts"
        );
    }
    match client.broadcast(tx) {
        Ok(()) => {
            println!("Broadcast via Esplora OK");
            return Ok(txid);
        }
        Err(e) => {
            eprintln!("Esplora broadcast failed: {e}");
            if std::env::var_os("LITECOIN_RPC_URL").is_none() {
                bail!("Esplora rejected tx; set LITECOIN_RPC_URL for sendrawtransaction fallback");
            }
        }
    }
    let hex = serialize(tx).to_lower_hex_string();
    rpc_sendrawtransaction(&hex)?;
    println!("Broadcast via Litecoin RPC OK");
    Ok(txid)
}

fn rpc_sendrawtransaction(tx_hex: &str) -> anyhow::Result<()> {
    let url = std::env::var("LITECOIN_RPC_URL")?;
    let user = std::env::var("LITECOIN_RPC_USER").unwrap_or_default();
    let pass = std::env::var("LITECOIN_RPC_PASS").unwrap_or_default();
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "bdk_mweb",
        "method": "sendrawtransaction",
        "params": [tx_hex],
    });
    let mut req = minreq::post(&url)
        .with_header("Content-Type", "application/json")
        .with_body(body.to_string());
    if !user.is_empty() {
        req = req.with_header(
            "Authorization",
            format!("Basic {}", base64_encode(&format!("{user}:{pass}"))),
        );
    }
    let resp = req.send().context("RPC HTTP")?;
    let v: serde_json::Value = resp.json().context("RPC JSON")?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        bail!("RPC error: {err}");
    }
    Ok(())
}

fn base64_encode(s: &str) -> String {
    use bitcoin::base64::Engine;
    bitcoin::base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
