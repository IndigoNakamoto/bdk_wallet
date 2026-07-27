//! Litecoin-specific wallet behaviour.
//!
//! These cover the places where the transparent UTXO wallet must stay correct on a chain that also
//! has MWEB: HogEx transactions must not inflate balance, MWEB destinations must not be spendable
//! as transparent outputs, and modern `M...` P2SH addresses must round-trip.

use std::str::FromStr;
use std::sync::Arc;

use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::hex::FromHex;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::{Address, AddressType, Amount, Network, NetworkKind, Transaction};
use bdk_wallet::chain::TxUpdate;
use bdk_wallet::test_utils::get_funded_wallet_wpkh;
use bdk_wallet::error::CreateTxError;
use bdk_wallet::{KeychainKind, Update, Wallet};

/// Real mainnet HogEx transaction from block 3,149,263.
const HOGEX_TX_HEX: &str = "02000000000802bb03318fafc391a712d7f91a62cc9d1c505d50510b393e6ad91a8a47fcdd5b780000000000ffffffff57eee2ab0d098d12f89ce605c9d557c4260b254c61561789e41c0dc3a1e6754f0000000000ffffffff031b418561f5250000225820fd5fdb1335f2798d173cc602b6dc167acc7f8d927cae162cb1cb822789ea7899ec0e6e040000000016001428ea10e4b98adffc8c8169fb4adcab8fb739aa3260dcdb4b00000000160014f9ab13f3deb53dd5e50be7927a9ab4ecb6f2df3b0000000000";

#[test]
fn hogex_does_not_inflate_balance_or_utxos() {
    let (mut wallet, _) = get_funded_wallet_wpkh();
    let before_balance = wallet.balance().total();
    let before_utxos = wallet.list_unspent().count();

    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let hogex: Transaction = deserialize(&raw).expect("HogEx must decode");
    assert!(hogex.is_hog_ex);

    let mut tx_update = TxUpdate::default();
    tx_update.txs.push(Arc::new(hogex));
    wallet
        .apply_update(Update {
            tx_update,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        wallet.balance().total(),
        before_balance,
        "a HogEx that does not pay the wallet must not change balance"
    );
    assert_eq!(
        wallet.list_unspent().count(),
        before_utxos,
        "a HogEx that does not pay the wallet must not create spendable UTXOs"
    );
}

/// Peg-out vouts in a HogEx are ordinary transparent UTXOs and must credit the wallet. HogAddr
/// (vout0, witness v8) must never credit — covered at the chain indexer when a bridge SPK is
/// watched; here a confirmed peg-out rewrite to our SPK increases balance while the HogAddr is
/// ignored.
#[test]
fn hogex_pegout_credits_wallet_but_hogaddr_does_not() {
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{OutPoint, TxIn, TxOut};
    use bdk_wallet::chain::{is_mweb_bridge_output, BlockId, ConfirmationBlockTime};

    let (mut wallet, _) = get_funded_wallet_wpkh();
    let before = wallet.balance().total();
    // Index 0 is already used by the funding fixture; reveal a fresh receive SPK.
    let addr = wallet.peek_address(KeychainKind::External, 1).address;
    let pegout_amount = Amount::from_sat(25_000);

    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let mut hogex: Transaction = deserialize(&raw).unwrap();
    assert!(is_mweb_bridge_output(&hogex.output[0].script_pubkey));
    hogex.output[1] = TxOut {
        value: pegout_amount,
        script_pubkey: addr.script_pubkey(),
    };
    hogex.input[0] = TxIn {
        previous_output: OutPoint {
            txid: bdk_wallet::bitcoin::Txid::from_byte_array([0xAB; 32]),
            vout: 0,
        },
        ..hogex.input[0].clone()
    };

    let bridge_value = hogex.output[0].value;
    let txid = hogex.compute_txid();
    let tip = wallet.latest_checkpoint().block_id();
    let anchor = ConfirmationBlockTime {
        block_id: BlockId {
            height: tip.height,
            hash: tip.hash,
        },
        confirmation_time: 300,
    };
    let mut tx_update = TxUpdate::default();
    tx_update.txs.push(Arc::new(hogex));
    tx_update.anchors = [(anchor, txid)].into();
    wallet
        .apply_update(Update {
            tx_update,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(
        wallet.balance().total(),
        before + pegout_amount,
        "only the peg-out should credit; HogAddr value {bridge_value} must be ignored"
    );
}

#[test]
fn sending_to_mweb_address_is_rejected() {
    let (mut wallet, _) = get_funded_wallet_wpkh();

    let scan = PublicKey::from_str(
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
    )
    .unwrap();
    let spend = PublicKey::from_str(
        "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
    )
    .unwrap();
    let mweb = Address::mweb(scan, spend, NetworkKind::Main);
    assert_eq!(mweb.address_type(), Some(AddressType::Mweb));
    assert!(
        mweb.script_pubkey().is_empty(),
        "MWEB destinations have no transparent script pubkey"
    );

    let mut builder = wallet.build_tx();
    builder.add_recipient(mweb.script_pubkey(), Amount::from_sat(10_000));
    let err = builder.finish().expect_err("MWEB destination must fail");
    assert!(
        matches!(err, CreateTxError::MwebPegInRequiresKernel(0)),
        "expected MwebPegInRequiresKernel, got {err:?}"
    );
}

#[test]
fn add_mweb_pegin_requires_mweb_body() {
    let (mut wallet, _) = get_funded_wallet_wpkh();
    let kernel = [0x11u8; 32];
    let mut builder = wallet.build_tx();
    builder.add_mweb_pegin(kernel, Amount::from_sat(10_000));
    let err = builder
        .finish_mweb_pegin()
        .expect_err("peg-in without mw_tx must fail");
    assert!(
        matches!(err, CreateTxError::MwebPegInMissingBody),
        "expected MwebPegInMissingBody, got {err:?}"
    );
}

#[test]
fn modern_p2sh_m_prefix_round_trips() {
    // sh(wpkh(xprv...)) on Litecoin mainnet displays as M..., not Bitcoin's 3...
    let descriptor = "sh(wpkh(xprv9s21ZrQH143K2fpbqApQL69a4oKdGVnVN52R82Ft7d1pSqgKmajF62acJo3aMszZb6qQ22QsVECSFxvf9uyxFUvFYQMq3QbtwtRSMjLAhMf/0/*))";
    let change = "sh(wpkh(xprv9s21ZrQH143K2fpbqApQL69a4oKdGVnVN52R82Ft7d1pSqgKmajF62acJo3aMszZb6qQ22QsVECSFxvf9uyxFUvFYQMq3QbtwtRSMjLAhMf/1/*))";

    let mut wallet = Wallet::create(descriptor, change)
        .network(Network::Bitcoin)
        .create_wallet_no_persist()
        .unwrap();

    let addr = wallet.next_unused_address(KeychainKind::External).address;
    assert!(
        addr.to_string().starts_with('M'),
        "Litecoin mainnet P2SH must display as M..., got {addr}"
    );
    assert_eq!(addr.address_type(), Some(AddressType::P2sh));

    let parsed = Address::from_str(&addr.to_string())
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap();
    assert_eq!(parsed, addr);
    assert_eq!(parsed.script_pubkey(), addr.script_pubkey());

    // Known mainnet M... fixture from the chain regression suite.
    let fixture = Address::from_str("MQmSgrLBGkwxsaqULx1MsAYLywd6qpoMCN")
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap();
    assert!(fixture.to_string().starts_with('M'));
    assert_eq!(fixture.address_type(), Some(AddressType::P2sh));
}
