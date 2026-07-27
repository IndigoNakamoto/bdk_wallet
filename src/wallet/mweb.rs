//! Phase 6 minimal MWEB facade: combined balance and high-level send helpers.
//!
//! Callers still own [`bdk_mweb::MwebCoinDatabase`]. MWEB coins never enter
//! transparent [`IndexedTxGraph`](bdk_chain::IndexedTxGraph).

use alloc::vec::Vec;
use core::fmt;

use bdk_mweb::keys::MasterKeys;
use bdk_mweb::tx_builder::{
    build_pegin, FinishedMwebPegin, FinishedMwebTx, MwebTxBuilder, CHANGE_ADDRESS_INDEX,
};
use bdk_mweb::{MwebCoin, MwebCoinDatabase};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::All;
use bitcoin::{Address, Amount, Network, NetworkKind, ScriptBuf};

use crate::wallet::error::CreateTxError;
use crate::wallet::{Balance, Wallet};

/// Transparent [`Balance`] plus unspent MWEB value from a caller-owned database.
///
/// MWEB amounts have no confirmation buckets yet: once a coin is in
/// [`MwebCoinDatabase`] it is treated as spendable (`trusted_spendable` includes
/// the full `mweb` amount). Callers should only insert after maturity/scan.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub struct CombinedBalance {
    /// Existing transparent wallet balance.
    pub transparent: Balance,
    /// Sum of unspent MWEB coins in the provided database.
    pub mweb: Amount,
}

impl CombinedBalance {
    /// Transparent total plus MWEB unspent.
    pub fn total(&self) -> Amount {
        self.transparent.total() + self.mweb
    }

    /// Transparent trusted-spendable plus full MWEB unspent.
    pub fn trusted_spendable(&self) -> Amount {
        self.transparent.trusted_spendable() + self.mweb
    }
}

/// Result of [`Wallet::prepare_mweb_pegin`].
#[derive(Debug)]
pub struct PreparedMwebPegin {
    /// Unsigned (or partially signed) transparent peg-in PSBT.
    pub psbt: Psbt,
    /// MWEB body to [`super::attach_mweb_tx`] after extract.
    pub mw_tx: bitcoin::blockdata::mimblewimble::Transaction,
    /// Authored peg-in metadata (kernel id, owned outputs for later DB insert).
    pub pegin: FinishedMwebPegin,
}

/// Errors from Phase 6 MWEB facade helpers.
#[derive(Debug)]
pub enum MwebFacadeError {
    /// No unspent coins in the MWEB database.
    NoMwebCoins,
    /// Selected MWEB inputs cannot cover recipients + fee.
    InsufficientMwebFunds {
        /// Amount required (recipients + fee).
        needed: Amount,
        /// Sum of unspent MWEB coins.
        available: Amount,
    },
    /// Transparent [`TxBuilder`] / PSBT construction failed.
    CreateTx(CreateTxError),
    /// `bdk_mweb` authoring / crypto error.
    Mweb(bdk_mweb::Error),
}

impl fmt::Display for MwebFacadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMwebCoins => write!(f, "no unspent MWEB coins"),
            Self::InsufficientMwebFunds { needed, available } => {
                write!(
                    f,
                    "insufficient MWEB funds: needed {needed}, available {available}"
                )
            }
            Self::CreateTx(e) => write!(f, "create tx: {e}"),
            Self::Mweb(e) => write!(f, "mweb: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MwebFacadeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateTx(e) => Some(e),
            Self::Mweb(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CreateTxError> for MwebFacadeError {
    fn from(e: CreateTxError) -> Self {
        Self::CreateTx(e)
    }
}

impl From<bdk_mweb::Error> for MwebFacadeError {
    fn from(e: bdk_mweb::Error) -> Self {
        Self::Mweb(e)
    }
}

/// Map wallet [`Network`] to MWEB [`NetworkKind`].
pub fn network_kind(network: Network) -> NetworkKind {
    match network {
        Network::Bitcoin => NetworkKind::Main,
        _ => NetworkKind::Test,
    }
}

/// Greedy MWEB coin selection over `unspent`.
///
/// Prefers a single coin that covers `needed` (smallest such coin). Otherwise
/// selects largest-first until the sum covers `needed`.
pub fn select_mweb_coins(unspent: &[MwebCoin], needed: u64) -> Result<Vec<MwebCoin>, MwebFacadeError> {
    if unspent.is_empty() {
        return Err(MwebFacadeError::NoMwebCoins);
    }
    let available: u64 = unspent.iter().map(|c| c.amount).sum();
    if available < needed {
        return Err(MwebFacadeError::InsufficientMwebFunds {
            needed: Amount::from_sat(needed),
            available: Amount::from_sat(available),
        });
    }

    // Single-input preferred: smallest coin that alone covers `needed`.
    let mut singles: Vec<&MwebCoin> = unspent.iter().filter(|c| c.amount >= needed).collect();
    if !singles.is_empty() {
        singles.sort_by_key(|c| c.amount);
        return Ok(vec![singles[0].clone()]);
    }

    // Largest-first prefix.
    let mut sorted = unspent.to_vec();
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));
    let mut selected = Vec::new();
    let mut sum = 0u64;
    for coin in sorted {
        sum = sum.saturating_add(coin.amount);
        selected.push(coin);
        if sum >= needed {
            break;
        }
    }
    Ok(selected)
}

impl Wallet {
    /// Transparent balance plus unspent MWEB from a caller-owned database.
    ///
    /// Does not change [`Wallet::balance`] semantics.
    pub fn balance_combined(&self, mweb: &MwebCoinDatabase) -> CombinedBalance {
        CombinedBalance {
            transparent: self.balance(),
            mweb: Amount::from_sat(mweb.balance()),
        }
    }

    /// Author a peg-in body and assemble the transparent v9 PSBT half.
    ///
    /// Caller must sign `psbt`, extract, [`super::attach_mweb_tx`], broadcast,
    /// then insert scanned/`pegin.outputs` into their [`MwebCoinDatabase`] after maturity.
    pub fn prepare_mweb_pegin(
        &mut self,
        keys: &MasterKeys,
        receive_index: u32,
        pegin_amount: Amount,
        mweb_fee: Amount,
        transparent_fee: Amount,
        secp: &Secp256k1<All>,
    ) -> Result<PreparedMwebPegin, MwebFacadeError> {
        let pegin = build_pegin(
            keys,
            receive_index,
            pegin_amount.to_sat(),
            mweb_fee.to_sat(),
            network_kind(self.network()),
            secp,
        )?;
        let mut builder = self.build_tx();
        builder.apply_mweb_pegin(&pegin);
        builder.fee_absolute(transparent_fee);
        let (psbt, mw_tx) = builder.finish_mweb_pegin()?;
        Ok(PreparedMwebPegin { psbt, mw_tx, pegin })
    }

    /// Build an MWEB→MWEB spend from coins in `db`.
    pub fn build_mweb_send(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        recipient: Address,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&db.unspent_vec(), needed)?;
        let mut builder = MwebTxBuilder::new();
        for coin in selected {
            builder = builder.add_input(coin);
        }
        builder = builder
            .add_recipient(recipient, amount.to_sat())
            .fee(fee.to_sat());
        Ok(builder.finish(keys, change_index, network_kind(self.network()), secp)?)
    }

    /// Build a peg-out from coins in `db` to a transparent `script_pubkey`.
    pub fn build_mweb_pegout(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        script_pubkey: ScriptBuf,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&db.unspent_vec(), needed)?;
        let mut builder = MwebTxBuilder::new();
        for coin in selected {
            builder = builder.add_input(coin);
        }
        builder = builder
            .add_pegout(script_pubkey, amount.to_sat())
            .fee(fee.to_sat());
        Ok(builder.finish(keys, change_index, network_kind(self.network()), secp)?)
    }

    /// Convenience: peg-out with Core change index (`0`).
    pub fn build_mweb_pegout_default_change(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        script_pubkey: ScriptBuf,
        amount: Amount,
        fee: Amount,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        self.build_mweb_pegout(
            db,
            keys,
            script_pubkey,
            amount,
            fee,
            CHANGE_ADDRESS_INDEX,
            secp,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(amount: u64) -> MwebCoin {
        MwebCoin {
            output_id: [amount as u8; 32],
            commitment: [0; 33],
            amount,
            address_index: 0,
            blind: [0; 32],
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
        }
    }

    #[test]
    fn select_prefers_smallest_single_cover() {
        let coins = vec![coin(100), coin(50), coin(200)];
        let selected = select_mweb_coins(&coins, 60).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].amount, 100);
    }

    #[test]
    fn select_largest_first_when_no_single() {
        let coins = vec![coin(40), coin(30), coin(25)];
        let selected = select_mweb_coins(&coins, 60).unwrap();
        let sum: u64 = selected.iter().map(|c| c.amount).sum();
        assert!(sum >= 60);
        assert_eq!(selected[0].amount, 40);
    }

    #[test]
    fn select_errors_when_empty_or_short() {
        assert!(matches!(
            select_mweb_coins(&[], 1),
            Err(MwebFacadeError::NoMwebCoins)
        ));
        assert!(matches!(
            select_mweb_coins(&[coin(10)], 20),
            Err(MwebFacadeError::InsufficientMwebFunds { .. })
        ));
    }
}
