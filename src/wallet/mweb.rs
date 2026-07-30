//! Phase 6+ MWEB facade: combined balance, send helpers, and parallel [`MwebStore`].
//!
//! Callers may still own a bare [`bdk_mweb::MwebCoinDatabase`]. Prefer [`MwebStore`]
//! for load/persist beside the wallet. MWEB coins never enter transparent
//! [`IndexedTxGraph`](bdk_chain::IndexedTxGraph).

use alloc::vec::Vec;
use core::fmt;

use bdk_mweb::keys::MasterKeys;
use bdk_mweb::psbt_fund::{
    change_from_funded, fund_mweb_pegin, fund_mweb_spend, sign_funded_mweb, sign_funded_mweb_pegin,
    FundedMwebPsbt,
};
use bdk_mweb::tx_builder::{FinishedMwebTx, MwebTxBuilder, CHANGE_ADDRESS_INDEX};
use bdk_mweb::{MwebBalance, MwebCoin, MwebCoinDatabase, MWEB_PEGIN_MATURITY};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::All;
use bitcoin::{Address, Amount, Network, NetworkKind, ScriptBuf, Transaction};

use crate::wallet::error::CreateTxError;
use crate::wallet::{Balance, Wallet};

/// Transparent [`Balance`] plus bucketed MWEB value from a caller-owned database.
///
/// **Spendable** MWEB is a stricter subset of `mweb_confirmed`: confirmed **and**
/// peg-in mature ([`MWEB_PEGIN_MATURITY`] blocks). Use
/// [`MwebCoinDatabase::unspent_spendable`] for selection.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub struct CombinedBalance {
    /// Existing transparent wallet balance.
    pub transparent: Balance,
    /// Confirmed MWEB unspent (1+ confirmation at the tip used for bucketing).
    pub mweb_confirmed: Amount,
    /// Unconfirmed / unknown-height MWEB unspent.
    pub mweb_untrusted_pending: Amount,
}

impl CombinedBalance {
    /// Sum of confirmed + pending MWEB.
    pub fn mweb_total(&self) -> Amount {
        self.mweb_confirmed + self.mweb_untrusted_pending
    }

    /// Transparent total plus all MWEB unspent.
    pub fn total(&self) -> Amount {
        self.transparent.total() + self.mweb_total()
    }

    /// Transparent trusted-spendable plus confirmed MWEB only.
    pub fn trusted_spendable(&self) -> Amount {
        self.transparent.trusted_spendable() + self.mweb_confirmed
    }
}

/// Parallel MWEB coin store owned beside a [`Wallet`] (not part of `Wallet::ChangeSet`).
#[derive(Debug, Default, Clone)]
pub struct MwebStore {
    db: MwebCoinDatabase,
}

impl MwebStore {
    /// Empty in-memory store.
    pub fn new() -> Self {
        Self {
            db: MwebCoinDatabase::new(),
        }
    }

    /// Wrap an existing database.
    pub fn from_db(db: MwebCoinDatabase) -> Self {
        Self { db }
    }

    /// Shared access to the coin database.
    pub fn db(&self) -> &MwebCoinDatabase {
        &self.db
    }

    /// Mutable access to the coin database.
    pub fn db_mut(&mut self) -> &mut MwebCoinDatabase {
        &mut self.db
    }

    /// Consume the store, returning the database.
    pub fn into_db(self) -> MwebCoinDatabase {
        self.db
    }

    /// Load from an aggregated `bdk_mweb` changeset (e.g. file_store dump).
    pub fn from_changeset(cs: bdk_mweb::ChangeSet) -> Self {
        Self {
            db: MwebCoinDatabase::from_changeset(cs),
        }
    }

    /// Take staged mutations for persistence.
    pub fn take_staged(&mut self) -> bdk_mweb::ChangeSet {
        self.db.take_staged()
    }

    /// Append staged mutations to a `bdk_file_store::Store` and clear the stage.
    #[cfg(feature = "file_store")]
    pub fn persist_file_store(
        &mut self,
        store: &mut bdk_file_store::Store<bdk_mweb::ChangeSet>,
    ) -> Result<(), std::io::Error> {
        let staged = self.db.take_staged();
        store.append(&staged)?;
        Ok(())
    }

    /// Load from a file_store path (creates if missing).
    #[cfg(feature = "file_store")]
    pub fn load_file_store(
        magic: &[u8],
        path: impl AsRef<std::path::Path>,
    ) -> Result<
        (Self, bdk_file_store::Store<bdk_mweb::ChangeSet>),
        bdk_file_store::StoreErrorWithDump<bdk_mweb::ChangeSet>,
    > {
        let (store, aggregated) = bdk_file_store::Store::load_or_create(magic, path.as_ref())?;
        let db = aggregated
            .map(MwebCoinDatabase::from_changeset)
            .unwrap_or_else(MwebCoinDatabase::new);
        Ok((Self { db }, store))
    }

    /// Persist staged mutations into a SQLite transaction.
    #[cfg(feature = "mweb-sqlite")]
    pub fn persist_sqlite(
        &mut self,
        db_tx: &bdk_chain::rusqlite::Transaction<'_>,
    ) -> bdk_chain::rusqlite::Result<()> {
        let staged = self.db.take_staged();
        bdk_mweb::ChangeSet::persist_to_sqlite(&staged, db_tx)
    }

    /// Load from SQLite (initializes tables).
    #[cfg(feature = "mweb-sqlite")]
    pub fn load_sqlite(
        db_tx: &bdk_chain::rusqlite::Transaction<'_>,
    ) -> bdk_chain::rusqlite::Result<Self> {
        bdk_mweb::ChangeSet::init_sqlite_tables(db_tx)?;
        let cs = bdk_mweb::ChangeSet::from_sqlite(db_tx)?;
        Ok(Self::from_changeset(cs))
    }

    /// Clear inclusion heights for coins at or above `height` (reorg disconnect).
    pub fn disconnect_from(&mut self, height: u32) {
        self.db.disconnect_from(height);
    }

    /// Tip-driven LIP-0006 sync into this store.
    pub fn sync_at_tip<S: bdk_mweb::lip0006::MwebUtxoSource>(
        &mut self,
        source: &mut S,
        keys: &MasterKeys,
        book: &bdk_mweb::AddressBook,
        tip_hash: bitcoin::BlockHash,
        tip_height: u32,
        verify: bdk_mweb::lip0006::VerifyMode,
        secp: &Secp256k1<All>,
    ) -> Result<bdk_mweb::lip0006::SyncResult, bdk_mweb::Error> {
        bdk_mweb::lip0006::sync_mweb_at_tip(
            source,
            keys,
            book,
            &mut self.db,
            secp,
            tip_hash,
            tip_height,
            verify,
        )
    }

    /// mwebsync-shaped differential sync (leafset diff + UTXO dating).
    pub fn sync_differential<P, N, S>(
        &mut self,
        syncer: &bdk_mweb::mweb_sync::MwebSyncer,
        headers: &P,
        notifier: &mut N,
        source: &mut S,
        state: &mut bdk_mweb::mweb_sync::SyncState,
        keys: &MasterKeys,
        book: &bdk_mweb::AddressBook,
        secp: &Secp256k1<All>,
    ) -> Result<bdk_mweb::lip0006::SyncResult, bdk_mweb::Error>
    where
        P: bdk_mweb::mweb_sync::BlockHeaderProvider,
        N: bdk_mweb::mweb_sync::SyncNotifier,
        S: bdk_mweb::lip0006::MwebUtxoSource,
    {
        self.sync_differential_checkpointed(
            syncer, headers, notifier, source, state, keys, book, secp, None,
        )
    }

    /// [`Self::sync_differential`] with an optional mid-download checkpoint callback.
    pub fn sync_differential_checkpointed<P, N, S>(
        &mut self,
        syncer: &bdk_mweb::mweb_sync::MwebSyncer,
        headers: &P,
        notifier: &mut N,
        source: &mut S,
        state: &mut bdk_mweb::mweb_sync::SyncState,
        keys: &MasterKeys,
        book: &bdk_mweb::AddressBook,
        secp: &Secp256k1<All>,
        checkpoint: Option<
            &mut dyn FnMut(&bdk_mweb::mweb_sync::SyncState, &mut MwebCoinDatabase),
        >,
    ) -> Result<bdk_mweb::lip0006::SyncResult, bdk_mweb::Error>
    where
        P: bdk_mweb::mweb_sync::BlockHeaderProvider,
        N: bdk_mweb::mweb_sync::SyncNotifier,
        S: bdk_mweb::lip0006::MwebUtxoSource,
    {
        syncer.run_once(
            headers,
            notifier,
            source,
            state,
            keys,
            book,
            &mut self.db,
            secp,
            checkpoint,
        )
    }

    /// Differential sync with library [`PeerPool`] ban/rotate on leafset/PMMR/timeout errors.
    ///
    /// For mid-pass checkpoints, call [`PeerPool::with_failover`] around
    /// [`Self::sync_differential_checkpointed`] from the application (see `mainnet_mweb`).
    pub fn sync_differential_pooled<P, N>(
        &mut self,
        syncer: &bdk_mweb::mweb_sync::MwebSyncer,
        headers: &P,
        notifier: &mut N,
        pool: &mut bdk_mweb::mweb_sync::PeerPool,
        network: Network,
        state: &mut bdk_mweb::mweb_sync::SyncState,
        keys: &MasterKeys,
        book: &bdk_mweb::AddressBook,
        secp: &Secp256k1<All>,
    ) -> Result<bdk_mweb::lip0006::SyncResult, bdk_mweb::Error>
    where
        P: bdk_mweb::mweb_sync::BlockHeaderProvider,
        N: bdk_mweb::mweb_sync::SyncNotifier,
    {
        syncer.run_once_with_pool(
            headers, notifier, pool, network, state, keys, book, &mut self.db, secp,
        )
    }
}

/// Result of [`Wallet::prepare_mweb_pegin`].
///
/// The PSBT already carries signed MWEB maps; after transparent signing call
/// [`bdk_mweb::extract_tx_with_mweb`] (or [`super::extract_prepared_mweb_pegin`]).
#[derive(Debug)]
pub struct PreparedMwebPegin {
    /// Transparent peg-in PSBT with MWEB maps already populated and signed.
    pub psbt: Psbt,
    /// Peg-in kernel id (= v9 witness program).
    pub kernel_id: [u8; 32],
    /// Transparent v9 output value.
    pub pegin_amount: Amount,
    /// Owned stealth outputs for insertion after maturity.
    pub outputs: Vec<MwebCoin>,
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
    /// Transparent balance plus MWEB buckets at the wallet tip height.
    pub fn balance_combined(&self, mweb: &MwebCoinDatabase) -> CombinedBalance {
        self.balance_combined_at(mweb, self.latest_checkpoint().height())
    }

    /// Transparent balance plus MWEB buckets at `tip_height`.
    pub fn balance_combined_at(&self, mweb: &MwebCoinDatabase, tip_height: u32) -> CombinedBalance {
        let buckets: MwebBalance = mweb.balance_at(tip_height);
        CombinedBalance {
            transparent: self.balance(),
            mweb_confirmed: Amount::from_sat(buckets.confirmed),
            mweb_untrusted_pending: Amount::from_sat(buckets.untrusted_pending),
        }
    }

    /// [`balance_combined`] using an [`MwebStore`].
    pub fn balance_combined_store(&self, store: &MwebStore) -> CombinedBalance {
        self.balance_combined(store.db())
    }

    /// Finalize MWEB maps on a native [`Psbt`] using coin secrets from `db` (ltcwallet
    /// `SignMwebComponents` shape). Prefer [`Self::fund_mweb_send`] +
    /// [`Self::sign_and_extract_funded_mweb`] for the happy path.
    pub fn sign_mweb_components(
        &self,
        psbt: &mut Psbt,
        db: &MwebCoinDatabase,
        secp: &Secp256k1<All>,
    ) -> Result<(), MwebFacadeError> {
        let mut coins = db.unspent_vec();
        for inp in &psbt.mweb_inputs {
            if let Some(id) = inp.output_id {
                if let Some(c) = db.get_spent(&id) {
                    if !coins.iter().any(|x| x.output_id == id) {
                        coins.push(c.clone());
                    }
                }
            }
        }
        bdk_mweb::sign_mweb_components(psbt, &coins, secp)?;
        Ok(())
    }

    /// Author a peg-in via in-PSBT fund→sign, then assemble the transparent v9 PSBT half.
    ///
    /// Order: `fund_mweb_pegin` → `sign_funded_mweb_pegin` (computes `kernel_id`) → transparent
    /// coin selection with v9 program → merge MWEB maps onto the PSBT.
    ///
    /// Caller must sign the transparent inputs on `psbt`, then
    /// [`super::extract_prepared_mweb_pegin`] / [`bdk_mweb::extract_tx_with_mweb`], broadcast,
    /// then insert `outputs` into their [`MwebCoinDatabase`] after maturity.
    pub fn prepare_mweb_pegin(
        &mut self,
        keys: &MasterKeys,
        receive_index: u32,
        pegin_amount: Amount,
        mweb_fee: Amount,
        transparent_fee: Amount,
        secp: &Secp256k1<All>,
    ) -> Result<PreparedMwebPegin, MwebFacadeError> {
        let mut funded = fund_mweb_pegin(
            keys,
            receive_index,
            pegin_amount.to_sat(),
            mweb_fee.to_sat(),
            network_kind(self.network()),
            secp,
        )?;
        let kernel_id = sign_funded_mweb_pegin(&mut funded, keys, secp)?;
        let mut builder = self.build_tx();
        builder.add_mweb_pegin(kernel_id, pegin_amount);
        builder.fee_absolute(transparent_fee);
        let mut psbt = builder.finish()?;
        // Merge signed MWEB maps onto the transparent PSBT (no sidecar mw_tx).
        psbt.mweb_tx_offset = funded.psbt.mweb_tx_offset;
        psbt.mweb_stealth_offset = funded.psbt.mweb_stealth_offset;
        psbt.mweb_kernels = funded.psbt.mweb_kernels;
        psbt.mweb_inputs = funded.psbt.mweb_inputs;
        psbt.mweb_outputs = funded.psbt.mweb_outputs;
        Ok(PreparedMwebPegin {
            psbt,
            kernel_id,
            pegin_amount,
            outputs: funded.outputs,
        })
    }

    /// Fund an MWEB→MWEB spend (maps only, no `mw_tx`) from spendable coins.
    pub fn fund_mweb_send(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        recipient: Address,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        secp: &Secp256k1<All>,
    ) -> Result<FundedMwebPsbt, MwebFacadeError> {
        let tip = self.latest_checkpoint().height();
        let pool = db.unspent_spendable(tip, MWEB_PEGIN_MATURITY);
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&pool, needed)?;
        Ok(fund_mweb_spend(
            selected,
            vec![(recipient, amount.to_sat())],
            vec![],
            fee.to_sat(),
            keys,
            change_index,
            network_kind(self.network()),
            secp,
        )?)
    }

    /// Sign a [`FundedMwebPsbt`] and extract a network transaction (`mw_tx` at extract only).
    pub fn sign_and_extract_funded_mweb(
        &self,
        funded: &mut FundedMwebPsbt,
        keys: &MasterKeys,
        secp: &Secp256k1<All>,
    ) -> Result<(Transaction, Option<MwebCoin>), MwebFacadeError> {
        sign_funded_mweb(funded, keys, secp)?;
        let change = change_from_funded(funded, keys, secp)?;
        let tx = funded.extract_tx()?;
        Ok((tx, change))
    }

    /// Build an MWEB→MWEB spend from **confirmed** coins in `db` at the wallet tip.
    ///
    /// Prefer [`Self::fund_mweb_send`] + [`Self::sign_and_extract_funded_mweb`] for the
    /// ltcsuite in-PSBT path.
    #[deprecated(
        since = "3.1.0",
        note = "use fund_mweb_send + sign_and_extract_funded_mweb instead"
    )]
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
        #[allow(deprecated)]
        self.build_mweb_send_with(
            db,
            keys,
            recipient,
            amount,
            fee,
            change_index,
            false,
            secp,
        )
    }

    /// Build an MWEB→MWEB spend; set `include_unconfirmed` to also spend pending coins.
    #[deprecated(
        since = "3.1.0",
        note = "use fund_mweb_send + sign_and_extract_funded_mweb instead"
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn build_mweb_send_with(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        recipient: Address,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        include_unconfirmed: bool,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        let tip = self.latest_checkpoint().height();
        let pool = if include_unconfirmed {
            db.unspent_vec()
        } else {
            // Spendable = confirmed + peg-in maturity.
            db.unspent_spendable(tip, MWEB_PEGIN_MATURITY)
        };
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&pool, needed)?;
        let mut builder = MwebTxBuilder::new();
        for coin in selected {
            builder = builder.add_input(coin);
        }
        builder = builder
            .add_recipient(recipient, amount.to_sat())
            .fee(fee.to_sat());
        Ok(builder.finish(keys, change_index, network_kind(self.network()), secp)?)
    }

    /// Fund a peg-out (maps only) from spendable coins.
    pub fn fund_mweb_pegout(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        script_pubkey: ScriptBuf,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        secp: &Secp256k1<All>,
    ) -> Result<FundedMwebPsbt, MwebFacadeError> {
        let tip = self.latest_checkpoint().height();
        let pool = db.unspent_spendable(tip, MWEB_PEGIN_MATURITY);
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&pool, needed)?;
        Ok(fund_mweb_spend(
            selected,
            vec![],
            vec![(script_pubkey, amount.to_sat())],
            fee.to_sat(),
            keys,
            change_index,
            network_kind(self.network()),
            secp,
        )?)
    }

    /// Build a peg-out from **confirmed** coins in `db` to a transparent `script_pubkey`.
    ///
    /// Prefer [`Self::fund_mweb_pegout`] + [`Self::sign_and_extract_funded_mweb`].
    #[deprecated(
        since = "3.1.0",
        note = "use fund_mweb_pegout + sign_and_extract_funded_mweb instead"
    )]
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
        #[allow(deprecated)]
        self.build_mweb_pegout_with(
            db,
            keys,
            script_pubkey,
            amount,
            fee,
            change_index,
            false,
            secp,
        )
    }

    /// Peg-out helper; set `include_unconfirmed` to also spend pending coins.
    #[deprecated(
        since = "3.1.0",
        note = "use fund_mweb_pegout + sign_and_extract_funded_mweb instead"
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn build_mweb_pegout_with(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        script_pubkey: ScriptBuf,
        amount: Amount,
        fee: Amount,
        change_index: u32,
        include_unconfirmed: bool,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        let tip = self.latest_checkpoint().height();
        let pool = if include_unconfirmed {
            db.unspent_vec()
        } else {
            db.unspent_spendable(tip, MWEB_PEGIN_MATURITY)
        };
        let needed = amount.to_sat().saturating_add(fee.to_sat());
        let selected = select_mweb_coins(&pool, needed)?;
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
    #[deprecated(
        since = "3.1.0",
        note = "use fund_mweb_pegout + sign_and_extract_funded_mweb instead"
    )]
    pub fn build_mweb_pegout_default_change(
        &self,
        db: &MwebCoinDatabase,
        keys: &MasterKeys,
        script_pubkey: ScriptBuf,
        amount: Amount,
        fee: Amount,
        secp: &Secp256k1<All>,
    ) -> Result<FinishedMwebTx, MwebFacadeError> {
        #[allow(deprecated)]
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
            block_height: Some(1),
            is_pegin: false,
            leaf_index: None,
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
