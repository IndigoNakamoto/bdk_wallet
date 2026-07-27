// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Descriptor templates
//!
//! This module contains the definition of various common script templates that are ready to be
//! used. See the documentation of each template for an example.

use bitcoin::{bip32, NetworkKind};
use miniscript::{Legacy, Segwitv0, Tap};

use super::{ExtendedDescriptor, IntoWalletDescriptor, KeyMap};
use crate::descriptor::DescriptorError;
use crate::keys::{DerivableKey, IntoDescriptorKey, ValidNetworkKinds};
use crate::wallet::utils::SecpCtx;
use crate::{descriptor, KeychainKind};

/// Type alias for the return type of [`DescriptorTemplate`], [`descriptor!`](crate::descriptor!)
/// and others.
pub type DescriptorTemplateOut = (ExtendedDescriptor, KeyMap, ValidNetworkKinds);

/// Trait for descriptor templates that can be built into a full descriptor.
///
/// Since [`IntoWalletDescriptor`] is implemented for any [`DescriptorTemplate`], they can also be
/// passed directly to the [`Wallet`](crate::Wallet) constructor.
///
/// ## Example
///
/// ```
/// use bdk_wallet::descriptor::error::Error as DescriptorError;
/// use bdk_wallet::keys::{IntoDescriptorKey, KeyError};
/// use bdk_wallet::miniscript::Legacy;
/// use bdk_wallet::template::{DescriptorTemplate, DescriptorTemplateOut};
/// use bitcoin::NetworkKind;
///
/// struct MyP2PKH<K: IntoDescriptorKey<Legacy>>(K);
///
/// impl<K: IntoDescriptorKey<Legacy>> DescriptorTemplate for MyP2PKH<K> {
///     fn build(
///         self,
///         network_kind: NetworkKind,
///     ) -> Result<DescriptorTemplateOut, DescriptorError> {
///         Ok(bdk_wallet::descriptor!(pkh(self.0))?)
///     }
/// }
/// ```
pub trait DescriptorTemplate {
    /// Build the complete descriptor.
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError>;
}

/// Turns a [`DescriptorTemplate`] into a valid wallet descriptor by calling its
/// [`build`](DescriptorTemplate::build) method.
impl<T: DescriptorTemplate> IntoWalletDescriptor for T {
    fn into_wallet_descriptor(
        self,
        secp: &SecpCtx,
        network_kind: NetworkKind,
    ) -> Result<(ExtendedDescriptor, KeyMap), DescriptorError> {
        self.build(network_kind)?
            .into_wallet_descriptor(secp, network_kind)
    }
}

/// P2PKH template. Expands to a descriptor `pkh(key)`.
///
/// ## Example
///
/// ```
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::Wallet;
/// # use bdk_wallet::KeychainKind;
/// use bdk_wallet::template::P2Pkh;
///
/// let key_external =
///     bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")?;
/// let key_internal =
///     bitcoin::PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW")?;
/// let mut wallet = Wallet::create(P2Pkh(key_external), P2Pkh(key_internal))
///     .network(Network::Testnet4)
///     .create_wallet_no_persist()?;
///
/// assert_eq!(
///     wallet
///         .next_unused_address(KeychainKind::External)
///         .to_string(),
///     "mwJ8hxFYW19JLuc65RCTaP4v1rzVU8cVMT"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct P2Pkh<K: IntoDescriptorKey<Legacy>>(pub K);

impl<K: IntoDescriptorKey<Legacy>> DescriptorTemplate for P2Pkh<K> {
    fn build(self, _network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        descriptor!(pkh(self.0))
    }
}

/// P2WPKH-P2SH template. Expands to a descriptor `sh(wpkh(key))`
///
/// ## Example
///
/// ```
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::Wallet;
/// # use bdk_wallet::KeychainKind;
/// use bdk_wallet::template::P2Wpkh_P2Sh;
///
/// let key_external =
///     bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")?;
/// let key_internal =
///     bitcoin::PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW")?;
/// let mut wallet = Wallet::create(P2Wpkh_P2Sh(key_external), P2Wpkh_P2Sh(key_internal))
///     .network(Network::Testnet4)
///     .create_wallet_no_persist()?;
///
/// assert_eq!(
///     wallet
///         .next_unused_address(KeychainKind::External)
///         .to_string(),
///     "QeRa56MTT34jkfg94tV4a6ipgK6NsjbGBY"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub struct P2Wpkh_P2Sh<K: IntoDescriptorKey<Segwitv0>>(pub K);

impl<K: IntoDescriptorKey<Segwitv0>> DescriptorTemplate for P2Wpkh_P2Sh<K> {
    fn build(self, _network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        descriptor!(sh(wpkh(self.0)))
    }
}

/// P2WPKH template. Expands to a descriptor `wpkh(key)`
///
/// ## Example
///
/// ```
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::Wallet;
/// # use bdk_wallet::KeychainKind;
/// use bdk_wallet::template::P2Wpkh;
///
/// let key_external =
///     bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")?;
/// let key_internal =
///     bitcoin::PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW")?;
/// let mut wallet = Wallet::create(P2Wpkh(key_external), P2Wpkh(key_internal))
///     .network(Network::Testnet4)
///     .create_wallet_no_persist()?;
///
/// assert_eq!(
///     wallet
///         .next_unused_address(KeychainKind::External)
///         .to_string(),
///     "tltc1q4525hmgw265tl3drrl8jjta7ayffu6jfr0a4zy"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct P2Wpkh<K: IntoDescriptorKey<Segwitv0>>(pub K);

impl<K: IntoDescriptorKey<Segwitv0>> DescriptorTemplate for P2Wpkh<K> {
    fn build(self, _network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        descriptor!(wpkh(self.0))
    }
}

/// P2TR template. Expands to a descriptor `tr(key)`
///
/// ## Example
///
/// ```
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::Wallet;
/// # use bdk_wallet::KeychainKind;
/// use bdk_wallet::template::P2TR;
///
/// let key_external =
///     bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")?;
/// let key_internal =
///     bitcoin::PrivateKey::from_wif("cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW")?;
/// let mut wallet = Wallet::create(P2TR(key_external), P2TR(key_internal))
///     .network(Network::Testnet4)
///     .create_wallet_no_persist()?;
///
/// assert_eq!(
///     wallet
///         .next_unused_address(KeychainKind::External)
///         .to_string(),
///     "tltc1pvjf9t34fznr53u5tqhejz4nr69luzkhlvsdsdfq9pglutrpve2xqp5a329"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct P2TR<K: IntoDescriptorKey<Tap>>(pub K);

impl<K: IntoDescriptorKey<Tap>> DescriptorTemplate for P2TR<K> {
    fn build(self, _network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        descriptor!(tr(self.0))
    }
}

/// BIP44 template. Expands to `pkh(key/44'/{0,1}'/0'/{0,1}/*)`
///
/// Since there are hardened derivation steps, this template requires a private derivable key
/// (generally a `xprv`/`tprv`).
///
/// See [`Bip44Public`] for a template that can work with a `xpub`/`tpub`.
///
/// ## Example
///
/// ```rust
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip44;
///
/// let key = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m")?;
/// let mut wallet = Wallet::create(Bip44(key.clone(), KeychainKind::External), Bip44(key, KeychainKind::Internal))
///     .network(Network::Testnet4)
///     .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "mmogjc7HJEZkrLqyQYqJmxUqFaC7i4uf89");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "pkh([c55b303f/44'/1'/0']tpubDCuorCpzvYS2LCD75BR46KHE8GdDeg1wsAgNZeNr6DaB5gQK1o14uErKwKLuFmeemkQ6N2m3rNgvctdJLyr7nwu2yia7413Hhg8WWE44cgT/0/*)#5wrnv0xt");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip44<K: DerivableKey<Legacy>>(pub K, pub KeychainKind);

impl<K: DerivableKey<Legacy>> DescriptorTemplate for Bip44<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Pkh(legacy::make_bipxx_private(
            44,
            self.0,
            self.1,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP44 public template. Expands to `pkh(key/{0,1}/*)`
///
/// This assumes that the key used has already been derived with `m/44'/2'/0'` for Mainnet or
/// `m/44'/1'/0'` for Testnet.
///
/// This template requires the parent fingerprint to populate correctly the metadata of PSBTs.
///
/// See [`Bip44`] for a template that does the full derivation, but requires private data
/// for the key.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{KeychainKind, Wallet};
/// use bdk_wallet::template::Bip44Public;
///
/// let key = bitcoin::bip32::Xpub::from_str("tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU")?;
/// let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f")?;
/// let mut wallet = Wallet::create(
///     Bip44Public(key.clone(), fingerprint, KeychainKind::External),
///     Bip44Public(key, fingerprint, KeychainKind::Internal),
///     )
///     .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "miNG7dJTzJqNbFS19svRdTCisC65dsubtR");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "pkh([c55b303f/44'/1'/0']tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU/0/*)#cfhumdqz");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip44Public<K: DerivableKey<Legacy>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Legacy>> DescriptorTemplate for Bip44Public<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Pkh(legacy::make_bipxx_public(
            44,
            self.0,
            self.1,
            self.2,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP49 template. Expands to `sh(wpkh(key/49'/{0,1}'/0'/{0,1}/*))`
///
/// Since there are hardened derivation steps, this template requires a private derivable key
/// (generally a `xprv`/`tprv`).
///
/// See [`Bip49Public`] for a template that can work with a `xpub`/`tpub`.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip49;
///
/// let key = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m")?;
/// let mut wallet = Wallet::create(
///     Bip49(key.clone(), KeychainKind::External),
///     Bip49(key, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "QYMWdBfWeay9WiTVVaAF18WnKRYH57qf5b");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "sh(wpkh([c55b303f/49'/1'/0']tpubDDYr4kdnZgjjShzYNjZUZXUUtpXaofdkMaipyS8ThEh45qFmhT4hKYways7UXmg6V7het1QiFo9kf4kYUXyDvV4rHEyvSpys9pjCB3pukxi/0/*))#s9vxlc8e");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip49<K: DerivableKey<Segwitv0>>(pub K, pub KeychainKind);

impl<K: DerivableKey<Segwitv0>> DescriptorTemplate for Bip49<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Wpkh_P2Sh(segwit_v0::make_bipxx_private(
            49,
            self.0,
            self.1,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP49 public template. Expands to `sh(wpkh(key/{0,1}/*))`
///
/// This assumes that the key used has already been derived with `m/49'/2'/0'` for Mainnet or
/// `m/49'/1'/0'` for Testnet.
///
/// This template requires the parent fingerprint to populate correctly the metadata of PSBTs.
///
/// See [`Bip49`] for a template that does the full derivation, but requires private data
/// for the key.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip49Public;
///
/// let key = bitcoin::bip32::Xpub::from_str("tpubDC49r947KGK52X5rBWS4BLs5m9SRY3pYHnvRrm7HcybZ3BfdEsGFyzCMzayi1u58eT82ZeyFZwH7DD6Q83E3fM9CpfMtmnTygnLfP59jL9L")?;
/// let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f")?;
/// let mut wallet = Wallet::create(
///     Bip49Public(key.clone(), fingerprint, KeychainKind::External),
///     Bip49Public(key, fingerprint, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "QWfq5cMQJumYYdi1NfmXJMmEWaTwgnUaut");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "sh(wpkh([c55b303f/49'/1'/0']tpubDC49r947KGK52X5rBWS4BLs5m9SRY3pYHnvRrm7HcybZ3BfdEsGFyzCMzayi1u58eT82ZeyFZwH7DD6Q83E3fM9CpfMtmnTygnLfP59jL9L/0/*))#3tka9g0q");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip49Public<K: DerivableKey<Segwitv0>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Segwitv0>> DescriptorTemplate for Bip49Public<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Wpkh_P2Sh(segwit_v0::make_bipxx_public(
            49,
            self.0,
            self.1,
            self.2,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP84 template. Expands to `wpkh(key/84'/{0,1}'/0'/{0,1}/*)`
///
/// Since there are hardened derivation steps, this template requires a private derivable key
/// (generally a `xprv`/`tprv`).
///
/// See [`Bip84Public`] for a template that can work with a `xpub`/`tpub`.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip84;
///
/// let key = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m")?;
/// let mut wallet = Wallet::create(
///     Bip84(key.clone(), KeychainKind::External),
///     Bip84(key, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "tltc1qhl85z42h7r4su5u37rvvw0gk8j2t3n9y82jk96");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "wpkh([c55b303f/84'/1'/0']tpubDDc5mum24DekpNw92t6fHGp8Gr2JjF9J7i4TZBtN6Vp8xpAULG5CFaKsfugWa5imhrQQUZKXe261asP5koDHo5bs3qNTmf3U3o4v9SaB8gg/0/*)#6kfecsmr");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip84<K: DerivableKey<Segwitv0>>(pub K, pub KeychainKind);

impl<K: DerivableKey<Segwitv0>> DescriptorTemplate for Bip84<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Wpkh(segwit_v0::make_bipxx_private(
            84,
            self.0,
            self.1,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP84 public template. Expands to `wpkh(key/{0,1}/*)`
///
/// This assumes that the key used has already been derived with `m/84'/2'/0'` for Mainnet or
/// `m/84'/1'/0'` for Testnet.
///
/// This template requires the parent fingerprint to populate correctly the metadata of PSBTs.
///
/// See [`Bip84`] for a template that does the full derivation, but requires private data
/// for the key.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip84Public;
///
/// let key = bitcoin::bip32::Xpub::from_str("tpubDC2Qwo2TFsaNC4ju8nrUJ9mqVT3eSgdmy1yPqhgkjwmke3PRXutNGRYAUo6RCHTcVQaDR3ohNU9we59brGHuEKPvH1ags2nevW5opEE9Z5Q")?;
/// let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f")?;
/// let mut wallet = Wallet::create(
///     Bip84Public(key.clone(), fingerprint, KeychainKind::External),
///     Bip84Public(key, fingerprint, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "tltc1qedg9fdlf8cnnqfd5mks6uz5w4kgpk2prrvh7gh");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "wpkh([c55b303f/84'/1'/0']tpubDC2Qwo2TFsaNC4ju8nrUJ9mqVT3eSgdmy1yPqhgkjwmke3PRXutNGRYAUo6RCHTcVQaDR3ohNU9we59brGHuEKPvH1ags2nevW5opEE9Z5Q/0/*)#dhu402yv");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip84Public<K: DerivableKey<Segwitv0>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Segwitv0>> DescriptorTemplate for Bip84Public<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2Wpkh(segwit_v0::make_bipxx_public(
            84,
            self.0,
            self.1,
            self.2,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP86 template. Expands to `tr(key/86'/{0,1}'/0'/{0,1}/*)`
///
/// Since there are hardened derivation steps, this template requires a private derivable key
/// (generally a `xprv`/`tprv`).
///
/// See [`Bip86Public`] for a template that can work with a `xpub`/`tpub`.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip86;
///
/// let key = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m")?;
/// let mut wallet = Wallet::create(
///     Bip86(key.clone(), KeychainKind::External),
///     Bip86(key, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "tltc1p5unlj09djx8xsjwe97269kqtxqpwpu2epeskgqjfk4lnf69v4tnq7zd4lr");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "tr([c55b303f/86'/1'/0']tpubDCiHofpEs47kx358bPdJmTZHmCDqQ8qw32upCSxHrSEdeeBs2T5Mq6QMB2ukeMqhNBiyhosBvJErteVhfURPGXPv3qLJPw5MVpHUewsbP2m/0/*)#dkgvr5hm");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip86<K: DerivableKey<Tap>>(pub K, pub KeychainKind);

impl<K: DerivableKey<Tap>> DescriptorTemplate for Bip86<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2TR(segwit_v1::make_bipxx_private(
            86,
            self.0,
            self.1,
            network_kind,
        )?)
        .build(network_kind)
    }
}

/// BIP86 public template. Expands to `tr(key/{0,1}/*)`
///
/// This assumes that the key used has already been derived with `m/86'/2'/0'` for Mainnet or
/// `m/86'/1'/0'` for Testnet.
///
/// This template requires the parent fingerprint to populate correctly the metadata of PSBTs.
///
/// See [`Bip86`] for a template that does the full derivation, but requires private data
/// for the key.
///
/// ## Example
///
/// ```
/// # use std::str::FromStr;
/// # use bdk_wallet::bitcoin::{PrivateKey, Network};
/// # use bdk_wallet::{Wallet, KeychainKind};
/// use bdk_wallet::template::Bip86Public;
///
/// let key = bitcoin::bip32::Xpub::from_str("tpubDC2Qwo2TFsaNC4ju8nrUJ9mqVT3eSgdmy1yPqhgkjwmke3PRXutNGRYAUo6RCHTcVQaDR3ohNU9we59brGHuEKPvH1ags2nevW5opEE9Z5Q")?;
/// let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f")?;
/// let mut wallet = Wallet::create(
///     Bip86Public(key.clone(), fingerprint, KeychainKind::External),
///     Bip86Public(key, fingerprint, KeychainKind::Internal),
/// )
/// .network(Network::Testnet4)
/// .create_wallet_no_persist()?;
///
/// assert_eq!(wallet.next_unused_address(KeychainKind::External).to_string(), "tltc1pwjp9f2k5n0xq73ecuu0c5njvgqr3vkh7yaylmpqvsuuaafymh0msnm8kwp");
/// assert_eq!(wallet.public_descriptor(KeychainKind::External).to_string(), "tr([c55b303f/86'/1'/0']tpubDC2Qwo2TFsaNC4ju8nrUJ9mqVT3eSgdmy1yPqhgkjwmke3PRXutNGRYAUo6RCHTcVQaDR3ohNU9we59brGHuEKPvH1ags2nevW5opEE9Z5Q/0/*)#2p65srku");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Bip86Public<K: DerivableKey<Tap>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Tap>> DescriptorTemplate for Bip86Public<K> {
    fn build(self, network_kind: NetworkKind) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2TR(segwit_v1::make_bipxx_public(
            86,
            self.0,
            self.1,
            self.2,
            network_kind,
        )?)
        .build(network_kind)
    }
}

macro_rules! expand_make_bipxx {
    ( $mod_name:ident, $ctx:ty ) => {
        mod $mod_name {
            use super::*;

            pub(super) fn make_bipxx_private<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                keychain: KeychainKind,
                network_kind: NetworkKind,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let mut derivation_path = alloc::vec::Vec::with_capacity(4);
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(bip)?);

                match network_kind {
                    // SLIP-44: Litecoin mainnet is coin type 2'.
                    NetworkKind::Main => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(2)?);
                    }
                    _ => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(1)?);
                    }
                }
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(0)?);

                match keychain {
                    KeychainKind::External => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(0)?)
                    }
                    KeychainKind::Internal => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(1)?)
                    }
                };

                let derivation_path: bip32::DerivationPath = derivation_path.into();

                Ok((key, derivation_path))
            }
            pub(super) fn make_bipxx_public<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                parent_fingerprint: bip32::Fingerprint,
                keychain: KeychainKind,
                network_kind: NetworkKind,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let derivation_path: bip32::DerivationPath = match keychain {
                    KeychainKind::External => vec![bip32::ChildNumber::from_normal_idx(0)?].into(),
                    KeychainKind::Internal => vec![bip32::ChildNumber::from_normal_idx(1)?].into(),
                };

                let source_path = bip32::DerivationPath::from(vec![
                    bip32::ChildNumber::from_hardened_idx(bip)?,
                    match network_kind {
                        // SLIP-44: Litecoin mainnet is coin type 2'.
                        NetworkKind::Main => bip32::ChildNumber::from_hardened_idx(2)?,
                        _ => bip32::ChildNumber::from_hardened_idx(1)?,
                    },
                    bip32::ChildNumber::from_hardened_idx(0)?,
                ]);

                Ok((key, (parent_fingerprint, source_path), derivation_path))
            }
        }
    };
}

expand_make_bipxx!(legacy, Legacy);
expand_make_bipxx!(segwit_v0, Segwitv0);
expand_make_bipxx!(segwit_v1, Tap);

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod test {
    // Test existing descriptor templates to make sure they are expanded to the right descriptors.

    use super::*;

    use alloc::{string::ToString, vec::Vec};
    use core::str::FromStr;

    use assert_matches::assert_matches;
    use bitcoin::Network;
    use miniscript::descriptor::{DescriptorPublicKey, KeyMap};
    use miniscript::Descriptor;

    use crate::descriptor::{DescriptorError, DescriptorMeta};
    use crate::keys::ValidNetworkKinds;

    // BIP44 `pkh(key/44'/{0,1}'/0'/{0,1}/*)`.
    #[test]
    fn test_bip44_template_cointype() {
        use bitcoin::bip32::ChildNumber::{self, Hardened};

        let xprvkey = bitcoin::bip32::Xpriv::from_str("xprv9s21ZrQH143K2fpbqApQL69a4oKdGVnVN52R82Ft7d1pSqgKmajF62acJo3aMszZb6qQ22QsVECSFxvf9uyxFUvFYQMq3QbtwtRSMjLAhMf").unwrap();
        assert!(xprvkey.network.is_mainnet());
        let xdesc = Bip44(xprvkey, KeychainKind::Internal)
            .build(NetworkKind::Main)
            .unwrap();

        if let ExtendedDescriptor::Pkh(pkh) = xdesc.0 {
            let path: Vec<ChildNumber> = pkh.into_inner().full_derivation_path().unwrap().into();
            let purpose = path.first().unwrap();
            assert_matches!(purpose, Hardened { index: 44 });
            let coin_type = path.get(1).unwrap();
            assert_matches!(coin_type, Hardened { index: 2 });
        }

        let tprvkey = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        assert!(!tprvkey.network.is_mainnet());
        let tdesc = Bip44(tprvkey, KeychainKind::Internal)
            .build(NetworkKind::Test)
            .unwrap();

        if let ExtendedDescriptor::Pkh(pkh) = tdesc.0 {
            let path: Vec<ChildNumber> = pkh.into_inner().full_derivation_path().unwrap().into();
            let purpose = path.first().unwrap();
            assert_matches!(purpose, Hardened { index: 44 });
            let coin_type = path.get(1).unwrap();
            assert_matches!(coin_type, Hardened { index: 1 });
        }
    }

    // Verify template descriptor generates expected address(es).
    fn check(
        desc: Result<(Descriptor<DescriptorPublicKey>, KeyMap, ValidNetworkKinds), DescriptorError>,
        is_witness: bool,
        is_taproot: bool,
        is_fixed: bool,
        network_kind: NetworkKind,
        expected: &[&str],
    ) {
        let (desc, _key_map, _network_kinds) = desc.unwrap();
        assert_eq!(desc.is_witness(), is_witness);
        assert_eq!(desc.is_taproot(), is_taproot);
        assert_eq!(!desc.has_wildcard(), is_fixed);

        // The only non-mainnet network we test is regtest.
        let network = match network_kind.is_mainnet() {
            true => Network::Bitcoin,
            false => Network::Regtest,
        };

        for i in 0..expected.len() {
            let index = i as u32;
            let child_desc = if !desc.has_wildcard() {
                desc.at_derivation_index(0).unwrap()
            } else {
                desc.at_derivation_index(index).unwrap()
            };
            let address = child_desc.address(network).unwrap();
            assert_eq!(address.to_string(), *expected.get(i).unwrap());
        }
    }

    // P2PKH
    #[test]
    fn test_p2pkh_template() {
        let prvkey =
            bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")
                .unwrap();
        check(
            P2Pkh(prvkey).build(NetworkKind::Test),
            false,
            false,
            true,
            NetworkKind::Test,
            &["mwJ8hxFYW19JLuc65RCTaP4v1rzVU8cVMT"],
        );

        let pubkey = bitcoin::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        check(
            P2Pkh(pubkey).build(NetworkKind::Test),
            false,
            false,
            true,
            NetworkKind::Test,
            &["muZpTpBYhxmRFuCjLc7C6BBDF32C8XVJUi"],
        );
    }

    // P2WPKH-P2SH `sh(wpkh(key))`
    #[test]
    fn test_p2wph_p2sh_template() {
        let prvkey =
            bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")
                .unwrap();
        check(
            P2Wpkh_P2Sh(prvkey).build(NetworkKind::Main),
            true,
            false,
            true,
            NetworkKind::Test,
            &["QeRa56MTT34jkfg94tV4a6ipgK6NsjbGBY"],
        );

        let pubkey = bitcoin::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        check(
            P2Wpkh_P2Sh(pubkey).build(NetworkKind::Main),
            true,
            false,
            true,
            NetworkKind::Test,
            &["QYhUK45624GfucDRt7njTcSgxkkE1dadwM"],
        );
    }

    // P2WPKH `wpkh(key)`
    #[test]
    fn test_p2wpkh_template() {
        let prvkey =
            bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")
                .unwrap();
        check(
            P2Wpkh(prvkey).build(NetworkKind::Main),
            true,
            false,
            true,
            NetworkKind::Test,
            &["rltc1q4525hmgw265tl3drrl8jjta7ayffu6jfxru0j6"],
        );

        let pubkey = bitcoin::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        check(
            P2Wpkh(pubkey).build(NetworkKind::Main),
            true,
            false,
            true,
            NetworkKind::Test,
            &["rltc1qngw83fg8dz0k749cg7k3emc7v98wy0c7r085df"],
        );
    }

    // P2TR `tr(key)`
    #[test]
    fn test_p2tr_template() {
        let prvkey =
            bitcoin::PrivateKey::from_wif("cTc4vURSzdx6QE6KVynWGomDbLaA75dNALMNyfjh3p8DRRar84Um")
                .unwrap();
        check(
            P2TR(prvkey).build(NetworkKind::Main),
            false,
            true,
            true,
            NetworkKind::Test,
            &["rltc1pvjf9t34fznr53u5tqhejz4nr69luzkhlvsdsdfq9pglutrpve2xqmdpf0d"],
        );

        let pubkey = bitcoin::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        check(
            P2TR(pubkey).build(NetworkKind::Main),
            false,
            true,
            true,
            NetworkKind::Test,
            &["rltc1pw74tdcrxlzn5r8z6ku2vztr86fgq0m245s72mjktf4afwzsf8ugsa6x3zy"],
        );
    }

    // BIP44 `pkh(key/44'/2'/0'/{0,1}/*)`
    #[test]
    fn test_bip44_template() {
        let prvkey = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        check(
            Bip44(prvkey, KeychainKind::External).build(NetworkKind::Main),
            false,
            false,
            false,
            NetworkKind::Test,
            &[
                "mjo1T5ngGXhrgx6zQo2v8NSL1MpftjYCBt",
                "mii6nxDVkQmseuRgtPefec4YRMSVNht8Fb",
                "mxH7pw3LpXFfVPLk8ES2rSjoyqyR4CXrQZ",
            ],
        );
        check(
            Bip44(prvkey, KeychainKind::Internal).build(NetworkKind::Main),
            false,
            false,
            false,
            NetworkKind::Test,
            &[
                "mkgTgsfw6Bt7hPWRfourYnQi4PmahRYjhJ",
                "mgo7EJztxZbJqEXBr8i2jYJYaUfp6uJibh",
                "mzgJHqpBxLyUAAwRnSRV6qNE5qh7UQ3yoN",
            ],
        );
    }

    // BIP44 public `pkh(key/{0,1}/*)`
    #[test]
    fn test_bip44_public_template() {
        let pubkey = bitcoin::bip32::Xpub::from_str("tpubDDDzQ31JkZB7VxUr9bjvBivDdqoFLrDPyLWtLapArAi51ftfmCb2DPxwLQzX65iNcXz1DGaVvyvo6JQ6rTU73r2gqdEo8uov9QKRb7nKCSU").unwrap();
        let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f").unwrap();
        check(
            Bip44Public(pubkey, fingerprint, KeychainKind::External).build(NetworkKind::Main),
            false,
            false,
            false,
            NetworkKind::Test,
            &[
                "miNG7dJTzJqNbFS19svRdTCisC65dsubtR",
                "n2UqaDbCjWSFJvpC84m3FjUk5UaeibCzYg",
                "muCPpS6Ue7nkzeJMWDViw7Lkwr92Yc4K8g",
            ],
        );
        check(
            Bip44Public(pubkey, fingerprint, KeychainKind::Internal).build(NetworkKind::Test),
            false,
            false,
            false,
            NetworkKind::Test,
            &[
                "moDr3vJ8wpt5nNxSK55MPq797nXJb2Ru9H",
                "ms7A1Yt4uTezT2XkefW12AvLoko8WfNJMG",
                "mhYiyat2rtEnV77cFfQsW32y1m2ceCGHPo",
            ],
        );
    }

    // BIP49 `sh(wpkh(key/49'/2'/0'/{0,1}/*))`
    #[test]
    fn test_bip49_template() {
        let prvkey = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        check(
            Bip49(prvkey, KeychainKind::External).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "QTQJYyY8Etzc1uJckqrA9pFiWFLM3TNj4Z",
                "QjgCpNsbi5qTojNwp3Rtu3WNahXLRLv6SQ",
                "QeqL6JTpYXVaGpErc7dehNKEtLmYCd1kak",
            ],
        );
        check(
            Bip49(prvkey, KeychainKind::Internal).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "QRiMRhwGntzQEw2Yq2LEe1E3J4n45SBtmt",
                "Qh5ZAtP672Y92aFjBTEbTDXvRro5c997B8",
                "Qg3DEfy78pBccwV7fgvXgeRk4xRCsPxmT7",
            ],
        );
    }

    // BIP49 public `sh(wpkh(key/{0,1}/*))`
    #[test]
    fn test_bip49_public_template() {
        let pubkey = bitcoin::bip32::Xpub::from_str("tpubDC49r947KGK52X5rBWS4BLs5m9SRY3pYHnvRrm7HcybZ3BfdEsGFyzCMzayi1u58eT82ZeyFZwH7DD6Q83E3fM9CpfMtmnTygnLfP59jL9L").unwrap();
        let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f").unwrap();
        check(
            Bip49Public(pubkey, fingerprint, KeychainKind::External).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "QWfq5cMQJumYYdi1NfmXJMmEWaTwgnUaut",
                "QfpAnJt7ag72YEaSVkaSNJ1oPCds3HTsNj",
                "QQ125BmS9HbV8ejeaDHyXgwZRq4x1Ffo7Q",
            ],
        );
        check(
            Bip49Public(pubkey, fingerprint, KeychainKind::Internal).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "QiPh1uBxd433rsiwaF7b1pkYT5fRdLJbur",
                "QN8jk9kpmz1TdgxLh3XwfRKJFnqP87tDn1",
                "QfDoKUMnQx4NMBVDgeHtsCdpMGpW76pzpE",
            ],
        );
    }

    // BIP84 `wpkh(key/84'/2'/0'/{0,1}/*)`
    #[test]
    fn test_bip84_template() {
        let prvkey = bitcoin::bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        check(
            Bip84(prvkey, KeychainKind::External).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "rltc1qm0jc96qdwgjauk9sqrnp0yagv0pakuetg6lvrp",
                "rltc1qmxt2yxchtw3ep26kts7nak33thfqn8lurttysg",
                "rltc1q9x4zqka4dke9ypnx8mgjf562sc728ystz289et",
            ],
        );
        check(
            Bip84(prvkey, KeychainKind::Internal).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "rltc1qjphqc36g7zegk5r5c0c86tv3a80mnt8afcrryr",
                "rltc1qny3mdxf0852daxa0g0v7q46h876h4tcsuy53wl",
                "rltc1qr0xl3g39x4duyr8n4mytxwqr35hry247cpqwds",
            ],
        );
    }

    // BIP84 public `wpkh(key/{0,1}/*)`
    #[test]
    fn test_bip84_public_template() {
        let pubkey = bitcoin::bip32::Xpub::from_str("tpubDC2Qwo2TFsaNC4ju8nrUJ9mqVT3eSgdmy1yPqhgkjwmke3PRXutNGRYAUo6RCHTcVQaDR3ohNU9we59brGHuEKPvH1ags2nevW5opEE9Z5Q").unwrap();
        let fingerprint = bitcoin::bip32::Fingerprint::from_str("c55b303f").unwrap();
        check(
            Bip84Public(pubkey, fingerprint, KeychainKind::External).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "rltc1qedg9fdlf8cnnqfd5mks6uz5w4kgpk2prxqkycf",
                "rltc1q3lncdlwq3lgcaaeyruynjnlccr0ve0kag6q5yr",
                "rltc1qt9800y6xl3922jy3uyl0z33jh5wfpycyf47k5m",
            ],
        );
        check(
            Bip84Public(pubkey, fingerprint, KeychainKind::Internal).build(NetworkKind::Main),
            true,
            false,
            false,
            NetworkKind::Test,
            &[
                "rltc1qm6wqukenh7guu792lj2njgw9n78cmwsyet7c45",
                "rltc1q694twxtjn4nnrvnyvra769j0a23rllj5xhzpel",
                "rltc1qhlac3c5ranv5w5emlnqs7wxhkxt8mael6jz55l",
            ],
        );
    }

    // BIP86 `tr(key/86'/2'/0'/{0,1}/*)`
    // Used addresses in test vector from https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    #[test]
    fn test_bip86_template() {
        let prvkey = bitcoin::bip32::Xpriv::from_str("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu").unwrap();
        check(
            Bip86(prvkey, KeychainKind::External).build(NetworkKind::Main),
            false,
            true,
            false,
            NetworkKind::Main,
            &[
                "ltc1puht8rk95c53q3u9w3pf9h3jfcutcrl9lxc7rqsdthjrse4k6sn7q9tuqm9",
                "ltc1p4m4d6s554w3lhamw6pt5je23xvzsqxnz58wc24gc8g9n328yc3xsg3antm",
                "ltc1phmldcawq5rnvuzj54k5nkkyyqrzvu0g5xegyu0q4wnejmstg2tfsyvjas8",
            ],
        );
        check(
            Bip86(prvkey, KeychainKind::Internal).build(NetworkKind::Main),
            false,
            true,
            false,
            NetworkKind::Main,
            &[
                "ltc1pehskafcqerg3hqvx005ywevqta7r0q980xgnencjgez0fyf7lt7s8r36hx",
                "ltc1prpas0sz74px6juj240kpx4j7ww65ldqlu0s7s875gtsmv2m7jeasy93njw",
                "ltc1pj80qe6zrc04pxruk3lk5ygcscyvvc4zj6nsx29xnagnpvekjuqssygxc0k",
            ],
        );
    }

    // BIP86 public `tr(key/{0,1}/*)`
    // Used addresses in test vector in https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    #[test]
    fn test_bip86_public_template() {
        let pubkey = bitcoin::bip32::Xpub::from_str("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ").unwrap();
        let fingerprint = bitcoin::bip32::Fingerprint::from_str("73c5da0a").unwrap();
        check(
            Bip86Public(pubkey, fingerprint, KeychainKind::External).build(NetworkKind::Main),
            false,
            true,
            false,
            NetworkKind::Main,
            &[
                "ltc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxq4arnzx",
                "ltc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0wasxdwj5j",
                "ltc1p0d0rhyynq0awa9m8cqrcr8f5nxqx3aw29w4ru5u9my3h0sfygnzsxjekcz",
            ],
        );
        check(
            Bip86Public(pubkey, fingerprint, KeychainKind::Internal).build(NetworkKind::Main),
            false,
            true,
            false,
            NetworkKind::Main,
            &[
                "ltc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqd8j8vm",
                "ltc1ptdg60grjk9t3qqcqczp4tlyy3z47yrx9nhlrjsmw36q5a72lhdrsxdplfh",
                "ltc1pgcwgsu8naxp7xlp5p7ufzs7emtfza2las7r2e7krzjhe5qj5xz2qyrctv3",
            ],
        );
    }
}
