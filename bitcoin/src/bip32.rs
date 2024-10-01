// SPDX-License-Identifier: CC0-1.0

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.

use alloc::vec;
use core::borrow::Borrow;
use core::ops::Index;
use core::str::FromStr;
use core::{fmt, slice};
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    hardened::HardenedChildIndex,
    normal::NormalChildIndex,
    derivation_path::{
        DerivationPath, IntoIter as DerivationPathIntoIter, Iter as DerivationPathIter,
    },
    normal_derivation_path::{
        NormalDerivationPath, IntoIter as NormalDerivationPathIntoIter, Iter as NormalDerivationPathIter,
    },
};
use hashes::{hash160, hash_newtype, sha512, GeneralHash, HashEngine, Hmac, HmacEngine};
use internals::{impl_array_newtype, write_err};
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::crypto::key::{CompressedPublicKey, Keypair, PrivateKey};
use crate::internal_macros::impl_array_newtype_stringify;
use crate::network::NetworkKind;
use crate::prelude::{String, Vec};

/// Version bytes for extended public keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Version bytes for extended private keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Version bytes for extended public keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Version bytes for extended private keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// [`HARDENED_GATE`] is the minimum value that a [`HardenedChildIndex`] should be.
/// 
/// Useful to validate that any given index is a hardened index.
const HARDENED_GATE: u32 = 0x80000000; // 2^31. This is the minimum that a HardenedChildIndex should be.

/// The old name for xpub, extended public key.
#[deprecated(since = "0.31.0", note = "use Xpub instead")]
pub type ExtendedPubKey = Xpub;

/// The old name for xpriv, extended public key.
#[deprecated(since = "0.31.0", note = "use Xpriv instead")]
pub type ExtendedPrivKey = Xpriv;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_array_newtype_stringify!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac.as_ref()[32..].try_into().expect("half of hmac is guaranteed to be 32 bytes")
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_array_newtype_stringify!(Fingerprint, 4);

hash_newtype! {
    /// Extended key identifier as defined in BIP-32.
    pub struct XKeyIdentifier(hash160::Hash);
}

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Xpriv {
    /// The network this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_index: ChildKeyIndex,
    /// Private key
    pub private_key: secp256k1::SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(Xpriv, "a BIP-32 extended private key");

#[cfg(not(feature = "std"))]
impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[SecretKey]")
            .finish()
    }
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub {
    /// The network kind this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_index: ChildKeyIndex,
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(Xpub, "a BIP-32 extended public key");


/// A child key index
/// 
/// "Given a parent extended key and an index i, it is possible to compute the corresponding child extended key" defined in [BIP-23](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
/// 
/// A [`ChildKeyIndex`] is used to compute the child extended key from the parent extended key at the corresponding index.
/// 
/// The index can be either a [`NormalChildIndex`] or a [`HardenedChildIndex`].
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildKeyIndex {
    /// Enum wrapper for a [`NormalChildIndex`]
    Normal(NormalChildIndex),
    /// Enum wrapper for a [`HardenedChildIndex`]
    Hardened(HardenedChildIndex),
}

impl ChildKeyIndex {
    /// [`NormalChildIndex`] with index 0.
    pub const ZERO_NORMAL: Self = ChildKeyIndex::Normal(NormalChildIndex::ZERO);

    /// [`NormalChildIndex`] with index 1.
    pub const ONE_NORMAL: Self = ChildKeyIndex::Normal(NormalChildIndex::ONE);

    /// [`HardenedChildIndex`] with index 0.
    pub const ZERO_HARDENED: Self = ChildKeyIndex::Hardened(HardenedChildIndex::ZERO);

    /// [`HardenedChildIndex`] with index 1.
    pub const ONE_HARDENED: Self = ChildKeyIndex::Hardened(HardenedChildIndex::ONE);

    /// Create a [`NormalChildIndex`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    pub fn from_normal_index(index: u32) -> Result<Self, Error> {
        Ok(NormalChildIndex::from_index(index)?.into())
    }

    /// Creates a [`HardenedChildIndex`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    pub fn from_hardened_index(index: u32) -> Result<Self, Error> {
        Ok(HardenedChildIndex::from_index(index)?.into())
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool { !self.is_hardened() }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildKeyIndex::Hardened { .. } => true,
            ChildKeyIndex::Normal { .. } => false,
        }
    }

    /// Returns the [`ChildKeyIndex`] that is a single increment from this one.
    pub fn increment(self) -> Result<ChildKeyIndex, Error> {
        match self {
            ChildKeyIndex::Normal(number) =>
                Ok(NormalChildIndex::from_index(number.to_raw() + 1)?.into()),
            ChildKeyIndex::Hardened(number) =>
                Ok(HardenedChildIndex::from_index(number.to_raw() + 1)?.into()),
        }
    }

    /// Creates a new [`ChildKeyIndex`] from a raw index.
    pub fn from_raw_index(index: u32) -> Self {
        match NormalChildIndex::from_index(index) {
            Ok(normal) => ChildKeyIndex::Normal(normal),
            Err(_) => ChildKeyIndex::Hardened(
                HardenedChildIndex::from_index(index ^ (1 << 31)).expect("valid since not normal"),
            ),
        }
    }
}

impl From<u32> for ChildKeyIndex {
    fn from(index: u32) -> Self { Self::from_raw_index(index) }
}

impl TryInto<NormalChildIndex> for ChildKeyIndex {
    type Error = Error;
    fn try_into(self) -> Result<NormalChildIndex, Error> {
        match self {
            ChildKeyIndex::Normal(num) => Ok(num),
            ChildKeyIndex::Hardened(_) => Err(Error::CannotDeriveFromHardenedKey),
        }
    }
}

impl From<ChildKeyIndex> for u32 {
    fn from(cnum: ChildKeyIndex) -> Self {
        match cnum {
            ChildKeyIndex::Normal(index) => index.to_raw(),
            ChildKeyIndex::Hardened(index) => index.to_raw() | (1 << 31),
        }
    }
}

impl fmt::Display for ChildKeyIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildKeyIndex::Hardened(index) => {
                fmt::Display::fmt(&index.to_raw(), f)?;
                let alt = f.alternate();
                f.write_str(if alt { "h" } else { "'" })
            }
            ChildKeyIndex::Normal(index) => fmt::Display::fmt(&index.to_raw(), f),
        }
    }
}

impl FromStr for ChildKeyIndex {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildKeyIndex, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildKeyIndex::from_hardened_index(
            inp[0..inp.len() - 1].parse().map_err(|_| Error::InvalidChildKeyIndexFormat)?,
            )?
        } else {
            ChildKeyIndex::from_normal_index(
            inp.parse().map_err(|_| Error::InvalidChildKeyIndexFormat)?,
            )?
        })
    }
}

impl AsRef<[ChildKeyIndex]> for ChildKeyIndex {
    fn as_ref(&self) -> &[ChildKeyIndex] { slice::from_ref(self) }
}

impl FromStr for HardenedChildIndex {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
    let index = s.parse().map_err(|_| Error::InvalidChildKeyIndex(0))?;
        HardenedChildIndex::from_index(index)
    }
}
impl FromStr for NormalChildIndex {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
    let index = s.parse().map_err(|_| Error::InvalidChildKeyIndex(0))?;
        NormalChildIndex::from_index(index)
    }
}
impl From<NormalChildIndex> for ChildKeyIndex {
    fn from(num: NormalChildIndex) -> Self { ChildKeyIndex::Normal(num) }
}
impl From<HardenedChildIndex> for ChildKeyIndex {
    fn from(num: HardenedChildIndex) -> Self { ChildKeyIndex::Hardened(num) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildKeyIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildKeyIndex::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildKeyIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Module to protect the invariants on the inner field of [`HardenedChildIndex`].
mod hardened {
    use super::*;

    /// A [`HardenedChildIndex`], these require both the parent private key and chain code to derive child keys.
    /// Prevents public key derivation if only the parent public key is known.
    /// 
    /// The new-type guarantees that the inner field is a valid hardened index value.
    /// 
    /// (indexes `2_147_483_648` to `4_294_967_295`, the second half of all possible children).
    #[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
    pub struct HardenedChildIndex(u32);

    impl HardenedChildIndex {
        /// [`HardenedChildIndex`] with index 0.
        pub const ZERO: Self = HardenedChildIndex(0);
        /// [`HardenedChildIndex`] with index 1.
        pub const ONE: Self = HardenedChildIndex(1);

        /// Consumes the [`HardenedChildIndex`] and converts it to [`ChildKeyIndex::Hardened`].
        pub const fn to_childkey(self) -> ChildKeyIndex { ChildKeyIndex::Hardened(self) }

        /// [`HardenedChildIndex`] to [`u32`] index.
        pub const fn to_raw(self) -> u32 { self.0 }

        /// [`HardenedChildIndex`] from [`u32`] index.
        pub const fn from_index(index: u32) -> Result<HardenedChildIndex, Error> {
            //  NOTE to future developers:
            //
            //  Any u32 above 2^31 is a valid hardened index, but it notation needs to be less than 2^31.
            //  
            //  For Example:
            //      The Path m/5' (the same as m/5h) is a valid hardened index. 
            //      but it value would be 2^31 + 5 = 2147483653.
            //  Another valid example:
            //       2^31 + 5 = 2147483653. is a valid hardened index.
            //       but it notation would be m/5' (the same as m/5h).
            //       since we expect the notation to be in the form of m/5' or m/5h and not m/2147483653.
            //       we can safely assume that any index below 2^31 is a valid hardened index but its only defined, if its hardened
            //       by its notation.
            //
            //  Thats why we check if the index is less than the hardened gate.
            //  The same check can be achieved with:
            //      index >> 31 == 0
            //      index & (1 << 31) == 0
            //      index < HARDENED_GATE
            //      index < 0x80000000
            // 
            // The actual check is done with a simple comparison for readability since the computational difference is negligible nowadays.
            if index < HARDENED_GATE {
                Ok(HardenedChildIndex(index))
            } else {
                Err(Error::InvalidChildKeyIndex(index))
            }
        }

    /// [`HardenedChildIndex`] from [`ChildKeyIndex`].
        pub const fn from_childkey(childkey: ChildKeyIndex) -> Result<HardenedChildIndex, Error> {
            match childkey {
                ChildKeyIndex::Hardened(num) => Ok(num),
            ChildKeyIndex::Normal(num) => Err(Error::InvalidChildKeyIndex(num.to_raw())),
            }
        }
    }
}
/// This module exists to protect the
/// invariants on the inner field of [`NormalChildIndex`].
mod normal {
    use super::*;

    /// A [`NormalChildIndex`], these allow the generation of child public keys using only the parent public key and chain code.
    /// 
    /// The new-type guarantees that the inner field is a valid normal index value 
    /// (indexes `0` to `2_147_483_648`, the first half of all possible children).
    #[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
    pub struct NormalChildIndex(u32);

    impl NormalChildIndex {

        /// [`NormalChildIndex`] with index 0.
        pub const ZERO: Self = NormalChildIndex(0);

        /// [`NormalChildIndex`] with index 1.
        pub const ONE: Self = NormalChildIndex(1);

        /// [`NormalChildIndex`] to [`u32`] index.
        pub const fn to_raw(self) -> u32 { self.0 }

        /// [`NormalChildIndex`] to [`ChildKeyIndex::Normal`].
        pub const fn to_childkey(self) -> ChildKeyIndex { ChildKeyIndex::Normal(self) }

        /// [`NormalChildIndex`] from [`u32`] index.
        pub const fn from_index(index: u32) -> Result<NormalChildIndex, Error> {
            if index < HARDENED_GATE {
                Ok(NormalChildIndex(index))
            } else {
                Err(Error::InvalidChildKeyIndex(index))
            }
        }

        /// [`NormalChildIndex`] from [`ChildKeyIndex`].
        pub const fn from_childkey(number: ChildKeyIndex) -> Result<NormalChildIndex, Error> {
            match number {
                ChildKeyIndex::Normal(num) => Ok(num),
                ChildKeyIndex::Hardened(_) => Err(Error::CannotDeriveFromHardenedKey),
            }
        }
    }
}

impl fmt::Display for HardenedChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_raw(), f)
    }
}
impl fmt::Display for NormalChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_raw(), f)
    }
}

/// `normal_derivation_path` module to protect the inner field of [`NormalDerivationPath`].
pub mod normal_derivation_path {
    use super::*;

    /// A [`DerivationPath`] that can only contain [`NormalChildIndex`] (i.e. no hardened indexes).
    #[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
    pub struct NormalDerivationPath(Vec<NormalChildIndex>);

    #[cfg(feature = "serde")]
    internals::serde_string_impl!(
        NormalDerivationPath,
        "a BIP-32 derivation path containing normal numbers only"
    );

    impl NormalDerivationPath {
        /// The Master (empty) path (i.e. the master key).
        pub const MASTER: Self = NormalDerivationPath(Vec::new());

        /// Creates a new [`NormalDerivationPath`] from a vector of [`NormalChildIndex`]s.
        pub fn new(vec: Vec<NormalChildIndex>) -> Self { NormalDerivationPath(vec) }

        /// Returns length of the [`NormalDerivationPath`].
        pub fn len(&self) -> usize { self.0.len() }

        /// Returns a [`DerivationPath`] from the [`NormalDerivationPath`].
        pub fn to_derivation_path(&self) -> DerivationPath {
            self.into_iter().map(|n| n.to_childkey()).collect()
        }

        /// Returns `true` if the [`NormalDerivationPath`] is empty.
        pub fn is_empty(&self) -> bool { self.0.is_empty() }

        /// Returns whether [`NormalDerivationPath`] represents master key (i.e. it's length
        /// is empty). True for `m` path.
        pub fn is_master(&self) -> bool { self.is_empty() }

        /// Creates a new [`NormalDerivationPath`] that is a child of this one.
        pub fn child(&self, cn: NormalChildIndex) -> Self { self.new_extended_from([cn]) }

        /// Converts into a [`NormalDerivationPath`] that is a child of this one.
        pub fn into_with_child(self, cn: NormalChildIndex) -> Self {
            let mut path = self;
            path.extend([cn]);
            path
        }
        /// Concatenates `self` with `path` and return the resulting new path.
        ///
        /// ```
        /// use bitcoin::bip32::{NormalDerivationPath, NormalChildIndex};
        /// use std::str::FromStr;
        ///
        /// let base = NormalDerivationPath::from_str("m/42").unwrap();
        ///
        /// let deriv_1 = base.new_extended_from(NormalDerivationPath::from_str("0/1").unwrap());
        /// let deriv_2 = base.new_extended_from([
        ///     NormalChildIndex::ZERO,
        ///     NormalChildIndex::ONE
        /// ]);
        ///
        /// assert_eq!(deriv_1, deriv_2);
        /// ```
        pub fn new_extended_from<P: IntoIterator<Item = NormalChildIndex>>(
            &self,
            path: P,
        ) -> NormalDerivationPath {
            let mut ret = self.clone();
            ret.extend(path);
            ret
        }

        /// Returns the [`NormalDerivationPath`] as a vector of [`u32`] integers.
        /// Unhardened elements are copied as is.
        ///
        /// ```
        /// use bitcoin::bip32::NormalDerivationPath;
        /// use std::str::FromStr;
        ///
        /// let path = NormalDerivationPath::from_str("m/84/0/0/0/1").unwrap();
        /// const NORMAL: u32 = 0;
        /// assert_eq!(path.into_u32_vec(), vec![84 + NORMAL, NORMAL, NORMAL, 0, 1]);
        /// ```
        pub fn into_u32_vec(self) -> Vec<u32> {
            self.into_iter().map(|num| num.to_raw()).collect()
        }

        /// Creates a [`DerivationPath`] from a slice of [`u32`]s.
        ///
        /// ```
        /// use bitcoin::bip32::NormalDerivationPath;
        ///
        /// const NORMAL: u32 = 0;
        /// let expected = vec![84 + NORMAL, NORMAL, NORMAL, 0, 1];
        /// let path = NormalDerivationPath::from_u32_slice(expected.as_slice()).expect("Valid slice of normal numbers");
        /// assert_eq!(path.into_u32_vec(), expected);
        /// ```
        pub fn from_u32_slice(numbers: &[u32]) -> Result<NormalDerivationPath, Error> {
            numbers.iter().map(|&n| NormalChildIndex::from_index(n)).collect()
        }
    }
    /// [`NormalDerivationPath`] Iterator wrapper.
    pub struct Iter<'a>(core::slice::Iter<'a, normal::NormalChildIndex>);

    impl<'a> core::iter::Iterator for Iter<'a> {
        type Item = NormalChildIndex;
        fn next(&mut self) -> Option<Self::Item> { self.0.next().copied() }
    }

    impl<'a> core::iter::IntoIterator for &'a NormalDerivationPath {
        type Item = NormalChildIndex;
        type IntoIter = Iter<'a>;
        fn into_iter(self) -> Self::IntoIter { Iter(self.0.iter()) }
    }
    /// [`NormalDerivationPath`] IntoIterator Wrapper
    pub struct IntoIter(alloc::vec::IntoIter<NormalChildIndex>);

    impl Iterator for IntoIter {
        type Item = NormalChildIndex;
        fn next(&mut self) -> Option<Self::Item> { self.0.next() }
    }

    impl core::iter::IntoIterator for NormalDerivationPath {
        type Item = NormalChildIndex;
        type IntoIter = IntoIter;
        fn into_iter(self) -> Self::IntoIter { IntoIter(self.0.into_iter()) }
    }

    impl core::iter::FromIterator<NormalChildIndex> for NormalDerivationPath {
        fn from_iter<T>(iter: T) -> Self
        where
            T: IntoIterator<Item = NormalChildIndex>,
        {
            NormalDerivationPath::new(Vec::from_iter(iter))
        }
    }
    impl<'a> core::iter::FromIterator<&'a NormalChildIndex> for NormalDerivationPath {
        fn from_iter<T>(iter: T) -> Self
        where
            T: IntoIterator<Item = &'a NormalChildIndex>,
        {
            NormalDerivationPath::from(Vec::from_iter(iter.into_iter().copied()))
        }
    }
    impl From<NormalDerivationPath> for Vec<NormalChildIndex> {
        fn from(path: NormalDerivationPath) -> Self { path.0 }
    }
    impl<I> Index<I> for NormalDerivationPath
    where
        Vec<NormalChildIndex>: Index<I>,
    {
        type Output = <Vec<NormalChildIndex> as Index<I>>::Output;

        #[inline]
        fn index(&self, index: I) -> &<Vec<NormalChildIndex> as Index<I>>::Output {
            &self.0[index]
        }
    }
    impl Extend<NormalChildIndex> for NormalDerivationPath {
        fn extend<T: IntoIterator<Item = NormalChildIndex>>(&mut self, iter: T) {
            self.0.extend(iter)
        }
    }
    impl AsRef<[NormalChildIndex]> for NormalDerivationPath {
        fn as_ref(&self) -> &[NormalChildIndex] { &self.0 }
    }
}
impl From<Vec<NormalChildIndex>> for NormalDerivationPath {
    fn from(numbers: Vec<NormalChildIndex>) -> Self { NormalDerivationPath::new(numbers) }
}

impl TryInto<NormalDerivationPath> for String {
    type Error = Error;
    fn try_into(self) -> Result<NormalDerivationPath, Error> { self.parse() }
}

impl<'a> TryInto<NormalDerivationPath> for &'a str {
    type Error = Error;
    fn try_into(self) -> Result<NormalDerivationPath, Error> { self.parse() }
}

impl<'a> From<&'a [NormalChildIndex]> for NormalDerivationPath {
    fn from(numbers: &'a [NormalChildIndex]) -> Self {
        NormalDerivationPath::new(numbers.to_vec())
    }
}

impl From<NormalDerivationPath> for DerivationPath {
    fn from(path: NormalDerivationPath) -> Self { NormalDerivationPath::to_derivation_path(&path) }
}

impl From<&NormalDerivationPath> for DerivationPath {
    fn from(path: &NormalDerivationPath) -> Self {
        path.into_iter().map(ChildKeyIndex::from).collect()
    }
}

impl fmt::Display for NormalDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, child) in self.into_iter().enumerate() {
            if i != 0 {
                write!(f, "/")?;
            }
            write!(f, "{}", child.to_raw())?;
        }
        Ok(())
    }
}

impl TryFrom<&[ChildKeyIndex]> for NormalDerivationPath {
    type Error = Error;
    fn try_from(value: &[ChildKeyIndex]) -> Result<Self, Self::Error> {
        let mut base = Vec::with_capacity(value.len());
        for number in value.iter() {
            base.push(NormalChildIndex::from_childkey(*number)?)
        }
        Ok(NormalDerivationPath::from(base))
    }
}

impl FromStr for NormalDerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<NormalDerivationPath, Error> {
        if path.is_empty() || path == "m" || path == "m/" {
            return Ok(vec![].into());
        }

        let path = path.strip_prefix("m/").unwrap_or(path);

        let parts = path.split('/');
        let ret: Result<Vec<NormalChildIndex>, Error> =
            parts.map(str::parse::<NormalChildIndex>).collect();
        Ok(NormalDerivationPath::from(ret?))
    }
}

/// An iterator over children of a [`DerivationPath`].
///
/// It is returned by the methods [`DerivationPath::children_from`],
/// [`DerivationPath::normal_children`] and [`DerivationPath::hardened_children`].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildKeyIndex>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Starts a new [`DerivationPathIterator`] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildKeyIndex) -> DerivationPathIterator<'a> {
        DerivationPathIterator { base: path, next_child: Some(start) }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.with_child(ret))
    }
}
/// [`DerivationPath`] methods and utils.
pub mod derivation_path {
    use super::*;

    /// A BIP 32 derivation path.
    #[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
    pub struct DerivationPath(Vec<ChildKeyIndex>);
    #[cfg(feature = "serde")]
    internals::serde_string_impl!(DerivationPath, "a BIP-32 derivation path");
    impl DerivationPath {
        /// The Master(empty) path (i.e. the master key).
        pub const MASTER: Self = DerivationPath(Vec::new());

        /// Creates a new [`DerivationPath`] from a vector of [`ChildKeyIndex`].
        pub fn new(vec: Vec<ChildKeyIndex>) -> Self { DerivationPath(vec) }

        /// Tries to convert this [`DerivationPath`] into a [`NormalDerivationPath`]
        pub fn to_normal(&self) -> Result<NormalDerivationPath, Error> {
            NormalDerivationPath::try_from(self.0.as_slice())
        }

        /// Check if the [`DerivationPath`] is empty
        pub fn is_empty(&self) -> bool { self.0.is_empty() }

        /// Returns length of the [`DerivationPath`]
        pub fn len(&self) -> usize { self.0.len() }

        /// Returns whether derivation path represents master key (i.e. it's length
        /// is empty). True for `m` path.
        pub fn is_master(&self) -> bool { self.0.is_empty() }

        /// Creates a new [`DerivationPath`] that is a child of this one.
        pub fn with_child(&self, cn: ChildKeyIndex) -> Self { self.new_extended_from([cn]) }

        /// Converts into a [`DerivationPath`] that is a child of this one.
        pub fn into_with_child(self, cn: ChildKeyIndex) -> Self {
            let mut ret = self.clone();
            ret.extend([cn]);
            ret
        }

        /// Returns an [`Iterator`] over the children of this [`DerivationPath`]
        /// starting with the given [`ChildKeyIndex`].
        pub fn children_from(&self, cn: ChildKeyIndex) -> DerivationPathIterator {
            DerivationPathIterator::start_from(self, cn)
        }

        /// Returns an [`Iterator`] over the unhardened children of this [`DerivationPath`].
        pub fn normal_children(&self) -> DerivationPathIterator {
            DerivationPathIterator::start_from(self, ChildKeyIndex::ZERO_NORMAL)
        }

        /// Returns an [`Iterator`] over the hardened children of this [`DerivationPath`].
        pub fn hardened_children(&self) -> DerivationPathIterator {
            DerivationPathIterator::start_from(self, ChildKeyIndex::ZERO_HARDENED)
        }
        /// Concatenates `self` with `path` and return the resulting new path.
        ///
        /// ```
        /// use bitcoin::bip32::{DerivationPath, ChildKeyIndex};
        /// use std::str::FromStr;
        ///
        /// let mut base = DerivationPath::from_str("m/42").unwrap();
        ///
        /// let deriv_1 = base.new_extended_from(DerivationPath::from_str("0/1").unwrap());
        /// let deriv_2 = base.new_extended_from([
        ///     ChildKeyIndex::ZERO_NORMAL,
        ///     ChildKeyIndex::ONE_NORMAL
        /// ]);
        ///
        /// assert_eq!(deriv_1, deriv_2);
        /// ```
        pub fn new_extended_from<P: IntoIterator<Item = ChildKeyIndex>>(
            &self,
            path: P,
        ) -> DerivationPath {
            let mut ret = self.clone();
            ret.extend(path);
            ret
        }

        /// Returns the [`DerivationPath`] as a vector of [`u32`]s.
        /// Unhardened elements are copied as is.
        /// 0x80000000 is added to the hardened elements.
        ///
        /// ```
        /// use bitcoin::bip32::DerivationPath;
        /// use std::str::FromStr;
        ///
        /// let path = DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap();
        /// const HARDENED: u32 = 0x80000000;
        /// assert_eq!(path.into_u32_vec(), vec![84 + HARDENED, HARDENED, HARDENED, 0, 1]);
        /// ```
        pub fn into_u32_vec(&self) -> Vec<u32> { self.into_iter().map(|el| el.into()).collect() }

        /// Creates a [`DerivationPath`] from a slice of [`u32`]s.
        ///
        /// ```
        /// use bitcoin::bip32::DerivationPath;
        ///
        /// const HARDENED: u32 = 0x80000000;
        /// let expected = vec![84 + HARDENED, HARDENED, HARDENED, 0, 1];
        /// let path = DerivationPath::from_u32_slice(expected.as_slice());
        /// assert_eq!(path.into_u32_vec(), expected);
        /// ```
        pub fn from_u32_slice(numbers: &[u32]) -> Self {
            numbers.iter().map(|&n| ChildKeyIndex::from(n)).collect()
        }
    }

    impl AsRef<[ChildKeyIndex]> for DerivationPath {
        fn as_ref(&self) -> &[ChildKeyIndex] { &self.0 }
    }
    impl Extend<ChildKeyIndex> for DerivationPath {
        fn extend<T: IntoIterator<Item = ChildKeyIndex>>(&mut self, iter: T) { self.0.extend(iter) }
    }
    impl<I> Index<I> for DerivationPath
    where
        Vec<ChildKeyIndex>: Index<I>,
    {
        type Output = <Vec<ChildKeyIndex> as Index<I>>::Output;

        #[inline]
        fn index(&self, index: I) -> &<Vec<ChildKeyIndex> as Index<I>>::Output { &self.0[index] }
    }

    /// [`DerivationPath`] [`Iterator`] wrapper starting with the given
    /// [`ChildKeyIndex`].
    pub struct Iter<'a>(core::slice::Iter<'a, ChildKeyIndex>);

    impl<'a> core::iter::Iterator for Iter<'a> {
        type Item = ChildKeyIndex;
        fn next(&mut self) -> Option<Self::Item> { self.0.next().copied() }
    }

    impl<'a> core::iter::IntoIterator for &'a DerivationPath {
        type Item = ChildKeyIndex;
        type IntoIter = Iter<'a>;
        fn into_iter(self) -> Self::IntoIter { Iter(self.0.iter()) }
    }

    /// [`DerivationPath`] [`IntoIterator`] wrapper.
    pub struct IntoIter(alloc::vec::IntoIter<ChildKeyIndex>);

    impl Iterator for IntoIter {
        type Item = ChildKeyIndex;
        fn next(&mut self) -> Option<Self::Item> { self.0.next() }
    }

    impl core::iter::IntoIterator for DerivationPath {
        type Item = ChildKeyIndex;
        type IntoIter = IntoIter;
        fn into_iter(self) -> Self::IntoIter { IntoIter(self.0.into_iter()) }
    }

    impl From<DerivationPath> for Vec<ChildKeyIndex> {
        fn from(path: DerivationPath) -> Self { path.0 }
    }
}

impl<'a> core::iter::FromIterator<&'a ChildKeyIndex> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = &'a ChildKeyIndex>,
    {
        DerivationPath::from(Vec::from_iter(iter.into_iter().copied()))
    }
}

impl From<Vec<ChildKeyIndex>> for DerivationPath {
    fn from(numbers: Vec<ChildKeyIndex>) -> Self { DerivationPath::new(numbers) }
}

impl<'a> From<&'a [ChildKeyIndex]> for DerivationPath {
    fn from(numbers: &'a [ChildKeyIndex]) -> Self { DerivationPath::new(numbers.to_vec()) }
}

impl TryInto<DerivationPath> for String {
    type Error = Error;
    fn try_into(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl<'a> TryInto<DerivationPath> for &'a str {
    type Error = Error;
    fn try_into(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl core::iter::FromIterator<ChildKeyIndex> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildKeyIndex>,
    {
        DerivationPath::from(Vec::from_iter(iter))
    }
}
impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        if path.is_empty() || path == "m" || path == "m/" {
            return Ok(vec![].into());
        }

        let path = path.strip_prefix("m/").unwrap_or(path);

        let parts = path.split('/');

        let ret: Result<Vec<ChildKeyIndex>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath::from(ret?))
    }
}


impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.into_iter();
        if let Some(first_element) = iter.next() {
            write!(f, "{}", first_element)?;
        }
        for cn in iter {
            f.write_str("/")?;
            write!(f, "{}", cn)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self, f) }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP 32 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Secp256k1(secp256k1::Error),
    /// A child key index was provided that was out of range
    InvalidChildKeyIndex(u32),
    /// Invalid [`ChildKeyIndex`] format.
    InvalidChildKeyIndexFormat,
    /// Invalid [`DerivationPath`] format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Hexadecimal decoding error
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            CannotDeriveFromHardenedKey =>
                f.write_str("cannot derive hardened key from public key"),
            Secp256k1(ref e) => write_err!(f, "secp256k1 error"; e),
            InvalidChildKeyIndex(ref n) => {
                write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n)
            }
            InvalidChildKeyIndexFormat => f.write_str("invalid child number format"),
            InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            UnknownVersion(ref bytes) => write!(f, "unknown version magic bytes: {:?}", bytes),
            WrongExtendedKeyLength(ref len) => {
                write!(f, "encoded extended key data has wrong length {}", len)
            }
            Base58(ref e) => write_err!(f, "base58 encoding error"; e),
            Hex(ref e) => write_err!(f, "Hexadecimal decoding error"; e),
            InvalidPublicKeyHexLength(got) => {
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got)
            }
            InvalidBase58PayloadLength(ref e) => write_err!(f, "base58 payload"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            Base58(ref e) => Some(e),
            Hex(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            CannotDeriveFromHardenedKey
            | InvalidChildKeyIndex(_)
            | InvalidChildKeyIndexFormat
            | InvalidDerivationPathFormat
            | UnknownVersion(_)
            | WrongExtendedKeyLength(_)
            | InvalidPublicKeyHexLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self { Error::Base58(err) }
}

impl From<InvalidBase58PayloadLengthError> for Error {
    fn from(e: InvalidBase58PayloadLengthError) -> Error { Self::InvalidBase58PayloadLength(e) }
}

impl Xpriv {
    /// Construct a new master key from a seed value
    pub fn new_master(network: impl Into<NetworkKind>, seed: &[u8]) -> Result<Xpriv, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(Xpriv {
            network: network.into(),
            depth: 0,
            parent_fingerprint: Default::default(),
            child_index: ChildKeyIndex::ZERO_NORMAL,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Constructs ECDSA compressed private key matching internal secret key representation.
    #[deprecated(since = "TBD", note = "use `to_private_key()`")]
    pub fn to_priv(self) -> PrivateKey {
        self.to_private_key()
    }

    /// Constructs ECDSA compressed private key matching internal secret key representation.
    pub fn to_private_key(self) -> PrivateKey {
        PrivateKey { compressed: true, network: self.network, inner: self.private_key }
    }

    /// Creates new extended public key from this extended private key.
    pub fn to_xpub<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>,) -> Xpub {
        Xpub::from_xpriv(secp, self)
    }

    /// Constructs BIP340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair<C: secp256k1::Signing>(self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_seckey_slice(secp, &self.private_key[..])
            .expect("BIP32 internal private key representation is broken")
    }

    /// Derives an extended private key from a path.
    ///
    /// The `path` argument can be both of type [`DerivationPath`] or [`Vec<ChildKeyIndex>`].
    pub fn derive_xpriv<
        C: secp256k1::Signing,
        I: Into<ChildKeyIndex>,
        P: core::iter::IntoIterator<Item = I>,
    >(
        &self,
        secp: &Secp256k1<C>,
        path: P,
    ) -> Xpriv {
        let mut sk: Xpriv = *self;
        for cnum in path {
            sk = sk.ckd_priv(secp, cnum.into())
        }
        sk
    }

    /// Private->Private child key derivation
    fn ckd_priv<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>, i: ChildKeyIndex) -> Xpriv {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildKeyIndex::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
            }
            ChildKeyIndex::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }

        hmac_engine.input(&u32::from(i).to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32])
            .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Xpriv {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_index: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        }
    }

    /// Decoding extended private key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpriv, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_MAINNET_PRIVATE) {
            NetworkKind::Main
        } else if data.starts_with(&VERSION_BYTES_TESTNETS_PRIVATE) {
            NetworkKind::Test
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpriv {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_index: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        })
    }

    /// Extended private key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PRIVATE,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PRIVATE,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_index).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XKeyIdentifier {
        Xpub::from_xpriv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl Xpub {
    /// Creates extended public key from an extended private key.
    #[deprecated(since = "TBD", note = "use `from_xpriv()`")]
    pub fn from_priv<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &Xpriv) -> Xpub {
        Self::from_xpriv(secp, sk)
    }

    /// Creates extended public key from an extended private key.
    pub fn from_xpriv<C: secp256k1::Signing>(secp: &Secp256k1<C>, xpriv: &Xpriv) -> Xpub {
        Xpub {

            network: xpriv.network,
            depth: xpriv.depth,
            parent_fingerprint: xpriv.parent_fingerprint,
            child_index: xpriv.child_index,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &xpriv.private_key),
            chain_code: xpriv.chain_code,
        }
    }

    /// Constructs ECDSA compressed public key matching internal public key representation.
    #[deprecated(since = "TBD", note = "use `to_public_key()`")]
    pub fn to_pub(self) -> CompressedPublicKey { self.to_public_key() }

    /// Constructs ECDSA compressed public key matching internal public key representation.
    pub fn to_public_key(self) -> CompressedPublicKey { CompressedPublicKey(self.public_key) }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    #[deprecated(since = "TBD", note = "use `to_x_only_public_key()`")]
    pub fn to_x_only_pub(self) -> XOnlyPublicKey { self.to_x_only_public_key() }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_public_key(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    
    /// Derives an extended public key from a path that contains only [`NormalChildIndex`]s.
    /// 
    /// The path can be anything iterable over [`NormalChildIndex`]s, such as [`NormalDerivationPath`].
    pub fn derive_xpub<
        C: secp256k1::Verification,
        I: Borrow<NormalChildIndex>,
        P: IntoIterator<Item = I>,
    >(

        &self,
        secp: &Secp256k1<C>,
        path: P,
    ) -> Xpub {
        let mut pk: Xpub = *self;
        for normal_cnum in path {
            pk = pk
                .internal_derive_xpub(secp, *normal_cnum.borrow())
                .unwrap_or_else(|never| match never {});
        }
        pk
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing
    /// [`IntoIterator<Item = &'a ChildKeyIndex>`], such as
    /// [`DerivationPath`], for instance.
    pub fn try_derive_xpub<
        C: secp256k1::Verification,
        I: Borrow<ChildKeyIndex>,
        P: IntoIterator<Item = I>,
    >(
        &self,
        secp: &Secp256k1<C>,
        path: P,
    ) -> Result<Xpub, Error> {
        let mut pk: Xpub = *self;
        for normal_cnum in path {
            pk = pk.internal_derive_xpub(secp, *normal_cnum.borrow())?
        }
        Ok(pk)
    }

    /// Public->Public child key derivation
    fn internal_derive_xpub<C: secp256k1::Verification, N: TryInto<NormalChildIndex>>(
        &self,
        secp: &Secp256k1<C>,
        number_from: N,
    ) -> Result<Xpub, N::Error> {
        let number_from: NormalChildIndex = number_from.try_into()?;
        let (sk, chain_code) = self.ckd_pub_tweak(number_from);
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into()).unwrap();
        Ok(Xpub {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_index: number_from.to_childkey(),
            public_key: tweaked,
            chain_code,
        })
    }

    /// Computes the scalar tweak added to this key to get a child key.
    pub fn ckd_pub_tweak(&self, i: NormalChildIndex) -> (secp256k1::SecretKey, ChainCode) {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&self.public_key.serialize()[..]);
        hmac_engine.input(&i.to_raw().to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result.as_ref()[..32]).unwrap();
        let chain_code = ChainCode::from_hmac(hmac_result);
        (private_key, chain_code)
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpub, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_MAINNET_PUBLIC) {
            NetworkKind::Main
        } else if data.starts_with(&VERSION_BYTES_TESTNETS_PUBLIC) {
            NetworkKind::Test
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpub {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_index: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PUBLIC,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PUBLIC,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_index).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XKeyIdentifier {
        XKeyIdentifier(hash160::Hash::hash(&self.public_key.serialize()))
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier()[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl fmt::Display for Xpriv {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpriv {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpriv, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Xpriv::decode(&data)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpub {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpub, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Xpub::decode(&data)
    }
}

impl From<Xpub> for XKeyIdentifier {
    fn from(key: Xpub) -> XKeyIdentifier { key.identifier() }
}

impl From<&Xpub> for XKeyIdentifier {
    fn from(key: &Xpub) -> XKeyIdentifier { key.identifier() }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding xpriv/xpub string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize { self.length }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "decoded base58 xpriv/xpub data was an invalid length: {} (expected 78)",
            self.length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;
    #[cfg(feature = "serde")]
    use internals::serde_round_trip;

    use super::ChildKeyIndex::{Hardened, Normal};
    use super::*;

    #[test]
    fn test_parse_derivation_path() {
    assert_eq!("n/0'/0".parse::<DerivationPath>(), Err(Error::InvalidChildKeyIndexFormat));
    assert_eq!("4/m/5".parse::<DerivationPath>(), Err(Error::InvalidChildKeyIndexFormat));
    assert_eq!("//3/0'".parse::<DerivationPath>(), Err(Error::InvalidChildKeyIndexFormat));
    assert_eq!("0h/0x".parse::<DerivationPath>(), Err(Error::InvalidChildKeyIndexFormat));
        assert_eq!(
            "2147483648".parse::<DerivationPath>(),
        Err(Error::InvalidChildKeyIndex(2147483648))
        );

        assert_eq!(DerivationPath::MASTER, "".parse::<DerivationPath>().unwrap());
        assert_eq!(DerivationPath::MASTER, DerivationPath::from_str("").unwrap());

        // Acceptable forms for a master path.
        assert_eq!("m".parse::<DerivationPath>().unwrap(), DerivationPath::MASTER);
        assert_eq!("m/".parse::<DerivationPath>().unwrap(), DerivationPath::MASTER);
        assert_eq!("".parse::<DerivationPath>().unwrap(), DerivationPath::MASTER);

        assert_eq!("0'".parse::<DerivationPath>(), Ok(vec![ChildKeyIndex::ZERO_HARDENED].into()));
        assert_eq!(
            "0'/1".parse::<DerivationPath>(),
            Ok(vec![ChildKeyIndex::ZERO_HARDENED, ChildKeyIndex::ONE_NORMAL].into())
        );
        assert_eq!(
            "0h/1/2'".parse::<DerivationPath>(),
            Ok(vec![
                ChildKeyIndex::ZERO_HARDENED,
                ChildKeyIndex::ONE_NORMAL,
                ChildKeyIndex::from_hardened_index(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            "0'/1/2h/2".parse::<DerivationPath>(),
            Ok(vec![
                ChildKeyIndex::ZERO_HARDENED,
                ChildKeyIndex::ONE_NORMAL,
                ChildKeyIndex::from_hardened_index(2).unwrap(),
                ChildKeyIndex::from_normal_index(2).unwrap(),
            ]
            .into())
        );
        let want = DerivationPath::from(vec![
            ChildKeyIndex::ZERO_HARDENED,
            ChildKeyIndex::ONE_NORMAL,
            ChildKeyIndex::from_hardened_index(2).unwrap(),
            ChildKeyIndex::from_normal_index(2).unwrap(),
            ChildKeyIndex::from_normal_index(1000000000).unwrap(),
        ]);
        assert_eq!("0'/1/2'/2/1000000000".parse::<DerivationPath>().unwrap(), want);
        assert_eq!("m/0'/1/2'/2/1000000000".parse::<DerivationPath>().unwrap(), want);

        let s = "0'/50/3'/5/545456";
        assert_eq!(s.parse::<DerivationPath>(), DerivationPath::from_str(s));

        let s = "m/0'/50/3'/5/545456";
        assert_eq!(s.parse::<DerivationPath>(), DerivationPath::from_str(s));
    
    }

    #[test]
    fn test_derivation_path_conversion_index() {
        let path = "0h/1/2'".parse::<DerivationPath>().unwrap();
        let numbers: Vec<ChildKeyIndex> = path.clone().into();
        let path2: DerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(&path[..2], &[ChildKeyIndex::ZERO_HARDENED, ChildKeyIndex::ONE_NORMAL]);
        let indexed: DerivationPath = path[..2].into();
        assert_eq!(indexed, "0h/1".parse::<DerivationPath>().unwrap());
        assert_eq!(indexed.with_child(HardenedChildIndex::from_index(2).unwrap().to_childkey()), path);
    }

    fn test_path<C: secp256k1::Signing + secp256k1::Verification>(
        secp: &Secp256k1<C>,
        network: NetworkKind,
        seed: &[u8],
        path: DerivationPath,
        expected_sk: &str,
        expected_pk: &str,
    ) {
        let mut sk = Xpriv::new_master(network, seed).unwrap();
        let mut pk = Xpub::from_xpriv(secp, &sk);
        // Checks derivation convenience method for Xpriv
        assert_eq!(&sk.derive_xpriv(secp, &path).to_string()[..], expected_sk);

        // Tries to convert the path into a normal path, if it fails, it should return an error
        match path.to_normal() {
            Ok(path) => {
                assert_eq!(&pk.derive_xpub(secp, &path).to_string()[..], expected_pk);
            }
            Err(e) => {
                assert_eq!(e, Error::CannotDeriveFromHardenedKey);
            }

        }
        // Derives keys, checking hardened and non-hardened derivation one-by-one
        for num in path {
            sk = sk.ckd_priv(secp, num);
            match num {
                Normal { .. } => {
                    let pk2 = pk.internal_derive_xpub(secp, num).unwrap();
                    pk = Xpub::from_xpriv(secp, &sk);
                    assert_eq!(pk, pk2);
                }
                Hardened { .. } => {
                    assert_eq!(
                        pk.try_derive_xpub(secp, &[num]),
                        Err(Error::CannotDeriveFromHardenedKey)
                    );
                    pk = Xpub::from_xpriv(secp, &sk);

                }
            }
        }

        // Check result against expected base58
        assert_eq!(&sk.to_string()[..], expected_sk);
        assert_eq!(&pk.to_string()[..], expected_pk);
        // Check decoded base58 against result
        let decoded_sk = expected_sk.parse::<Xpriv>();
        let decoded_pk = expected_pk.parse::<Xpub>();
        assert_eq!(Ok(sk), decoded_sk);
        assert_eq!(Ok(pk), decoded_pk);
    }

    #[test]
    fn test_increment() {
        let index = 9345497; // randomly generated, I promise
        let cn = ChildKeyIndex::from_normal_index(index).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildKeyIndex::from_normal_index(index + 1).unwrap()));
        let cn = ChildKeyIndex::from_hardened_index(index).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildKeyIndex::from_hardened_index(index + 1).unwrap()));

        let max = (1 << 31) - 1;
        let cn = ChildKeyIndex::from_normal_index(max).unwrap();
    assert_eq!(cn.increment().err(), Some(Error::InvalidChildKeyIndex(1 << 31)));
        let cn = ChildKeyIndex::from_hardened_index(max).unwrap();
    assert_eq!(cn.increment().err(), Some(Error::InvalidChildKeyIndex(1 << 31)));

        let cn = ChildKeyIndex::from_normal_index(350).unwrap();
        let path = DerivationPath::from_str("42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("42'/350".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/351".parse().unwrap()));

        let path = "42'/350'".parse::<DerivationPath>().unwrap();
        let mut iter = path.normal_children();
        assert_eq!(iter.next(), Some("42'/350'/0".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/350'/1".parse().unwrap()));

        let path = "42'/350'".parse::<DerivationPath>().unwrap();
        let mut iter = path.hardened_children();
        assert_eq!(iter.next(), Some("42'/350'/0'".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/350'/1'".parse().unwrap()));

        let cn = ChildKeyIndex::from_hardened_index(42350).unwrap();
        let path = "42'".parse::<DerivationPath>().unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("42'/42350'".parse().unwrap()));
        assert_eq!(iter.next(), Some("42'/42351'".parse().unwrap()));

        let cn = ChildKeyIndex::from_hardened_index(max).unwrap();
        let path = "42'".parse::<DerivationPath>().unwrap();
        let mut iter = path.children_from(cn);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_vector_1() {
        let secp = Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        // m
        test_path(&secp, NetworkKind::Main, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

        // m/0h
        test_path(&secp, NetworkKind::Main, &seed, "m/0h".parse().unwrap(),
                  "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                  "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

        // m/0h/1
        test_path(&secp, NetworkKind::Main, &seed, "m/0h/1".parse().unwrap(),
                   "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                   "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

        // m/0h/1/2h
        test_path(&secp, NetworkKind::Main, &seed, "m/0h/1/2h".parse().unwrap(),
                  "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                  "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

        // m/0h/1/2h/2
        test_path(&secp, NetworkKind::Main, &seed, "m/0h/1/2h/2".parse().unwrap(),
                  "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                  "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");

        // m/0h/1/2h/2/1000000000
        test_path(&secp, NetworkKind::Main, &seed, "m/0h/1/2h/2/1000000000".parse().unwrap(),
                  "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                  "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    }

    #[test]
    fn test_vector_2() {
        let secp = Secp256k1::new();
        let seed = hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

        // m
        test_path(&secp, NetworkKind::Main, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                  "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");

        // m/0
        test_path(&secp, NetworkKind::Main, &seed, "m/0".parse().unwrap(),
                  "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                  "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");

        // m/0/2147483647h
        test_path(&secp, NetworkKind::Main, &seed, "m/0/2147483647h".parse().unwrap(),
                  "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                  "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");

        // m/0/2147483647h/1
        test_path(&secp, NetworkKind::Main, &seed, "m/0/2147483647h/1".parse().unwrap(),
                  "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                  "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");

        // m/0/2147483647h/1/2147483646h
        test_path(&secp, NetworkKind::Main, &seed, "m/0/2147483647h/1/2147483646h".parse().unwrap(),
                  "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");

        // m/0/2147483647h/1/2147483646h/2
        test_path(&secp, NetworkKind::Main, &seed, "m/0/2147483647h/1/2147483646h/2".parse().unwrap(),
                  "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                  "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    }

    #[test]
    fn test_vector_3() {
        let secp = Secp256k1::new();
        let seed = hex!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

        // m
        test_path(&secp, NetworkKind::Main, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                  "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");

        // m/0h
        test_path(&secp, NetworkKind::Main, &seed, "m/0h".parse().unwrap(),
                  "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                  "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_child_key_index() {
        serde_round_trip!(ChildKeyIndex::ZERO_NORMAL);
        serde_round_trip!(ChildKeyIndex::ONE_NORMAL);
        serde_round_trip!(ChildKeyIndex::from_normal_index((1 << 31) - 1).unwrap());
        serde_round_trip!(ChildKeyIndex::ZERO_HARDENED);
        serde_round_trip!(ChildKeyIndex::ONE_HARDENED);
        serde_round_trip!(ChildKeyIndex::from_hardened_index((1 << 31) - 1).unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_fingerprint_chaincode() {
        use serde_json;
        let fp = Fingerprint::from([1u8, 2, 3, 42]);
        #[rustfmt::skip]
        let cc = ChainCode::from(
            [1u8,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]
        );

        serde_round_trip!(fp);
        serde_round_trip!(cc);

        assert_eq!("\"0102032a\"", serde_json::to_string(&fp).unwrap());
        assert_eq!(
            "\"0102030405060708090001020304050607080900010203040506070809000102\"",
            serde_json::to_string(&cc).unwrap()
        );
        assert_eq!("0102032a", fp.to_string());
        assert_eq!(
            "0102030405060708090001020304050607080900010203040506070809000102",
            cc.to_string()
        );
    }

    #[test]
    fn fmt_child_number() {
        assert_eq!("000005h", &format!("{:#06}", ChildKeyIndex::from_hardened_index(5).unwrap()));
        assert_eq!("5h", &format!("{:#}", ChildKeyIndex::from_hardened_index(5).unwrap()));
        assert_eq!("000005'", &format!("{:06}", ChildKeyIndex::from_hardened_index(5).unwrap()));
        assert_eq!("5'", &format!("{}", ChildKeyIndex::from_hardened_index(5).unwrap()));
        assert_eq!("42", &format!("{}", ChildKeyIndex::from_normal_index(42).unwrap()));
        assert_eq!("000042", &format!("{:06}", ChildKeyIndex::from_normal_index(42).unwrap()));
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_zeros() {
        /* this is how we generate key:
        let mut sk = secp256k1::key::ONE_KEY;

        let zeros = [0u8; 32];
        unsafe {
            sk.as_mut_ptr().copy_from(zeros.as_ptr(), 32);
        }

        let xpriv = Xpriv {
            network: NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
        child_number: ChildKeyIndex::Normal { index: 0 },
            private_key: sk,
            chain_code: ChainCode::from([0u8; 32])
        };

        println!("{}", xpriv);
         */

        // Xpriv having secret key set to all zeros
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";
        xpriv_str.parse::<Xpriv>().unwrap();
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_ffs() {
        // Xpriv having secret key set to all 0xFF's
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        xpriv_str.parse::<Xpriv>().unwrap();
    }
}
