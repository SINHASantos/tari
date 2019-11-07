// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # LibWallet API Definition
//! This module contains the Rust backend implementations of the functionality that a wallet for the Tari Base Layer
//! will require. The module contains a number of sub-modules that are implemented as async services. These services are
//! collected into the main Wallet container struct which manages spinning up all the component services and maintains a
//! collection of the handles required to interact with those services.
//! This files contians the API calls that will be exposed to external systems that make use of this module. The API
//! will be exposed via FFI and will consist of API calls that the FFI client can make into the Wallet module and a set
//! of Callbacks that the client must implement and provide to the Wallet module to receive asynchronous replies and
//! updates.
extern crate libc;
extern crate tari_wallet;

use libc::{c_char, c_uint, c_int, c_longlong, c_uchar, c_ulonglong};
use std::{
    boxed::Box,
    ffi::{CStr, CString},
    slice,
};
use tari_comms::peer_manager::NodeIdentity;
use tari_crypto::keys::SecretKey;
use tari_transactions::tari_amount::MicroTari;
use tari_utilities::ByteArray;
use tari_wallet::wallet::WalletConfig;

use core::ptr;
use std::{sync::Arc, time::Duration};
use tari_comms::{connection::NetAddress, control_service::ControlServiceConfig, peer_manager::PeerFeatures};
use tari_crypto::keys::PublicKey;
use tari_utilities::hex::Hex;
use tari_wallet::{
    contacts_service::storage::database::Contact,
    storage::memory_db::WalletMemoryDatabase,
    test_utils::generate_wallet_test_data,
};
use tokio::runtime::Runtime;

pub type TariWallet = tari_wallet::wallet::Wallet<WalletMemoryDatabase>;
pub type TariPublicKey = tari_comms::types::CommsPublicKey;
pub type TariPrivateKey = tari_comms::types::CommsSecretKey;
pub type TariCommsConfig = tari_p2p::initialization::CommsConfig;
pub struct TariContacts(Vec<TariContact>);
pub type TariContact = tari_wallet::contacts_service::storage::database::Contact;
pub type TariCompletedTransaction = tari_wallet::transaction_service::storage::database::CompletedTransaction;
pub struct TariCompletedTransactions(Vec<TariCompletedTransaction>);
pub type TariPendingInboundTransaction = tari_wallet::transaction_service::storage::database::InboundTransaction;
pub struct TariPendingInboundTransactions(Vec<TariPendingInboundTransaction>);
pub type TariPendingOutboundTransaction = tari_wallet::transaction_service::storage::database::OutboundTransaction;
pub struct TariPendingOutboundTransactions(Vec<TariPendingOutboundTransaction>);
pub struct ByteVector(Vec<c_uchar>); // declared like this so that it can be exposed to external header

/// -------------------------------- Strings ------------------------------------------------ ///

/// Destroys a char array
///
/// ## Arguments
/// `ptr` - The pointer to be freed
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C.

#[no_mangle]
pub unsafe extern "C" fn string_destroy(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- ByteVector ------------------------------------------------ ///

/// Creates a ByteVector
///
/// ## Arguments
/// `byte_array` - The pointer to the byte array
/// `element_count` - The number of elements in byte_array
///
/// ## Returns
/// `*mut ByteVector` - Pointer to the created ByteVector. Note that it will be ptr::null_mut()
/// if the byte_array pointer was null or if the elements in the byte_vector don't match
/// element_count when it is created
#[no_mangle]
pub unsafe extern "C" fn byte_vector_create(byte_array: *const c_uchar, element_count: c_uint) -> *mut ByteVector {
    let mut bytes = ByteVector(Vec::new());
    if byte_array.is_null() {
        return ptr::null_mut();
    } else {
        let array: &[c_uchar] = slice::from_raw_parts(byte_array, element_count as usize);
        bytes.0 = array.to_vec();
        if bytes.0.len() != element_count as usize {
            return ptr::null_mut();
        }
    }
    Box::into_raw(Box::new(bytes))
}

/// Destroys a ByteVector
///
/// ## Arguments
/// `bytes` - The pointer to a ByteVector
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn byte_vector_destroy(bytes: *mut ByteVector) {
    if bytes.is_null() {
        Box::from_raw(bytes);
    }
}

/// Gets a c_uchar at position in a ByteVector
///
/// ## Arguments
/// `ptr` - The pointer to a ByteVector
/// `position` - The integer position
///
/// ## Returns
/// `c_uchar` - Returns a character. Note that the character will be a null terminator (0) if ptr
/// is null or if the position is invalid
#[no_mangle]
pub unsafe extern "C" fn byte_vector_get_at(ptr: *mut ByteVector, position: c_uint) -> c_uchar {
    if ptr.is_null() {
        return 0 as c_uchar;
    }
    let len= byte_vector_get_length(ptr) as c_int - 1; // clamp to length
    if len < 0 {
        return 0 as c_uchar;
    }
    if position > len as c_uint {
        return 0 as c_uchar;
    }
    (*ptr).0.clone()[position as usize]
}

/// Gets the number of elements in a ByteVector
///
/// ## Arguments
/// `ptr` - The pointer to a ByteVector
///
/// ## Returns
/// `c_uint` - Returns the integer number of elements in the ByteVector. Note that it will be zero
/// if ptr is null
#[no_mangle]
pub unsafe extern "C" fn byte_vector_get_length(vec: *const ByteVector) -> c_uint {
    if vec.is_null() {
        return 0;
    }
    (&*vec).0.len() as c_uint
}

/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Public Key ------------------------------------------------ ///

/// Creates a TariPublicKey from a ByteVector
///
/// ## Arguments
/// `bytes` - The pointer to a ByteVector
///
/// ## Returns
/// `TariPublicKey` - Returns a public key. Note that it will be ptr::null_mut() if bytes is null or
/// if there was an error with the contents of bytes
#[no_mangle]
pub unsafe extern "C" fn public_key_create(bytes: *mut ByteVector) -> *mut TariPublicKey {
    let v;
    if !bytes.is_null() {
        v = (*bytes).0.clone();
    } else {
        return ptr::null_mut();
    }
    let pk = TariPublicKey::from_bytes(&v);
    match pk {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroys a TariPublicKey
///
/// ## Arguments
/// `pk` - The pointer to a TariPublicKey
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn public_key_destroy(pk: *mut TariPublicKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

/// Gets a ByteVector from a TariPublicKey
///
/// ## Arguments
/// `pk` - The pointer to a TariPublicKey
///
/// ## Returns
/// `*mut ByteVector` - Returns a pointer to a ByteVector. Note that it returns ptr::null_mut() if pk is null
#[no_mangle]
pub unsafe extern "C" fn public_key_get_bytes(pk: *mut TariPublicKey) -> *mut ByteVector {
    let mut bytes = ByteVector(Vec::new());
    if !pk.is_null() {
        bytes.0 = (*pk).to_vec();
    } else {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(bytes))
}

/// Creates a TariPublicKey from a TariPrivateKey
///
/// ## Arguments
/// `secret_key` - The pointer to a TariPrivateKey
///
/// ## Returns
/// `*mut TariPublicKey` - Returns a pointer to a TariPublicKey
#[no_mangle]
pub unsafe extern "C" fn public_key_from_private_key(secret_key: *mut TariPrivateKey) -> *mut TariPublicKey {
    if secret_key.is_null() {
        return ptr::null_mut();
    }
    let m = TariPublicKey::from_secret_key(&(*secret_key));
    Box::into_raw(Box::new(m))
}

/// Creates a TariPublicKey from a char array
///
/// ## Arguments
/// `key` - The pointer to a char array
///
/// ## Returns
/// `*mut TariPublicKey` - Returns a pointer to a TariPublicKey. Note that it returns ptr::null_mut()
/// if key is null or if there was an error creating the TariPublicKey from key
#[no_mangle]
pub unsafe extern "C" fn public_key_from_hex(key: *const c_char) -> *mut TariPublicKey {
    let key_str;
    if !key.is_null() {
        key_str = CStr::from_ptr(key).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }

    let public_key = TariPublicKey::from_hex(key_str.as_str());
    match public_key {
        Ok(public_key) => Box::into_raw(Box::new(public_key)),
        Err(_) => ptr::null_mut(),
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Private Key ----------------------------------------------- ///

/// Creates a TariPrivateKey from a ByteVector
///
/// ## Arguments
/// `bytes` - The pointer to a ByteVector
///
/// ## Returns
/// `*mut TariPrivateKey` - Returns a pointer to a TariPublicKey. Note that it returns ptr::null_mut()
/// if bytes is null or if there was an error creating the TariPrivateKey from bytes
#[no_mangle]
pub unsafe extern "C" fn private_key_create(bytes: *mut ByteVector) -> *mut TariPrivateKey {
    let v;
    if !bytes.is_null() {
        v = (*bytes).0.clone();
    } else {
        return ptr::null_mut();
    }
    let pk = TariPrivateKey::from_bytes(&v);
    match pk {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroys a TariPrivateKey
///
/// ## Arguments
/// `pk` - The pointer to a TariPrivateKey
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn private_key_destroy(pk: *mut TariPrivateKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

/// Gets a ByteVector from a TariPrivateKey
///
/// ## Arguments
/// `pk` - The pointer to a TariPrivateKey
///
/// ## Returns
/// `*mut ByteVectror` - Returns a pointer to a ByteVector. Note that it returns ptr::null_mut()
/// if pk is null
#[no_mangle]
pub unsafe extern "C" fn private_key_get_bytes(pk: *mut TariPrivateKey) -> *mut ByteVector {
    let mut bytes = ByteVector(Vec::new());
    if !pk.is_null() {
        bytes.0 = (*pk).to_vec();
    } else {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(bytes))
}

/// Generates a TariPrivateKey
///
/// ## Arguments
/// `()` - Does  not take any arguments
///
/// ## Returns
/// `*mut TariPrivateKey` - Returns a pointer to a TariPrivateKey
#[no_mangle]
pub unsafe extern "C" fn private_key_generate() -> *mut TariPrivateKey {
    let mut rng = rand::OsRng::new().unwrap();
    let secret_key = TariPrivateKey::random(&mut rng);
    Box::into_raw(Box::new(secret_key))
}

/// Creates a TariPrivateKey from a char array
///
/// ## Arguments
/// `key` - The pointer to a char array
///
/// ## Returns
/// `*mut TariPrivateKey` - Returns a pointer to a TariPublicKey. Note that it returns ptr::null_mut()
/// if key is null or if there was an error creating the TariPrivateKey from key
#[no_mangle]
pub unsafe extern "C" fn private_key_from_hex(key: *const c_char) -> *mut TariPrivateKey {
    let key_str;
    if !key.is_null() {
        key_str = CStr::from_ptr(key).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }

    let secret_key = TariPrivateKey::from_hex(key_str.as_str());

    match secret_key {
        Ok(secret_key) => Box::into_raw(Box::new(secret_key)),
        Err(_) => ptr::null_mut(),
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- Contact -------------------------------------------------///

/// Creates a TariContact
///
/// ## Arguments
/// `alias` - The pointer to a char array
/// `public_key` - The pointer to a TariPublicKey
///
/// ## Returns
/// `*mut TariContact` - Returns a pointer to a TariContact. Note that it returns ptr::null_mut()
/// if alias is null or if pk is null
#[no_mangle]
pub unsafe extern "C" fn contact_create(alias: *const c_char, public_key: *mut TariPublicKey) -> *mut TariContact {
    let alias_string;
    if !alias.is_null() {
        alias_string = CStr::from_ptr(alias).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }

    if public_key.is_null() {
        return ptr::null_mut();
    }

    let contact = Contact {
        alias: alias_string.to_string(),
        public_key: (*public_key).clone(),
    };
    Box::into_raw(Box::new(contact))
}

/// Gets the alias of the TariContact
///
/// ## Arguments
/// `contact` - The pointer to a TariContact
///
/// ## Returns
/// `*mut c_char` - Returns a pointer to a char array. Note that it returns an empty char array if
/// contact is null
#[no_mangle]
pub unsafe extern "C" fn contact_get_alias(contact: *mut TariContact) -> *mut c_char {
    let mut a = CString::new("").unwrap();
    if !contact.is_null() {
        a = CString::new((*contact).alias.clone()).unwrap();
    }
    CString::into_raw(a)
}

/// Gets the TariPublicKey of the TariContact
///
/// ## Arguments
/// `contact` - The pointer to a TariContact
///
/// ## Returns
/// `*mut TariPublicKey` - Returns a pointer to a TariPublicKey. Note that it returns
/// ptr::null_mut() if contact is null
#[no_mangle]
pub unsafe extern "C" fn contact_get_public_key(contact: *mut TariContact) -> *mut TariPublicKey {
    if contact.is_null() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*contact).public_key.clone()))
}

/// Destroys the TariContact
///
/// ## Arguments
/// `contact` - The pointer to a TariContact
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn contact_destroy(contact: *mut TariContact) {
    if !contact.is_null() {
        Box::from_raw(contact);
    }
}

/// ----------------------------------- Contacts -------------------------------------------------///

/// Gets the length of TariContacts
///
/// ## Arguments
/// `contacts` - The pointer to a TariContacts
///
/// ## Returns
/// `c_uint` - Returns number of elements in , zero if contacts is null
#[no_mangle]
pub unsafe extern "C" fn contacts_get_length(contacts: *mut TariContacts) -> c_uint {
    let mut len = 0;
    if !contacts.is_null() {
        len = (*contacts).0.len();
    }
    len as c_uint
}

/// Gets a TariContact from TariContacts at position
///
/// ## Arguments
/// `contacts` - The pointer to a TariContacts
/// `position` - The integer position
///
/// ## Returns
/// `*mut TariContact` - Returns a TariContact, note that it returns ptr::null_mut() if contacts is
/// null or position is invalid
#[no_mangle]
pub unsafe extern "C" fn contacts_get_at(contacts: *mut TariContacts, position: c_uint) -> *mut TariContact {
    if contacts.is_null() {
        return ptr::null_mut();
    }
    let len = contacts_get_length(contacts) as c_int - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position > len as c_uint {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*contacts).0[position as usize].clone()))
}

/// Destroys the TariContacts
///
/// ## Arguments
/// `contacts` - The pointer to a TariContacts
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn contacts_destroy(contacts: *mut TariContacts) {
    if !contacts.is_null() {
        Box::from_raw(contacts);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- CompletedTransactions ----------------------------------- ///

/// Gets the length of a TariCompletedTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariCompletedTransactions
///
/// ## Returns
/// `c_uint` - Returns the number of elements in a TariCompletedTransactions, not that it will be
/// zero if transactions is null
#[no_mangle]
pub unsafe extern "C" fn completed_transactions_get_length(transactions: *mut TariCompletedTransactions) -> c_uint {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_uint
}

/// Gets a TariCompletedTransaction from a TariCompletedTransactions at position
///
/// ## Arguments
/// `transactions` - The pointer to a TariCompletedTransactions
/// `position` - The integer position
///
/// ## Returns
/// `*mut TariCompletedTransaction` - Returns a pointer to a TariCompletedTransaction,
/// note that ptr::null_mut() is returned if transactions is null or position is invalid
#[no_mangle]
pub unsafe extern "C" fn completed_transactions_get_at(
    transactions: *mut TariCompletedTransactions,
    position: c_uint,
) -> *mut TariCompletedTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = completed_transactions_get_length(transactions) as c_int - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position > len as c_uint {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

/// Destroys a TariCompletedTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn completed_transactions_destroy(transactions: *mut TariCompletedTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- OutboundTransactions ------------------------------------ ///

/// Gets the length of a TariPendingOutboundTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingOutboundTransactions
///
/// ## Returns
/// `c_uint` - Returns the number of elements in a TariPendingOutboundTransactions, note that it will be
/// zero if transactions is null
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_get_length(
    transactions: *mut TariPendingOutboundTransactions,
) -> c_uint {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_uint
}

/// Gets a TariPendingOutboundTransaction of a TariPendingOutboundTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingOutboundTransactions
/// `position` - The integer position
///
/// ## Returns
/// `*mut TariPendingOutboundTransaction` - Returns a pointer to a TariPendingOutboundTransaction,
/// note that ptr::null_mut() is returned if transactions is null or position is invalid
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_get_at(
    transactions: *mut TariPendingOutboundTransactions,
    position: c_uint,
) -> *mut TariPendingOutboundTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = pending_outbound_transactions_get_length(transactions) as c_int - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position > len as c_uint {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

/// Destroys a TariCompletedTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingOutboundTransactions
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_destroy(transactions: *mut TariPendingOutboundTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- InboundTransactions ------------------------------------- ///

/// Gets the length of a TariPendingInboundTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingInboundTransactions
///
/// ## Returns
/// `c_uint` - Returns the number of elements in a TariPendingInboundTransactions, note that
/// it will be zero if transactions is null
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_get_length(
    transactions: *mut TariPendingInboundTransactions,
) -> c_uint {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_uint
}

/// Gets a TariPendingInboundTransaction of a TariPendingInboundTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingInboundTransactions
/// `position` - The integer position
///
/// ## Returns
/// `*mut TariPendingOutboundTransaction` - Returns a pointer to a TariPendingInboundTransaction,
/// note that ptr::null_mut() is returned if transactions is null or position is invalid
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_get_at(
    transactions: *mut TariPendingInboundTransactions,
    position: c_uint,
) -> *mut TariPendingInboundTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = pending_inbound_transactions_get_length(transactions) as c_int - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position > len as c_uint {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

/// Destroys a TariCompletedTransactions
///
/// ## Arguments
/// `transactions` - The pointer to a TariPendingInboundTransactions
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_destroy(transactions: *mut TariPendingInboundTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- CompletedTransaction ------------------------------------- ///

/// Gets the TransactionID of a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the TransactionID, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_transaction_id(
    transaction: *mut TariCompletedTransaction,
) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

/// Gets the destination TariPublicKey of a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `*mut TairPublicKey` - Returns the destination TariPublicKey, note that it will be
/// ptr::null_mut() if transaction is null
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_destination_public_key(
    transaction: *mut TariCompletedTransaction,
) -> *mut TariPublicKey {
    if transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).destination_public_key.clone();
    Box::into_raw(Box::new(m))
}

/// Gets the amount of a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the amount, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_amount(transaction: *mut TariCompletedTransaction) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

/// Gets the fee of a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the fee, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_fee(transaction: *mut TariCompletedTransaction) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).fee)
}

/// Gets the timestamp of a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the timestamp, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_transaction_timestamp(
    transaction: *mut TariCompletedTransaction,
) -> c_longlong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
}

/// Destroys a TariCompletedTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_destroy(transaction: *mut TariCompletedTransaction) {
    if !transaction.is_null() {
        Box::from_raw(transaction);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- OutboundTransaction ------------------------------------- ///

/// Gets the TransactionId of a TariPendingOutboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingOutboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the TransactionID, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_transaction_id(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

/// Gets the destination TariPublicKey of a TariPendingOutboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingOutboundTransaction
///
/// ## Returns
/// `*mut TariPublicKey` - Returns the destination TariPublicKey, note that it will be
/// ptr::null_mut() if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_destination_public_key(
    transaction: *mut TariPendingOutboundTransaction,
) -> *mut TariPublicKey {
    if transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).destination_public_key.clone();
    Box::into_raw(Box::new(m))
}

/// Gets the amount of a TariPendingOutboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingOutboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the amount, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_amount(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

/// Gets the timestamp of a TariPendingOutboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingOutboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the timestamp, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_transaction_timestamp(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_longlong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
}

/// Destroys a TariPendingOutboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariCompletedTransaction
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_destroy(transaction: *mut TariPendingOutboundTransaction) {
    if !transaction.is_null() {
        Box::from_raw(transaction);
    }
}

/// -------------------------------------------------------------------------------------------- ///
///
/// ----------------------------------- InboundTransaction ------------------------------------- ///

/// Gets the TransactionId of a TariPendingInboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingInboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the TransactonId, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_transaction_id(
    transaction: *mut TariPendingInboundTransaction,
) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

/// Gets the source TariPublicKey of a TariPendingInboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingInboundTransaction
///
/// ## Returns
/// `*mut TariPublicKey` - Returns a pointer to the source TariPublicKey, note that it will be
/// ptr::null_mut() if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_source_public_key(
    transaction: *mut TariPendingInboundTransaction,
) -> *mut TariPublicKey {
    if transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).source_public_key.clone();
    Box::into_raw(Box::new(m))
}

/// Gets the amount of a TariPendingInboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingInboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the amount, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_amount(
    transaction: *mut TariPendingInboundTransaction,
) -> c_ulonglong {
    if transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

/// Gets the timestamp of a TariPendingInboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingInboundTransaction
///
/// ## Returns
/// `c_ulonglong` - Returns the timestamp, note that it will be zero if transaction is null
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_transaction_timestamp(
    transaction: *mut TariPendingInboundTransaction,
) -> c_longlong {
    if transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
}

/// Destroys a TariPendingInboundTransaction
///
/// ## Arguments
/// `transaction` - The pointer to a TariPendingInboundTransaction
///
/// ## Returns
/// `()` - Does not return a value, equivalent to void in C
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_destroy(transaction: *mut TariPendingInboundTransaction) {
    if !transaction.is_null() {
        Box::from_raw(transaction);
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- CommsConfig ---------------------------------------------///

#[no_mangle]
pub unsafe extern "C" fn comms_config_create(
    address: *const c_char,
    database_name: *const c_char,
    datastore_path: *const c_char,
    secret_key: *mut TariPrivateKey,
) -> *mut TariCommsConfig
{
    let address_string;
    if !address.is_null() {
        address_string = CStr::from_ptr(address).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }
    let database_name_string;
    if !database_name.is_null() {
        database_name_string = CStr::from_ptr(database_name).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }
    let datastore_path_string;
    if !datastore_path.is_null() {
        datastore_path_string = CStr::from_ptr(datastore_path).to_str().unwrap().to_owned();
    } else {
        return ptr::null_mut();
    }

    let net_address = address_string.parse::<NetAddress>();

    match net_address {
        Ok(net_address) => {
            let ni = NodeIdentity::new(
                (*secret_key).clone(),
                net_address.clone(),
                PeerFeatures::COMMUNICATION_CLIENT,
            )
            .unwrap();

            let config = TariCommsConfig {
                node_identity: Arc::new(ni.clone()),
                host: net_address.host().parse().unwrap(),
                socks_proxy_address: None,
                control_service: ControlServiceConfig {
                    listener_address: ni.control_service_address(),
                    socks_proxy_address: None,
                    requested_connection_timeout: Duration::from_millis(2000),
                },
                datastore_path: datastore_path_string,
                peer_database_name: database_name_string,
                inbound_buffer_size: 100,
                outbound_buffer_size: 100,
                dht: Default::default(),
            };

            Box::into_raw(Box::new(config))
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn comms_config_destroy(wc: *mut TariCommsConfig) {
    if !wc.is_null() {
        Box::from_raw(wc);
    }
}

/// ---------------------------------------------------------------------------------------------- ///

/// ------------------------------------- Wallet -------------------------------------------------///

#[no_mangle]
pub unsafe extern "C" fn wallet_create(config: *mut TariCommsConfig) -> *mut TariWallet {
    if config.is_null() {
        return ptr::null_mut();
    }
    // TODO Gracefully handle the case where these expects would fail
    let runtime = Runtime::new();
    let w;
    match runtime {
        Ok(runtime) => {
            w = TariWallet::new(
                WalletConfig {
                    comms_config: (*config).clone(),
                },
                WalletMemoryDatabase::new(),
                runtime,
            );
            match w {
                Ok(w) => Box::into_raw(Box::new(w)),
                Err(_) => ptr::null_mut(),
            }
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_generate_test_data(wallet: *mut TariWallet) -> bool {
    if wallet.is_null() {
        return false;
    }
    match generate_wallet_test_data(&mut *wallet) {
        Ok(_) => true,
        _ => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_add_base_node_peer(
    wallet: *mut TariWallet,
    public_key: *mut TariPublicKey,
    address: *const c_char,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if public_key.is_null() {
        return false;
    }

    let address_string;
    if !address.is_null() {
        address_string = CStr::from_ptr(address).to_str().unwrap().to_owned();
    } else {
        return false;
    }

    match (*wallet).add_base_node_peer((*public_key).clone(), address_string) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub unsafe extern "C" fn wallet_add_contact(wallet: *mut TariWallet, contact: *mut TariContact) -> bool {
    if wallet.is_null() {
        return false;
    }
    if contact.is_null() {
        return false;
    }

    match (*wallet)
        .runtime
        .block_on((*wallet).contacts_service.save_contact((*contact).clone()))
    {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub unsafe extern "C" fn wallet_remove_contact(wallet: *mut TariWallet, contact: *mut TariContact) -> bool {
    if wallet.is_null() {
        return false;
    }
    if contact.is_null() {
        return false;
    }

    match (*wallet)
        .runtime
        .block_on((*wallet).contacts_service.remove_contact((*contact).public_key.clone()))
    {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_balance(wallet: *mut TariWallet) -> c_ulonglong {
    if wallet.is_null() {
        return 0;
    }

    match (*wallet)
        .runtime
        .block_on((*wallet).output_manager_service.get_balance())
    {
        Ok(b) => u64::from(b),
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_send_transaction(
    wallet: *mut TariWallet,
    dest_public_key: *mut TariPublicKey,
    amount: c_ulonglong,
    fee_per_gram: c_ulonglong,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if dest_public_key.is_null() {
        return false;
    }

    match (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.send_transaction(
            (*dest_public_key).clone(),
            MicroTari::from(amount),
            MicroTari::from(fee_per_gram),
        )) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_contacts(wallet: *mut TariWallet) -> *mut TariContacts {
    let mut contacts = Vec::new();
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let retrieved_contacts = (*wallet).runtime.block_on((*wallet).contacts_service.get_contacts());
    match retrieved_contacts {
        Ok(retrieved_contacts) => {
            contacts.append(&mut retrieved_contacts.clone());
            Box::into_raw(Box::new(TariContacts(contacts)))
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_completed_transactions(wallet: *mut TariWallet) -> *mut TariCompletedTransactions {
    let mut completed = Vec::new();
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let completed_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_completed_transactions());
    match completed_transactions {
        Ok(completed_transactions) => {
            for (_id, tx) in &completed_transactions {
                completed.push(tx.clone());
            }
            Box::into_raw(Box::new(TariCompletedTransactions(completed)))
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_pending_inbound_transactions(
    wallet: *mut TariWallet,
) -> *mut TariPendingInboundTransactions {
    let mut pending = Vec::new();
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_inbound_transactions());
    match pending_transactions {
        Ok(pending_transactions) => {
            for (_id, tx) in &pending_transactions {
                pending.push(tx.clone());
            }
            Box::into_raw(Box::new(TariPendingInboundTransactions(pending)))
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_pending_outbound_transactions(
    wallet: *mut TariWallet,
) -> *mut TariPendingOutboundTransactions {
    let mut pending = Vec::new();
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_outbound_transactions());
    match pending_transactions {
        Ok(pending_transactions) => {
            for (_id, tx) in &pending_transactions {
                pending.push(tx.clone());
            }
            Box::into_raw(Box::new(TariPendingOutboundTransactions(pending)))
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_completed_transaction_by_id(
    wallet: *mut TariWallet,
    transaction_id: c_ulonglong,
) -> *mut TariCompletedTransaction
{
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_completed_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id {
                    let pending = tx.clone();
                    return Box::into_raw(Box::new(pending));
                }
            }
            return ptr::null_mut();
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_pending_inbound_transaction_by_id(
    wallet: *mut TariWallet,
    transaction_id: c_ulonglong,
) -> *mut TariPendingInboundTransaction
{
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_inbound_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id {
                    let pending = tx.clone();
                    return Box::into_raw(Box::new(pending));
                }
            }
            return ptr::null_mut();
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_get_pending_outbound_transaction_by_id(
    wallet: *mut TariWallet,
    transaction_id: c_ulonglong,
) -> *mut TariPendingOutboundTransaction
{
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_outbound_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id {
                    let pending = tx.clone();
                    return Box::into_raw(Box::new(pending));
                }
            }
            return ptr::null_mut();
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_destroy(wallet: *mut TariWallet) {
    if !wallet.is_null() {
        let m = Box::from_raw(wallet);
        let l = m.shutdown();
        match l {
            Ok(_l) => {},
            Err(_) => {},
        }
    }
}


/// ------------------------------------- Callbacks -------------------------------------------- ///

#[no_mangle]
pub unsafe extern "C" fn wallet_call_back_register_received_transaction(
    wallet: *mut TariWallet,
    call: unsafe extern "C" fn(*mut TariPendingInboundTransaction),
) -> bool
{
    let result = (*wallet)
        .runtime
        .block_on((*wallet).register_callback_received_transaction(call));
    match result {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn wallet_call_back_register_received_transaction_reply(
    wallet: *mut TariWallet,
    call: unsafe extern "C" fn(*mut TariCompletedTransaction),
) -> bool
{
    let result = (*wallet)
        .runtime
        .block_on((*wallet).register_callback_received_transaction_reply(call));
    match result {
        Ok(_) => true,
        Err(_) => false,
    }
}

// TODO Callbacks to be written and registered to receive the following events
// Transaction hit the mempool (send and receive), wallet needs to be extended for this
// Transaction is mined, wallet needs to be extended for this
// Transaction is confirmed, wallet needs to be extended for this

// TODO (Potentially) Add optional error parameter to methods which can return null
// TODO Write additional tests

#[cfg(test)]
mod test {
    extern crate libc;
    use crate::*;
    use libc::{c_char, c_uint, c_uchar};
    use std::ffi::CString;

    unsafe extern "C" fn completed_callback(tx:*mut TariCompletedTransaction)
    {
        assert_eq!(tx.is_null(),false);
        completed_transaction_destroy(tx);
    }

    unsafe extern "C" fn inbound_callback(tx:*mut TariPendingInboundTransaction)
    {
        assert_eq!(tx.is_null(),false);
        pending_inbound_transaction_destroy(tx);
    }

    #[test]
    fn test_string_destroy() {
        unsafe {
            let m = CString::new("Test").unwrap();
            let m_ptr: *mut c_char = CString::into_raw(m) as *mut c_char;
            assert_ne!(m_ptr.is_null(), true);
            assert!(*m_ptr > 0); // dereference will return first character as integer, T as i8 = 84 > 0 = true
            string_destroy(m_ptr);
            assert_eq!(*m_ptr, 0); // dereference will return zero, avoids malloc error if attempting to evaluate by
                                   // other means.
        }
    }

    #[test]
    fn test_bytevector() {
        unsafe {
            let bytes: [c_uchar; 4] = [2, 114, 34, 255];
            let bytes_ptr = byte_vector_create(bytes.as_ptr(), bytes.len() as c_uint);
            let length = byte_vector_get_length(bytes_ptr);
            // println!("{:?}",c);
            assert_eq!(length, bytes.len() as c_uint);
            let byte = byte_vector_get_at(bytes_ptr, 2);
            assert_eq!(byte, bytes[2]);
            byte_vector_destroy(bytes_ptr);
        }
    }

    #[test]
    fn test_keys() {
        unsafe {
            let private_key = private_key_generate();
            let public_key = public_key_from_private_key(private_key);
            let private_key_length = byte_vector_get_length(private_key_get_bytes(private_key));
            let public_key_length = byte_vector_get_length(public_key_get_bytes(public_key));
            assert_eq!(private_key_length, 32);
            assert_eq!(public_key_length, 32);
            assert_ne!(private_key_get_bytes(private_key), public_key_get_bytes(public_key));
        }
    }

    #[test]
    fn test_wallet_ffi() {
        unsafe {
            let secret_key_alice = private_key_generate();
            let public_key_alice = public_key_from_private_key(secret_key_alice.clone());
            let db_name_alice = CString::new("ffi_test1_alice").unwrap();
            let db_name_alice_str: *const c_char = CString::into_raw(db_name_alice.clone()) as *const c_char;
            let db_path_alice = CString::new("./data_alice").unwrap();
            let db_path_alice_str: *const c_char = CString::into_raw(db_path_alice.clone()) as *const c_char;
            let address_alice = CString::new("127.0.0.1:21443").unwrap();
            let address_alice_str: *const c_char = CString::into_raw(address_alice.clone()) as *const c_char;
            let alice_config = comms_config_create(
                address_alice_str,
                db_name_alice_str,
                db_path_alice_str,
                secret_key_alice,
            );
            let alice_wallet = wallet_create(alice_config);

            let secret_key_bob = private_key_generate();
            let public_key_bob = public_key_from_private_key(secret_key_bob.clone());
            let db_name_bob = CString::new("ffi_test1_bob").unwrap();
            let db_name_bob_str: *const c_char = CString::into_raw(db_name_bob.clone()) as *const c_char;
            let db_path_bob = CString::new("./data_bob").unwrap();
            let db_path_bob_str: *const c_char = CString::into_raw(db_path_bob.clone()) as *const c_char;
            let address_bob = CString::new("127.0.0.1:21441").unwrap();
            let address_bob_str: *const c_char = CString::into_raw(address_bob.clone()) as *const c_char;
            let bob_config = comms_config_create(address_bob_str, db_name_bob_str, db_path_bob_str, secret_key_bob);
            let bob_wallet = wallet_create(bob_config);

            wallet_add_base_node_peer(alice_wallet, public_key_bob.clone(), address_bob_str);
            wallet_add_base_node_peer(bob_wallet, public_key_alice.clone(), address_alice_str);


            wallet_call_back_register_received_transaction(alice_wallet,inbound_callback);
            wallet_call_back_register_received_transaction_reply(alice_wallet, completed_callback);

            wallet_generate_test_data(alice_wallet);

            let contacts = wallet_get_contacts(alice_wallet);
            assert_eq!(contacts_get_length(contacts), 4);

            // free string memory
            string_destroy(db_name_alice_str as *mut c_char);
            string_destroy(db_path_alice_str as *mut c_char);
            string_destroy(address_alice_str as *mut c_char);
            string_destroy(db_name_bob_str as *mut c_char);
            string_destroy(db_path_bob_str as *mut c_char);
            string_destroy(address_bob_str as *mut c_char);
            // free wallet memory
            wallet_destroy(alice_wallet);
            wallet_destroy(bob_wallet);
            // free keys
            private_key_destroy(secret_key_alice);
            private_key_destroy(secret_key_bob);
            public_key_destroy(public_key_alice);
            public_key_destroy(public_key_bob);
            // free config memory
            comms_config_destroy(bob_config);
            comms_config_destroy(alice_config);
        }
    }
}
