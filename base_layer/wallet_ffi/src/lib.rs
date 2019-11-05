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

use libc::{c_char, c_int, c_longlong, c_uchar, c_ulonglong};
use std::{
    boxed::Box,
    ffi::{CStr, CString},
    slice,
};
use tari_comms::peer_manager::NodeIdentity;
use tari_crypto::keys::SecretKey;
use tari_transactions::tari_amount::MicroTari;
use tari_utilities::ByteArray;
use tari_wallet::wallet::{WalletConfig};

use core::ptr;
use std::{sync::Arc, time::Duration};
use tari_comms::{connection::NetAddress, control_service::ControlServiceConfig, peer_manager::PeerFeatures};
use tari_crypto::{keys::PublicKey};
use tari_utilities::hex::Hex;
use tari_wallet::{
    contacts_service::storage::database::Contact,
    storage::memory_db::WalletMemoryDatabase,
    test_utils::generate_wallet_test_data,
};
use tokio::runtime::Runtime;

pub type TariWallet = tari_wallet::wallet::Wallet<WalletMemoryDatabase>;
pub type TariWalletConfig = tari_wallet::wallet::WalletConfig;
pub type TariDateTime = chrono::NaiveDateTime;
pub type TariPublicKey = tari_comms::types::CommsPublicKey;
pub type TariPrivateKey = tari_comms::types::CommsSecretKey;
pub type TariCommsConfig = tari_p2p::initialization::CommsConfig;
pub type TariContact = tari_wallet::contacts_service::storage::database::Contact;
pub type TariCompletedTransaction = tari_wallet::transaction_service::storage::database::CompletedTransaction;
pub struct TariCompletedTransactions(Vec<TariCompletedTransaction>);
pub type TariPendingInboundTransaction = tari_wallet::transaction_service::storage::database::InboundTransaction;
pub struct TariPendingInboundTransactions(Vec<TariPendingInboundTransaction>);
pub type TariPendingOutboundTransaction = tari_wallet::transaction_service::storage::database::OutboundTransaction;
pub struct TariPendingOutboundTransactions(Vec<TariPendingOutboundTransaction>);
pub struct TariContacts(Vec<TariContact>);
pub struct ByteVector(Vec<c_uchar>); // declared like this so that it can be exposed to external header

/// -------------------------------- Strings ------------------------------------------------ ///
// Frees memory for string pointer
#[no_mangle]
pub unsafe extern "C" fn free_string(o: *mut c_char) {
    if !o.is_null() {
        let _ = CString::from_raw(o);
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- ByteVector ------------------------------------------------ ///
#[no_mangle]
pub unsafe extern "C" fn byte_vector_create(byte_array: *const c_uchar, element_count: c_int) -> *mut ByteVector {
    let mut bytes = ByteVector(Vec::new());
    if !byte_array.is_null() {
        let array: &[c_uchar] = slice::from_raw_parts(byte_array, element_count as usize);
        bytes.0 = array.to_vec();
        if bytes.0.len() != element_count as usize {
            return ptr::null_mut();
        }
    }
    Box::into_raw(Box::new(bytes))
}

#[no_mangle]
pub unsafe extern "C" fn byte_vector_destroy(bytes: *mut ByteVector) {
    if bytes.is_null() {
        Box::from_raw(bytes);
    }
}

/// returns c_uchar at position in internal vector
#[no_mangle]
pub unsafe extern "C" fn byte_vector_get_at(ptr: *mut ByteVector, position: c_int) -> c_uchar {
    if ptr.is_null() {
        return 0 as c_uchar;
    }
    let len = byte_vector_get_length(ptr) - 1; // clamp to length
    if len < 0 {
        return 0 as c_uchar;
    }
    if position < 0 {
        return 0 as c_uchar;
    } else if position > len {
        return 0 as c_uchar;
    }
    (*ptr).0.clone()[position as usize]
}

/// Returns the number of items, zero-indexed
#[no_mangle]
pub unsafe extern "C" fn byte_vector_get_length(vec: *const ByteVector) -> c_int {
    if vec.is_null() {
        return 0;
    }
    (&*vec).0.len() as c_int
}

/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Public Key ------------------------------------------------ ///

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

#[no_mangle]
pub unsafe extern "C" fn public_key_destroy(pk: *mut TariPublicKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

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

#[no_mangle]
pub unsafe extern "C" fn public_key_from_private_key(secret_key: *mut TariPrivateKey) -> *mut TariPublicKey {
    if secret_key.is_null() {
        return ptr::null_mut();
    }
    let m = TariPublicKey::from_secret_key(&(*secret_key));
    Box::into_raw(Box::new(m))
}

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

#[no_mangle]
pub unsafe extern "C" fn private_key_destroy(pk: *mut TariPrivateKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

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

#[no_mangle]
pub unsafe extern "C" fn private_key_generate() -> *mut TariPrivateKey {
    let mut rng = rand::OsRng::new().unwrap();
    let secret_key = TariPrivateKey::random(&mut rng);
    Box::into_raw(Box::new(secret_key))
}

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

#[no_mangle]
pub unsafe extern "C" fn contact_get_alias(contact: *mut TariContact) -> *mut c_char {
    let mut a = CString::new("").unwrap();
    if !contact.is_null() {
        a = CString::new((*contact).alias.clone()).unwrap();
    }
    CString::into_raw(a)
}

#[no_mangle]
pub unsafe extern "C" fn contact_get_public_key(contact: *mut TariContact) -> *mut TariPublicKey {
    if contact.is_null() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*contact).public_key.clone()))
}

#[no_mangle]
pub unsafe extern "C" fn contact_destroy(contact: *mut TariContact) {
    if !contact.is_null() {
        Box::from_raw(contact);
    }
}

/// ----------------------------------- Contacts -------------------------------------------------///

// no create since cloned from wallet, never passed to wallet

#[no_mangle]
pub unsafe extern "C" fn contacts_get_length(contact: *mut TariContacts) -> c_int {
    let mut len = 0;
    if !contact.is_null() {
        len = (*contact).0.len();
    }
    len as c_int
}

#[no_mangle]
pub unsafe extern "C" fn contacts_get_at(contacts: *mut TariContacts, position: c_int) -> *mut TariContact {
    if contacts.is_null() {
        return ptr::null_mut();
    }
    let len = contacts_get_length(contacts) - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position < 0 {
        return ptr::null_mut();
    }
    if position > len {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*contacts).0[position as usize].clone()))
}

// destructor since cloned from wallet
#[no_mangle]
pub unsafe extern "C" fn contacts_destroy(contacts: *mut TariContacts) {
    if !contacts.is_null() {
        Box::from_raw(contacts);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- CompletedTransactions ----------------------------------- ///
#[no_mangle]
pub unsafe extern "C" fn completed_transactions_get_length(transactions: *mut TariCompletedTransactions) -> c_int {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_int
}

#[no_mangle]
pub unsafe extern "C" fn ccompleted_transactions_get_at(
    transactions: *mut TariCompletedTransactions,
    position: c_int,
) -> *mut TariCompletedTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = completed_transactions_get_length(transactions) - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position < 0 {
        return ptr::null_mut();
    }
    if position > len {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

// destructor since cloned from wallet
#[no_mangle]
pub unsafe extern "C" fn completed_transactions_destroy(transactions: *mut TariCompletedTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- OutboundTransactions ------------------------------------ ///
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_get_length(
    transactions: *mut TariPendingOutboundTransactions,
) -> c_int {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_get_at(
    transactions: *mut TariPendingOutboundTransactions,
    position: c_int,
) -> *mut TariPendingOutboundTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = pending_outbound_transactions_get_length(transactions) - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position < 0 {
        return ptr::null_mut();
    }
    if position > len {
        return ptr::null_mut()
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

// destructor since cloned from wallet
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transactions_destroy(transactions: *mut TariPendingOutboundTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- InboundTransactions ------------------------------------- ///
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_get_length(
    transactions: *mut TariPendingInboundTransactions,
) -> c_int {
    let mut len = 0;
    if !transactions.is_null() {
        len = (*transactions).0.len();
    }
    len as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_get_at(
    transactions: *mut TariPendingInboundTransactions,
    position: c_int,
) -> *mut TariPendingInboundTransaction
{
    if transactions.is_null() {
        return ptr::null_mut();
    }
    let len = pending_inbound_transactions_get_length(transactions) - 1;
    if len < 0 {
        return ptr::null_mut();
    }
    if position < 0 {
        return ptr::null_mut()
    }
    if position > len {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new((*transactions).0[position as usize].clone()))
}

// destructor since cloned from wallet
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transactions_destroy(transactions: *mut TariPendingInboundTransactions) {
    if !transactions.is_null() {
        Box::from_raw(transactions);
    }
}

/// -------------------------------------------------------------------------------------------- ///
///
/// ----------------------------------- CompletedTransaction ------------------------------------- ///
#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_transaction_id(
    transaction: *mut TariCompletedTransaction,
) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_destination_public_key(
    transaction: *mut TariCompletedTransaction,
) -> *mut TariPublicKey {
    if !transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).destination_public_key.clone();
    Box::into_raw(Box::new(m))
}

#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_amount(transaction: *mut TariCompletedTransaction) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_fee(transaction: *mut TariCompletedTransaction) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).fee)
}

#[no_mangle]
pub unsafe extern "C" fn completed_transaction_get_transaction_timestamp(
    transaction: *mut TariCompletedTransaction,
) -> c_longlong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
}
/// -------------------------------------------------------------------------------------------- ///

/// ----------------------------------- OutboundTransaction ------------------------------------- ///
#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_transaction_id(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_destination_public_key(
    transaction: *mut TariPendingOutboundTransaction,
) -> *mut TariPublicKey {
    if !transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).destination_public_key.clone();
    Box::into_raw(Box::new(m))
}

#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_amount(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

#[no_mangle]
pub unsafe extern "C" fn pending_outbound_transaction_get_transaction_timestamp(
    transaction: *mut TariPendingOutboundTransaction,
) -> c_longlong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
}
/// -------------------------------------------------------------------------------------------- ///
///
/// ----------------------------------- InboundTransaction ------------------------------------- ///
#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_transaction_id(
    transaction: *mut TariPendingInboundTransaction,
) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).tx_id as c_ulonglong
}

#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_source_public_key(
    transaction: *mut TariPendingInboundTransaction,
) -> *mut TariPublicKey {
    if !transaction.is_null() {
        return ptr::null_mut();
    }
    let m = (*transaction).source_public_key.clone();
    Box::into_raw(Box::new(m))
}

#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_amount(
    transaction: *mut TariPendingInboundTransaction,
) -> c_ulonglong {
    if !transaction.is_null() {
        return 0;
    }
    c_ulonglong::from((*transaction).amount)
}

#[no_mangle]
pub unsafe extern "C" fn pending_inbound_transaction_get_transaction_timestamp(
    transaction: *mut TariPendingInboundTransaction,
) -> c_longlong {
    if !transaction.is_null() {
        return 0;
    }
    (*transaction).timestamp.timestamp() as c_longlong
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

// test code
// #[no_mangle]
// pub unsafe extern "C" fn wallet_get_num_completed_tx(wallet: *mut TariWallet) -> c_ulonglong {
// if wallet.is_null() {
// return 0;
// }
//
// match (*wallet)
// .runtime
// .block_on((*wallet).transaction_service.get_completed_transactions())
// {
// Ok(c) => c.len() as u64,
// Err(_) => 0,
// }
// }

// Create and send the first stage of a transaction to the specified wallet for the specified amount and with the
// specified fee.
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
pub unsafe extern "C" fn wallet_get_pending_completed_transaction_by_id(
    wallet: *mut TariWallet,
    transaction_id: c_ulonglong
) -> *mut TariCompletedTransaction {
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_completed_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id
                {
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
    transaction_id: c_ulonglong
) -> *mut TariPendingInboundTransaction {
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_inbound_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id
                {
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
    transaction_id: c_ulonglong
) -> *mut TariPendingOutboundTransaction {
    if wallet.is_null() {
        return ptr::null_mut();
    }

    let pending_transactions = (*wallet)
        .runtime
        .block_on((*wallet).transaction_service.get_pending_outbound_transactions());

    match pending_transactions {
        Ok(pending_transactions) => {
            for (id, tx) in &pending_transactions {
                if id == &transaction_id
                {
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

// TODO (Potentially) Add optional error parameter to methods which can return null

// Callback Definition - Example

// Will probably have to implement as a struct of callbacks in wallet, with wallet only calling the
// functions if they are callable from the relevant wallet function, where the register callback functions
// will bind the relevant c equivalent function pointer to the associated function
// The Rust
//
// use std::os::raw::{c_int, c_uchar};
//
// #[no_mangle]
// pub struct MyState {
// pub call_back: extern "C" fn(*const c_uchar) -> c_int
// }
//
// #[no_mangle]
// pub extern fn get_state(call: extern "C" fn(*const c_uchar) -> c_int) -> *const () {
// let state = MyState { call_back: call };
// Box::into_raw(Box::new(state)) as *const _
// }
//
// #[no_mangle]
// pub extern fn run(state: *mut MyState) -> c_int {
// unsafe {
// ((*state).call_back)(format!("Callback run").as_ptr())
// }
// }
//
// #[no_mangle]
// pub extern fn delete_state(state: *mut MyState) {
// unsafe {
// Box::from_raw(state);
// }
// }
//
// The C
// #include <iostream>
//
// extern "C" {
// void* get_state(int (*callback)(char*));
// int run(void* state);
// void delete_state(void* state);
// }
//

#[no_mangle]
#[derive(Debug, Clone, Copy)]
pub struct CallBacks {
    pub call_back_received_transaction: Option<extern "C" fn(c_ulonglong)>,
    pub call_back_received_transaction_reply: Option<extern "C" fn(c_ulonglong)>,
}

impl CallBacks {
    pub fn new() -> CallBacks {
        CallBacks {
            call_back_received_transaction: None,
            call_back_received_transaction_reply: None,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn call_back_create() -> *const () {
    let callbacks = CallBacks::new();
    Box::into_raw(Box::new(callbacks)) as *const _
}

#[no_mangle]
pub unsafe extern "C" fn call_back_register_received_transaction(
    callbacks: *mut CallBacks,
    call: extern "C" fn(c_ulonglong),
)
{
    (*callbacks).call_back_received_transaction = Some(call);
}

#[no_mangle]
pub unsafe extern "C" fn call_back_register_received_transaction_reply(
    callbacks: *mut CallBacks,
    call: extern "C" fn(c_ulonglong),
)
{
    (*callbacks).call_back_received_transaction_reply = Some(call);
}

#[no_mangle]
pub unsafe extern "C" fn callbacks_desktroy(calls: *mut CallBacks) {
    if !calls.is_null() {
        Box::from_raw(calls);
    }
}
// ------------------------------------------------------------------------------------------------
// Callback Functions
// ------------------------------------------------------------------------------------------------
// These functions must be implemented by the FFI client and registered with LibWallet so that
// LibWallet can directly respond to the client when events occur

// TODO Callbacks to be written and registered to receive the following events
// Transaction hit the mempool (send and receive), wallet needs to be extended for this
// Transaction is mined, wallet needs to be extended for this
// Transaction is confirmed, wallet needs to be extended for this

#[cfg(test)]
mod test {
    extern crate libc;
    use crate::*;
    use libc::{c_char, c_int, c_uchar};
    use std::ffi::CString;

    #[test]
    fn test_free_string() {
        unsafe {
            let m = CString::new("Test").unwrap();
            let m_ptr: *mut c_char = CString::into_raw(m) as *mut c_char;
            assert_ne!(m_ptr.is_null(), true);
            assert!(*m_ptr > 0); // dereference will return first character as integer, T as i8 = 84 > 0 = true
            free_string(m_ptr);
            assert_eq!(*m_ptr, 0); // dereference will return zero, avoids malloc error if attempting to evaluate by
                                   // other means.
        }
    }

    #[test]
    fn test_bytevector() {
        unsafe {
            let bytes: [c_uchar; 4] = [2, 114, 34, 255];
            let bytes_ptr = byte_vector_create(bytes.as_ptr(), bytes.len() as c_int);
            let length = byte_vector_get_length(bytes_ptr);
            // println!("{:?}",c);
            assert_eq!(length, bytes.len() as i32);
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
            let private_key_length = byte_vector_get_length(private_key_get_byte_vector(private_key));
            let public_key_length = byte_vector_get_length(public_key_get_key(public_key));
            assert_eq!(private_key_length, 32);
            assert_eq!(public_key_length, 32);
            assert_ne!(private_key_get_byte_vector(private_key), public_key_get_key(public_key));
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

            wallet_generate_test_data(alice_wallet);

            let contacts = wallet_get_contacts(alice_wallet);
            assert_eq!(contacts_get_length(contacts), 4);

            // free string memory
            free_string(db_name_alice_str as *mut c_char);
            free_string(db_path_alice_str as *mut c_char);
            free_string(address_alice_str as *mut c_char);
            free_string(db_name_bob_str as *mut c_char);
            free_string(db_path_bob_str as *mut c_char);
            free_string(address_bob_str as *mut c_char);
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
