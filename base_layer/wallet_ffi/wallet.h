//  wallet_ffi.h

/*
    Package MobileWallet
    Created by David Main on 10/30/19
    Using Swift 5.0
    Running on macOS 10.14

    Copyright 2019 The Tari Project

    Redistribution and use in source and binary forms, with or
    without modification, are permitted provided that the
    following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of
    its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
    CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
    OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef wallet_ffi_h
#define wallet_ffi_h

#include <stdio.h>
#include <stdbool.h>

struct ByteVector;

struct TariCommsConfig;

struct TariPrivateKey;

struct TariWallet;

struct TariWalletConfig;

struct TariPublicKey;

struct TariContacts;

struct TariContact;

struct TariCompletedTransactions;

struct TariCompletedTransaction;

struct TariPendingOutboundTransactions;

struct TariPendingOutboundTransaction;

struct TariPendingInboundTransactions;

struct TariPendingInboundTransaction;


/// -------------------------------- Strings ----------------------------------------------- ///

void free_string(char *s);

/// -------------------------------- ByteVector ----------------------------------------------- ///

struct ByteVector *byte_vector_create(const unsigned char *byte_array, int element_count);

unsigned char byte_vector_get_at(struct ByteVector *ptr, int i);

int byte_vector_get_length(const struct ByteVector *vec);

void byte_vector_destroy(struct ByteVector *bytes);

/// -------------------------------- TariPublicKey ----------------------------------------------- ///

struct TariPublicKey *public_key_create(struct ByteVector *bytes);

struct ByteVector *public_key_get_bytes(struct TariPublicKey *public_key);

struct TariPublicKey *public_key_get_from_private_key(struct TariPrivateKey *secret_key);

struct TariPublicKey *public_key_from_hex(const char *hex);

void public_key_destroy(struct TariPublicKey *pk);

/// -------------------------------- TariPrivateKey ----------------------------------------------- ///

struct TariPrivateKey *private_key_create(struct ByteVector *bytes);

struct TariPrivateKey *private_key_generate(void);

struct ByteVector *private_key_get_bytes(struct TariPrivateKey *private_key);

struct ByteVector *private_key_get_key(struct TariPrivateKey *pk);

struct TariPrivateKey *private_key_from_hex(const char *hex);

void private_key_destroy(struct TariPrivateKey *pk);

/// -------------------------------- Contact ------------------------------------------------------ ///
struct TariContact *contact_create(const char *alias, struct TariPublicKey *public_key);

char *contact_get_alias(struct TariContact *contact);

struct TariPublicKey *contact_get_public_key(struct TariContact *contact);

void contact_destroy(struct TariContact *contact);

/// -------------------------------- Contacts ------------------------------------------------------ ///
int contacts_get_length(struct TariContacts *contacts);

struct TariContact *contacts_get_at(struct TariContacts *contacts, int position);

void contacts_destroy(struct TariContacts *contacts);

/// -------------------------------- CompletedTransaction ------------------------------------------------------ ///
unsigned long long completed_transaction_get_transaction_id(struct TariCompletedTransaction *transaction);

struct TariPublicKey *completed_transaction_get_destination_public_key(struct TariCompletedTransaction *transaction);

unsigned long long completed_transaction_get_amount(struct TariCompletedTransaction *transaction);

unsigned long long completed_transaction_get_fee(struct TariCompletedTransaction *transaction);

unsigned long long completed_transaction_get_timestamp(struct TariCompletedTransaction *transaction);

/// -------------------------------- CompletedTransactions ------------------------------------------------------ ///

int completed_transactions_get_length(struct TariCompletedTransactions *transactions);

struct TariCompletedTransaction *completed_transactions_get_at(struct TariCompletedTransactions *transactions, int position);

void completed_transactions_destroy(struct TariCompletedTransactions *transactions);

/// -------------------------------- OutboundTransaction ------------------------------------------------------ ///

unsigned long long pending_outbound_transaction_get_transaction_id(struct TariPendingOutboundTransaction *transaction);

struct TariPublicKey *pending_outbound_transaction_get_destination_public_key(struct TariPendingOutboundTransaction *transaction);

unsigned long long pending_outbound_transaction_get_amount(struct TariPendingOutboundTransaction *transaction);

unsigned long long pending_outbound_transaction_get_timestamp(struct TariPendingOutboundTransaction *transaction);

/// -------------------------------- OutboundTransactions ------------------------------------------------------ ///

int pending_outbound_transactions_get_length(struct TariPendingOutboundTransactions *transactions);

struct TariPendingOutboundTransactions *pending_outbound_transactions_get_at(struct TariPendingOutboundTransactions *transactions, int position);

void pending_outbound_transactions_destroy(struct TariPendingOutboundTransactions *transactions);

/// -------------------------------- InboundTransaction ------------------------------------------------------ ///

unsigned long long pending_inbound_transaction_get_transaction_id(struct TariPendingInboundTransaction *transaction);

struct TariPublicKey *pending_inbound_transaction_get_source_public_key(struct TariPendingInboundTransaction *transaction);

unsigned long long pending_inbound_transaction_get_amount(struct TariPendingInboundTransaction *transaction);

unsigned long long pending_inbound_transaction_get_timestamp(struct TariPendingInboundTransaction *transaction);

/// -------------------------------- InboundTransactions ------------------------------------------------------ ///

int pending_inbound_transactions_get_length(struct TariPendingInboundTransactions *transactions);

struct TariPendingInboundTransactions *pending_inbound_transactions_get_at(struct TariPendingInboundTransactions *transactions, int position);

void pending_inbound_transactions_destroy(struct TariPendingInboundTransactions *transactions);

/// -------------------------------- TariCommsConfig ----------------------------------------------- ///

struct TariCommsConfig *comms_config_create(char *address,
                                     char *database_name,
                                     char *datastore_path,
                                            struct TariPrivateKey *secret_key);

void comms_config_destroy(struct TariCommsConfig *wc);

/// -------------------------------- TariWallet ----------------------------------------------- //

struct TariWallet *wallet_create(struct TariWalletConfig *config);

bool wallet_generate_test_data(struct TariWallet *wallet);

bool wallet_add_base_node_peer(struct TariWallet *wallet, struct TariPublicKey *public_key, char *address);

bool wallet_add_contact(struct TariWallet *wallet, struct TariContact *contact);

bool wallet_remove_contact(struct TariWallet *wallet, struct TariContact *contact);

unsigned long long wallet_get_balance(struct TariWallet *wallet);

bool wallet_send_transaction(struct TariWallet *wallet, struct TariPublicKey *destination, unsigned long long amount, unsigned long long fee_per_gram);

struct TariContacts *wallet_get_contacts(struct TariWallet *wallet);

struct TariCompletedTransactions *wallet_get_completed_transactions(struct TariWallet *wallet);

struct TariPendingOutboundTransactions *wallet_get_pending_outbound_transactions(struct TariWallet *wallet);

struct TariPendingInboundTransactions *wallet_get_pending_inbound_transactions(struct TariWallet *wallet);

struct TariCompletedTransaction *wallet_get_completed_transaction_by_id(struct TariWallet *wallet, unsigned long long transaction_id);

struct TariPendingOutboundTransaction *wallet_get_pending_outbound_transaction_by_id(struct TariWallet *wallet, unsigned long long transaction_id);

struct TariPendingInboundTransaction *wallet_get_pending_inbound_transaction_by_id(struct TariWallet *wallet, unsigned long long transaction_id);

void wallet_destroy(struct TariWallet *wallet);

///TODO expose callbacks

#endif /* wallet_ffi_h */
