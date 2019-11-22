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

use tari_comms::connection::net_address::NetAddressError;
use tari_utilities::{hex::HexError, ByteArrayError};
use tari_wallet::{
    error::WalletError,
    output_manager_service::error::{OutputManagerError, OutputManagerStorageError},
    transaction_service::error::{TransactionServiceError, TransactionStorageError},
};

/// This struct is meant to hold an error for use by FFI client applications. The error has an integer code and string
/// message
#[derive(Debug, Clone)]
pub struct LibWalletError {
    pub code: i32,
    pub message: String,
}

/// This implementation maps the internal WalletError to a set of LibWalletErrors. The mapping is explicitly manager
/// here and error code 999 is a catch-all code for any errors that are not explicitly mapped
impl From<WalletError> for LibWalletError {
    fn from(w: WalletError) -> Self {
        match w {
            // Output Manager Service Errors
            WalletError::OutputManagerError(OutputManagerError::NotEnoughFunds) => Self {
                code: 101,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::IncompleteTransaction) => Self {
                code: 102,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::DuplicateOutput) => Self {
                code: 103,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::OutputManagerStorageError(
                OutputManagerStorageError::ValuesNotFound,
            )) => Self {
                code: 104,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::OutputManagerStorageError(
                OutputManagerStorageError::OutputAlreadySpent,
            )) => Self {
                code: 105,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::OutputManagerStorageError(
                OutputManagerStorageError::PendingTransactionNotFound,
            )) => Self {
                code: 106,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::OutputManagerStorageError(
                OutputManagerStorageError::DuplicateOutput,
            )) => Self {
                code: 107,
                message: format!("{:?}", w),
            },
            WalletError::OutputManagerError(OutputManagerError::OutputManagerStorageError(
                OutputManagerStorageError::ValueNotFound(_),
            )) => Self {
                code: 108,
                message: format!("{:?}", w),
            },
            // Transaction Service Errors
            WalletError::TransactionServiceError(TransactionServiceError::InvalidStateError) => Self {
                code: 200,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::TransactionProtocolError(_)) => Self {
                code: 201,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::RepeatedMessageError) => Self {
                code: 202,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::TransactionDoesNotExistError) => Self {
                code: 203,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::OutputManagerError(
                OutputManagerError::NotEnoughFunds,
            )) => Self {
                code: 204,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::OutputManagerError(_)) => Self {
                code: 205,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::TransactionError(_)) => Self {
                code: 206,
                message: format!("{:?}", w),
            },
            WalletError::TransactionServiceError(TransactionServiceError::TransactionStorageError(
                TransactionStorageError::DuplicateOutput,
            )) => Self {
                code: 207,
                message: format!("{:?}", w),
            },

            WalletError::TransactionServiceError(TransactionServiceError::TransactionStorageError(
                TransactionStorageError::ValueNotFound(_),
            )) => Self {
                code: 208,
                message: format!("{:?}", w),
            },
            // Comms Stack errors
            WalletError::NetAddressError(NetAddressError::ParseFailed) => Self {
                code: 300,
                message: format!("{:?}", w),
            },

            // This is the catch all error code. Any error that is not explicitly mapped above will be given this code
            _ => Self {
                code: 999,
                message: format!("{:?}", w).to_string(),
            },
        }
    }
}

/// This implementation maps the internal HexError to a set of LibWalletErrors. The mapping is explicitly manager
/// here and error code 999 is a catch-all code for any errors that are not explicitly mapped
impl From<HexError> for LibWalletError {
    fn from(h: HexError) -> Self {
        match h {
            HexError::LengthError => Self {
                code: 400,
                message: format!("{:?}", h).to_string(),
            },
            HexError::HexConversionError => Self {
                code: 401,
                message: format!("{:?}", h).to_string(),
            },
            HexError::InvalidCharacter(_) => Self {
                code: 402,
                message: format!("{:?}", h).to_string(),
            },

            // This is the catch all error code. Any error that is not explicitly mapped above will be given this code
            _ => Self {
                code: 999,
                message: format!("{:?}", h).to_string(),
            },
        }
    }
}

/// This implementation maps the internal ByteArrayError to a set of LibWalletErrors. The mapping is explicitly manager
/// here and error code 999 is a catch-all code for any errors that are not explicitly mapped
impl From<ByteArrayError> for LibWalletError {
    fn from(b: ByteArrayError) -> Self {
        match b {
            ByteArrayError::IncorrectLength => Self {
                code: 403,
                message: format!("{:?}", b).to_string(),
            },
            ByteArrayError::ConversionError(_) => Self {
                code: 404,
                message: format!("{:?}", b).to_string(),
            },
            // This is the catch all error code. Any error that is not explicitly mapped above will be given this code
            _ => Self {
                code: 999,
                message: format!("{:?}", b).to_string(),
            },
        }
    }
}
