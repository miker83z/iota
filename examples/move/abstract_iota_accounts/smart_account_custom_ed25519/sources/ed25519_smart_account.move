// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// This module shows how to use the framework `SmartAccount` with a custom authenticator.
///
/// The account owner's Ed25519 `PublicKey` is stored as a dynamic field of the account under
/// `Ed25519PublicKeyFieldName`, a field name defined by this module. Only this module can
/// construct that name, so other Move code can only reach the key through the functions below.
/// The built-in authenticators of the framework look for their key under a different field name,
/// so they do not see the key attached here.
///
/// `ed25519_authenticator` authenticates a transaction by verifying an Ed25519 signature over
/// the transaction digest against the attached public key.
module smart_account_custom_ed25519::ed25519_smart_account;

use iota::authenticator_function::AuthenticatorFunctionRefV1;
use iota::ed25519;
use iota::public_key::PublicKey;
use iota::signature_scheme;
use iota::smart_account::{Self, SmartAccount, SmartAccountBuilder};

// === Errors ===

#[error(code = 0)]
const ENotEd25519PublicKey: vector<u8> = b"Public key is not an Ed25519 key.";
#[error(code = 1)]
const EEd25519VerificationFailed: vector<u8> = b"Ed25519 authenticator verification failed.";

// === Constants ===

// === Structs ===

/// Dynamic field name under which the account owner's Ed25519 public key is stored.
public struct Ed25519PublicKeyFieldName has copy, drop, store {}

// === Account Helpers ===

/// Creates a new `SmartAccount` as a shared object and returns its address.
///
/// `public_key` is attached to the account, and `authenticator` is expected to reference
/// `ed25519_authenticator`.
///
/// Aborts if `public_key` is not an Ed25519 key.
public fun create(
    public_key: PublicKey,
    authenticator: AuthenticatorFunctionRefV1<SmartAccount>,
    ctx: &mut TxContext,
): address {
    with_public_key(smart_account::builder_v1(authenticator, ctx), public_key).build_v1()
}

/// Attaches `public_key` to the account being built.
///
/// Aborts if `public_key` is not an Ed25519 key.
public fun with_public_key(
    builder: SmartAccountBuilder,
    public_key: PublicKey,
): SmartAccountBuilder {
    assert_ed25519(&public_key);

    builder.with_field(Ed25519PublicKeyFieldName {}, public_key)
}

/// Replaces the account owner's public key with `public_key` and returns the previous key.
/// Once this function is called, signatures made with the previous key are no longer valid.
///
/// Aborts if the transaction sender is not the account.
/// Aborts if `public_key` is not an Ed25519 key.
public fun rotate_public_key(
    account: &mut SmartAccount,
    public_key: PublicKey,
    ctx: &mut TxContext,
): PublicKey {
    assert_ed25519(&public_key);

    account.rotate_field(Ed25519PublicKeyFieldName {}, public_key, ctx)
}

// === Authenticators ===

/// Ed25519 signature authenticator for `SmartAccount`.
///
/// `signature` is the 64-byte Ed25519 signature over the transaction digest, made with the
/// private key matching the public key attached to the account.
#[authenticator]
public fun ed25519_authenticator(
    account: &SmartAccount,
    signature: vector<u8>,
    _: &AuthContext,
    ctx: &TxContext,
) {
    assert!(
        ed25519::ed25519_verify(&signature, borrow_public_key(account).raw_bytes(), ctx.digest()),
        EEd25519VerificationFailed,
    );
}

// === View Functions ===

/// Returns `true` if the account has an owner public key attached.
#[view]
public fun has_public_key(account: &SmartAccount): bool {
    account.has_field(Ed25519PublicKeyFieldName {})
}

/// Borrows the account owner's public key.
///
/// Aborts if no public key is attached.
#[view]
public fun borrow_public_key(account: &SmartAccount): &PublicKey {
    account.borrow_field(Ed25519PublicKeyFieldName {})
}

// === Admin Functions ===

// === Package Functions ===

// === Private Functions ===

fun assert_ed25519(public_key: &PublicKey) {
    assert!(public_key.scheme() == signature_scheme::ed25519(), ENotEd25519PublicKey);
}

// === Test Functions ===
