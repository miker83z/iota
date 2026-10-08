// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module smart_account_custom_ed25519::ed25519_smart_account_tests;

use iota::authenticator_function::{Self, AuthenticatorFunctionRefV1};
use iota::public_key::{Self, PublicKey};
use iota::signature_scheme;
use iota::smart_account::{Self, SmartAccount};
use iota::test_scenario::{Self, Scenario};
use iota::test_utils::{assert_eq, assert_ref_eq};
use smart_account_custom_ed25519::ed25519_smart_account;
use std::ascii;

// Ed25519 key pair and a signature made with it over `TX_DIGEST`.
const PUBLIC_KEY: vector<u8> = x"cc62332e34bb2d5cd69f60efbb2a36cb916c7eb458301ea36636c4dbb012bd88";
const TX_DIGEST: vector<u8> = x"315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
const SIGNATURE: vector<u8> =
    x"cce72947906dbae4c166fc01fd096432784032be43db540909bc901dbc057992b4d655ca4f4355cf0868e1266baacf6919902969f063e74162f8f04bc4056105";

// A second, unrelated Ed25519 public key.
const OTHER_PUBLIC_KEY: vector<u8> =
    x"20f76913ad844a620434f553f009cfda151fe9aba1a6de707c5efa5bc205552b";

// A valid Secp256k1 public key.
const SECP256K1_PUBLIC_KEY: vector<u8> =
    x"02337cca2171fdbfcfd657fa59881f46269f1e590b5ffab6023686c7ad2ecc2c1c";

// --------------------------------------- Account Creation ---------------------------------------

#[test]
fun create_attaches_public_key_and_authenticator() {
    let mut scenario = test_scenario::begin(@0x0);
    create_account_for_testing(&mut scenario, ed25519_public_key(PUBLIC_KEY));

    scenario.next_tx(@0x0);
    {
        let account = scenario.take_shared<SmartAccount>();

        assert_ref_eq(account.borrow_auth_function_ref_v1(), &authenticator_for_testing());
        assert_eq(ed25519_smart_account::has_public_key(&account), true);
        assert_ref_eq(
            ed25519_smart_account::borrow_public_key(&account),
            &ed25519_public_key(PUBLIC_KEY),
        );
        // The key is attached under this package's field name, not the built-in one.
        assert_eq(account.has_builtin_auth_public_key(), false);

        test_scenario::return_shared(account);
    };

    scenario.end();
}

#[test]
#[expected_failure(abort_code = ed25519_smart_account::ENotEd25519PublicKey)]
fun create_aborts_for_non_ed25519_public_key() {
    let mut scenario = test_scenario::begin(@0x0);
    let public_key = public_key::create(signature_scheme::secp256k1(), SECP256K1_PUBLIC_KEY);

    create_account_for_testing(&mut scenario, public_key);

    scenario.end();
}

// --------------------------------------- Ed25519 Authentication ---------------------------------------

#[test]
fun ed25519_authenticator_accepts_valid_signature() {
    let mut scenario = test_scenario::begin(@0x0);
    let account_address = create_account_for_testing(
        &mut scenario,
        ed25519_public_key(PUBLIC_KEY),
    );

    scenario.next_tx(account_address);
    {
        let account = scenario.take_shared<SmartAccount>();

        authenticate_for_testing(&account, account_address, SIGNATURE);

        test_scenario::return_shared(account);
    };

    scenario.end();
}

#[test]
#[expected_failure(abort_code = ed25519_smart_account::EEd25519VerificationFailed)]
fun ed25519_authenticator_rejects_wrong_signature() {
    let mut scenario = test_scenario::begin(@0x0);
    let account_address = create_account_for_testing(
        &mut scenario,
        ed25519_public_key(PUBLIC_KEY),
    );

    scenario.next_tx(account_address);
    {
        let account = scenario.take_shared<SmartAccount>();

        let mut signature = SIGNATURE;
        *&mut signature[63] = 0xaa;
        authenticate_for_testing(&account, account_address, signature);

        test_scenario::return_shared(account);
    };

    scenario.end();
}

// --------------------------------------- Public Key Rotation ---------------------------------------

#[test]
fun rotate_public_key_replaces_key() {
    let mut scenario = test_scenario::begin(@0x0);
    let account_address = create_account_for_testing(
        &mut scenario,
        ed25519_public_key(PUBLIC_KEY),
    );

    scenario.next_tx(account_address);
    {
        let mut account = scenario.take_shared<SmartAccount>();

        let previous_public_key = ed25519_smart_account::rotate_public_key(
            &mut account,
            ed25519_public_key(OTHER_PUBLIC_KEY),
            scenario.ctx(),
        );

        assert_eq(previous_public_key, ed25519_public_key(PUBLIC_KEY));
        assert_ref_eq(
            ed25519_smart_account::borrow_public_key(&account),
            &ed25519_public_key(OTHER_PUBLIC_KEY),
        );

        test_scenario::return_shared(account);
    };

    scenario.end();
}

#[test]
#[expected_failure(abort_code = ed25519_smart_account::EEd25519VerificationFailed)]
fun ed25519_authenticator_rejects_signature_from_rotated_out_key() {
    let mut scenario = test_scenario::begin(@0x0);
    let account_address = create_account_for_testing(
        &mut scenario,
        ed25519_public_key(PUBLIC_KEY),
    );

    scenario.next_tx(account_address);
    {
        let mut account = scenario.take_shared<SmartAccount>();

        ed25519_smart_account::rotate_public_key(
            &mut account,
            ed25519_public_key(OTHER_PUBLIC_KEY),
            scenario.ctx(),
        );
        authenticate_for_testing(&account, account_address, SIGNATURE);

        test_scenario::return_shared(account);
    };

    scenario.end();
}

#[test]
#[expected_failure(abort_code = smart_account::ETransactionSenderIsNotTheSmartAccount)]
fun rotate_public_key_aborts_if_sender_is_not_the_account() {
    let mut scenario = test_scenario::begin(@0x0);
    create_account_for_testing(&mut scenario, ed25519_public_key(PUBLIC_KEY));

    scenario.next_tx(@0x0);
    {
        let mut account = scenario.take_shared<SmartAccount>();

        ed25519_smart_account::rotate_public_key(
            &mut account,
            ed25519_public_key(OTHER_PUBLIC_KEY),
            scenario.ctx(),
        );

        test_scenario::return_shared(account);
    };

    scenario.end();
}

#[test]
#[expected_failure(abort_code = ed25519_smart_account::ENotEd25519PublicKey)]
fun rotate_public_key_aborts_for_non_ed25519_public_key() {
    let mut scenario = test_scenario::begin(@0x0);
    let account_address = create_account_for_testing(
        &mut scenario,
        ed25519_public_key(PUBLIC_KEY),
    );

    scenario.next_tx(account_address);
    {
        let mut account = scenario.take_shared<SmartAccount>();

        ed25519_smart_account::rotate_public_key(
            &mut account,
            public_key::create(signature_scheme::secp256k1(), SECP256K1_PUBLIC_KEY),
            scenario.ctx(),
        );

        test_scenario::return_shared(account);
    };

    scenario.end();
}

// --------------------------------------- Test Utilities ---------------------------------------

fun create_account_for_testing(scenario: &mut Scenario, public_key: PublicKey): address {
    ed25519_smart_account::create(public_key, authenticator_for_testing(), scenario.ctx())
}

fun authenticate_for_testing(account: &SmartAccount, sender: address, signature: vector<u8>) {
    let ctx = tx_context::new(sender, TX_DIGEST, 0, 0, 0);
    let auth_ctx = auth_context::new_for_testing(
        b"00000000000000000000000000000000",
        vector[],
        vector[],
        vector[],
        b"00000000000000000000000000000000",
        option::none(),
        option::none(),
        option::none(),
    );

    ed25519_smart_account::ed25519_authenticator(account, signature, &auth_ctx, &ctx);
}

fun ed25519_public_key(raw_bytes: vector<u8>): PublicKey {
    public_key::create(signature_scheme::ed25519(), raw_bytes)
}

fun authenticator_for_testing(): AuthenticatorFunctionRefV1<SmartAccount> {
    // The values don't matter: the tests call `ed25519_authenticator` directly.
    authenticator_function::create_auth_function_ref_v1_for_testing(
        @0x1,
        ascii::string(b"ed25519_smart_account"),
        ascii::string(b"ed25519_authenticator"),
    )
}
