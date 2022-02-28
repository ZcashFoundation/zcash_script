#![doc(html_logo_url = "https://www.zfnd.org/images/zebra-icon.png")]
#![doc(html_root_url = "https://docs.rs/zcash_script/0.1.5")]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

static mut ORCHARD_VK: Option<orchard::circuit::VerifyingKey> = None;

mod blake2b;
mod orchard_ffi;
mod streams_ffi;
mod transaction_ffi;

#[cfg(test)]
mod tests {
    pub use super::zcash_script_error_t;
    use hex::FromHex;

    lazy_static::lazy_static! {
        pub static ref SCRIPT_PUBKEY: Vec<u8> = <Vec<u8>>::from_hex("76a914f47cac1e6fec195c055994e8064ffccce0044dd788ac").unwrap();
        pub static ref SCRIPT_TX: Vec<u8> = <Vec<u8>>::from_hex("0400008085202f8901fcaf44919d4a17f6181a02a7ebe0420be6f7dad1ef86755b81d5a9567456653c010000006a473044022035224ed7276e61affd53315eca059c92876bc2df61d84277cafd7af61d4dbf4002203ed72ea497a9f6b38eb29df08e830d99e32377edb8a574b8a289024f0241d7c40121031f54b095eae066d96b2557c1f99e40e967978a5fd117465dbec0986ca74201a6feffffff020050d6dc0100000017a9141b8a9bda4b62cd0d0582b55455d0778c86f8628f870d03c812030000001976a914e4ff5512ffafe9287992a1cd177ca6e408e0300388ac62070d0095070d000000000000000000000000").expect("Block bytes are in valid hex representation");
        // Created by changing the byte before the hash inside the lock script, in each output, to 0xff
        pub static ref SCRIPT_TX_INVALID: Vec<u8> = <Vec<u8>>::from_hex("0400008085202f8901fcaf44919d4a17f6181a02a7ebe0420be6f7dad1ef86755b81d5a9567456653c010000006a473044022035224ed7276e61affd53315eca059c92876bc2df61d84277cafd7af61d4dbf4002203ed72ea497a9f6b38eb29df08e830d99e32377edb8a574b8a289024f0241d7c40121031f54b095eae066d96b2557c1f99e40e967978a5fd117465dbec0986ca74201a6feffffff020050d6dc0100000017a9ff1b8a9bda4b62cd0d0582b55455d0778c86f8628f870d03c812030000001976a9ffe4ff5512ffafe9287992a1cd177ca6e408e0300388ac62070d0095070d000000000000000000000000").expect("Block bytes are in valid hex representation");
    }

    pub fn verify_script(
        script_pub_key: &[u8],
        amount: i64,
        tx_to: &[u8],
        nIn: u32,
        flags: u32,
        consensus_branch_id: u32,
    ) -> Result<(), zcash_script_error_t> {
        let script_ptr = script_pub_key.as_ptr();
        let script_len = script_pub_key.len();
        let tx_to_ptr = tx_to.as_ptr();
        let tx_to_len = tx_to.len();
        let mut err = 0;

        let ret = unsafe {
            super::zcash_script_verify(
                script_ptr,
                script_len as u32,
                amount,
                tx_to_ptr,
                tx_to_len as u32,
                nIn,
                flags,
                consensus_branch_id,
                &mut err,
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn verify_script_precompute(
        script_pub_key: &[u8],
        amount: i64,
        tx_to: &[u8],
        nIn: u32,
        flags: u32,
        consensus_branch_id: u32,
    ) -> Result<(), zcash_script_error_t> {
        let script_ptr = script_pub_key.as_ptr();
        let script_len = script_pub_key.len();
        let tx_to_ptr = tx_to.as_ptr();
        let tx_to_len = tx_to.len();
        let mut err = 0;

        let precomputed =
            unsafe { super::zcash_script_new_precomputed_tx(tx_to_ptr, tx_to_len as _, &mut err) };

        let ret = unsafe {
            super::zcash_script_verify_precomputed(
                precomputed,
                nIn,
                script_ptr,
                script_len as u32,
                amount,
                flags,
                consensus_branch_id,
                &mut err,
            )
        };

        unsafe { super::zcash_script_free_precomputed_tx(precomputed) };

        if ret == 1 {
            Ok(())
        } else {
            Err(err)
        }
    }

    #[test]
    fn verify_script_works() {
        let coin = i64::pow(10, 8);
        let script_pub_key = &*SCRIPT_PUBKEY;
        let amount = 212 * coin;
        let tx_to = &*SCRIPT_TX;
        let nIn = 0;
        let flags = 1;
        let branch_id = 0x2bb40e60;

        verify_script(script_pub_key, amount, tx_to, nIn, flags, branch_id).unwrap();
    }

    #[test]
    fn verify_script_works_precomputed() {
        let coin = i64::pow(10, 8);
        let script_pub_key = &*SCRIPT_PUBKEY;
        let amount = 212 * coin;
        let tx_to = &*SCRIPT_TX;
        let nIn = 0;
        let flags = 1;
        let branch_id = 0x2bb40e60;

        verify_script_precompute(script_pub_key, amount, tx_to, nIn, flags, branch_id).unwrap();
    }

    #[test]
    fn verify_script_doesnt_work() {
        let coin = i64::pow(10, 8);
        let script_pub_key = &*SCRIPT_PUBKEY;
        let amount = 212 * coin;
        let tx_to = &*SCRIPT_TX;
        let nIn = 0;
        let flags = 1;
        let branch_id = 0x2bb40e61;

        verify_script(script_pub_key, amount, tx_to, nIn, flags, branch_id).unwrap_err();
    }

    #[test]
    fn verify_script_doesnt_work_precomputed() {
        let coin = i64::pow(10, 8);
        let script_pub_key = &*SCRIPT_PUBKEY;
        let amount = 212 * coin;
        let tx_to = &*SCRIPT_TX;
        let nIn = 0;
        let flags = 1;
        let branch_id = 0x2bb40e61;

        verify_script_precompute(script_pub_key, amount, tx_to, nIn, flags, branch_id).unwrap_err();
    }

    pub fn transparent_output_address(
        tx_to: &[u8],
        nOut: u32,
    ) -> Result<(super::zcash_script_uint160_t, super::zcash_script_type_t), zcash_script_error_t>
    {
        let tx_to_ptr = tx_to.as_ptr();
        let tx_to_len = tx_to.len();
        let mut addrType = 0;
        let mut err = 0;

        let address = unsafe {
            super::zcash_script_transparent_output_address(
                tx_to_ptr,
                tx_to_len as u32,
                nOut,
                &mut addrType,
                &mut err,
            )
        };

        if err == 0 {
            Ok((address, addrType))
        } else {
            Err(err)
        }
    }

    pub fn transparent_output_address_precomputed(
        tx_to: &[u8],
        nOut: u32,
    ) -> Result<(super::zcash_script_uint160_t, super::zcash_script_type_t), zcash_script_error_t>
    {
        let tx_to_ptr = tx_to.as_ptr();
        let tx_to_len = tx_to.len();
        let mut addrType = 0;
        let mut err = 0;

        let precomputed =
            unsafe { super::zcash_script_new_precomputed_tx(tx_to_ptr, tx_to_len as _, &mut err) };

        let address = unsafe {
            super::zcash_script_transparent_output_address_precomputed(
                precomputed,
                nOut,
                &mut addrType,
                &mut err,
            )
        };

        if err == 0 {
            Ok((address, addrType))
        } else {
            Err(err)
        }
    }

    #[test]
    fn transparent_output_address_works() {
        let tx_to = &*SCRIPT_TX;

        // Expected values manually extracted from the transaction
        // (parsed with zebra-chain, then manually extracted from lock_script)

        let (address, addrType) = transparent_output_address(tx_to, 0).unwrap();
        let expected_address = hex::decode("1b8a9bda4b62cd0d0582b55455d0778c86f8628f").unwrap();

        assert_eq!(Vec::<u8>::from(address.value), expected_address);
        assert_eq!(addrType, super::zcash_script_type_t_zcash_script_TYPE_P2SH);

        let (address, addrType) = transparent_output_address(tx_to, 1).unwrap();
        let expected_address = hex::decode("e4ff5512ffafe9287992a1cd177ca6e408e03003").unwrap();

        assert_eq!(Vec::<u8>::from(address.value), expected_address);
        assert_eq!(addrType, super::zcash_script_type_t_zcash_script_TYPE_P2PKH);
    }

    #[test]
    fn transparent_output_address_works_precomputed() {
        let tx_to = &*SCRIPT_TX;

        // Expected values manually extracted from the transaction
        // (parsed with zebra-chain, then manually extracted from lock_script)

        let (address, addrType) = transparent_output_address_precomputed(tx_to, 0).unwrap();
        let expected_address = hex::decode("1b8a9bda4b62cd0d0582b55455d0778c86f8628f").unwrap();

        assert_eq!(Vec::<u8>::from(address.value), expected_address);
        assert_eq!(addrType, super::zcash_script_type_t_zcash_script_TYPE_P2SH);

        let (address, addrType) = transparent_output_address_precomputed(tx_to, 1).unwrap();
        let expected_address = hex::decode("e4ff5512ffafe9287992a1cd177ca6e408e03003").unwrap();

        assert_eq!(Vec::<u8>::from(address.value), expected_address);
        assert_eq!(addrType, super::zcash_script_type_t_zcash_script_TYPE_P2PKH);
    }

    #[test]
    fn transparent_output_address_doesnt_work() {
        let tx_to = &*SCRIPT_TX;

        let ret = transparent_output_address(tx_to, 2).unwrap_err();
        assert_eq!(ret, super::zcash_script_error_t_zcash_script_ERR_TX_INDEX);

        let tx_to = &*SCRIPT_TX_INVALID;

        let ret = transparent_output_address(tx_to, 0).unwrap_err();
        assert_eq!(
            ret,
            super::zcash_script_error_t_zcash_script_ERR_TX_INVALID_SCRIPT
        );

        let ret = transparent_output_address(tx_to, 1).unwrap_err();
        assert_eq!(
            ret,
            super::zcash_script_error_t_zcash_script_ERR_TX_INVALID_SCRIPT
        );
    }

    #[test]
    fn transparent_output_address_precomputed_doesnt_work() {
        let tx_to = &*SCRIPT_TX;

        let ret = transparent_output_address_precomputed(tx_to, 2).unwrap_err();
        assert_eq!(ret, super::zcash_script_error_t_zcash_script_ERR_TX_INDEX);

        let tx_to = &*SCRIPT_TX_INVALID;

        let ret = transparent_output_address_precomputed(tx_to, 0).unwrap_err();
        assert_eq!(
            ret,
            super::zcash_script_error_t_zcash_script_ERR_TX_INVALID_SCRIPT
        );

        let ret = transparent_output_address_precomputed(tx_to, 1).unwrap_err();
        assert_eq!(
            ret,
            super::zcash_script_error_t_zcash_script_ERR_TX_INVALID_SCRIPT
        );
    }
}
