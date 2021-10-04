//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

interface ClaimTypes {

    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct CredentialMetadata {
        bytes issuerSignature;
        uint256 validFrom;
        uint256 validTo;
        Signature[] signatures;
        uint8 status; // 0 unregistered, 1 registered, 2 revoked
    }

}