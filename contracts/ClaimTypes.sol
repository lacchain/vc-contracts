//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

contract ClaimTypes {

    struct VerifiableCredential {
        address issuer;
        bytes32 data;
        uint256 validFrom;
        uint256 validTo;
    }

    bytes32 constant internal VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256(
        "VerifiableCredential(address issuer,bytes32 data,uint256 validFrom,uint256 validTo)"
    );

}