//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./ClaimTypes.sol";

interface ICredentialRegistry is ClaimTypes {

    function registerCredential(bytes32 credentialHash, uint256 from, uint256 exp, bytes calldata signature) external returns (bool);

    function revokeCredential(bytes32 credentialHash) external returns (bool);

    function getCredential(bytes32 credentialHash) external view returns (CredentialMetadata memory);

    function status(bytes32 _credentialHash) external view returns (uint8);

    function exist(bytes32 credentialHash) external view returns (bool);

    event CredentialRegistered(bytes32 indexed credentialHash, uint iat);
    event CredentialRevoked(bytes32 indexed credentialHash, uint256 date);
}