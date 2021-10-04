//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./lib/ECDSA.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./AbstractClaimsVerifier.sol";

contract ClaimsVerifier is AbstractClaimsVerifier, AccessControl {

    using ECDSA for bytes32;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    constructor (address _registryAddress)
    AbstractClaimsVerifier(
        "EIP712Domain",
        "1",
        648529,
        address(this),
        _registryAddress
    ) public {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function verifyCredential(bytes32 credentialHash, uint8 v, bytes32 r, bytes32 s) public view returns (bool, bool, bool, bool, bool) {
        CredentialMetadata memory vc = _getCredential( credentialHash );
        address issuer = ecrecover(credentialHash, v, r, s);
        return (_exist(credentialHash), _verifyRevoked(credentialHash), hasRole(ISSUER_ROLE, issuer), (_verifySigners(credentialHash) == getRoleMemberCount(keccak256("SIGNER_ROLE"))), _validPeriod(vc.validFrom, vc.validTo));
    }

    function verifySigner(bytes32 digest, bytes calldata _signature) public view returns (bool){
        address signer = digest.recover(_signature);
        return hasRole(SIGNER_ROLE, signer) && _isSigner(digest, _signature);
    }

    function registerCredential(bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes calldata _signature) public onlyIssuer returns (bool) {
        address signer = _credentialHash.recover(_signature);
        require(msg.sender == signer, "Sender hasn't signed the credential");
        return _registerCredential(_credentialHash, _from, _exp, _signature);
    }

    function registerSignature(bytes32 _credentialHash, bytes calldata _signature) public onlySigner returns (bool){
        address signer = _credentialHash.recover(_signature);
        require(msg.sender == signer, "Sender hasn't signed the credential");
        return _registerSignature(_credentialHash, _signature);
    }

    modifier onlyAdmin(){
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not Admin");
        _;
    }

    modifier onlySigner() {
        require(hasRole(SIGNER_ROLE, msg.sender), "Caller is not a signer");
        _;
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 1");
        _;
    }

}