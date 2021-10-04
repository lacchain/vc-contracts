//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./ICredentialRegistry.sol";

contract CredentialRegistry is ICredentialRegistry, AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(bytes32 => CredentialMetadata) public credentials;

    constructor() public {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function registerCredential(bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes calldata signature) external override onlyIssuer returns (bool) {
        CredentialMetadata storage credential = credentials[_credentialHash];
        require(credential.status > 0, "Credential already exists");
        credential.issuerSignature = signature;
        credential.validFrom = _from;
        credential.validTo = _exp;
        credential.status = 1;
        credentials[_credentialHash] = credential;
        emit CredentialRegistered(_credentialHash, credential.validFrom);
        return true;
    }

    function registerSignature(bytes32 _credentialHash, bytes calldata signature) external returns (bool){
        return _registerSignature(_credentialHash, signature);
    }

    function revokeCredential(bytes32 _credentialHash) external override returns (bool) {
        CredentialMetadata storage credential = credentials[_credentialHash];

        require(credential.status != 0, "credential hash doesn't exist");
        require(credential.status != 2, "Credential is already revoked");

        credential.status = 2;
        credentials[_credentialHash] = credential;
        emit CredentialRevoked(_credentialHash, block.timestamp);
        return true;
    }

    function getCredential(bytes32 credentialHash) external view override returns (CredentialMetadata memory){
        return credentials[credentialHash];
    }

    function exist(bytes32 _credentialHash) override external view returns (bool exist){
        CredentialMetadata memory credential = credentials[_credentialHash];
        return credential.status > 0;
    }

    function status(bytes32 _credentialHash) override external view returns (uint8){
        CredentialMetadata memory credential = credentials[_credentialHash];
        return credential.status;
    }

    function _registerSignature(bytes32 _credentialHash, bytes calldata _signature) private onlyIssuer returns (bool){
        CredentialMetadata storage credential = credentials[_credentialHash];
        require(credential.status > 0, "Credential doesn't exists");
        bytes memory signature = _signature;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        Signature memory _newSignature = Signature(r, s, v);
        bool signExist = false;
        uint8 i = 0;
        while (i < credential.signatures.length && !signExist) {
            if (credential.signatures[i].r == _newSignature.r && credential.signatures[i].s == _newSignature.s) {
                signExist = true;
            }
            i++;
        }

        if (signExist) {
            return false;
        } else {
            credential.signatures.push(_newSignature);
            emit SignatureRegistered(signExist, _newSignature);
            return true;
        }
    }

    function getSigners(bytes32 _credentialHash) external view returns (uint8 signers){
        CredentialMetadata memory credential = credentials[_credentialHash];
        if (credential.status > 0) {
            return uint8(credential.signatures.length);
        }
        return 0;
    }

    function isSigner(bytes32 _credentialHash, bytes memory _signature) external view returns (bool){
        CredentialMetadata memory credential = credentials[_credentialHash];
        require(credential.status > 0, "Credential doesn't exists");
        //bytes memory signature = _signature;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        Signature memory _newSignature = Signature(r, s, v);
        bool signExist = false;
        uint8 i = 0;
        while (i < credential.signatures.length && !signExist) {
            if (credential.signatures[i].r == _newSignature.r && credential.signatures[i].s == _newSignature.s) {
                signExist = true;
            }
            i++;
        }

        return signExist;
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer");
        _;
    }

    event SignatureRegistered(bool exits, Signature signature);
}