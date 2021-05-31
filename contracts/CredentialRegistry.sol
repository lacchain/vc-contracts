//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./ICredentialRegistry.sol";

contract CredentialRegistry is ICredentialRegistry, AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    mapping(bytes32 => mapping(address => CredentialMetadata)) public credentials;

    constructor() public {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function register(address issuer, address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes calldata signature) external override onlyIssuer returns (bool) {
        CredentialMetadata storage credential = credentials[_credentialHash][issuer];
        require(credential.subject == address(0), "Credential already exists");
        credential.issuer = issuer;
        credential.subject = _subject;
        credential.validFrom = _from;
        credential.validTo = _exp;
        credential.status = true;
        credentials[_credentialHash][issuer] = credential;
        emit CredentialRegistered(_credentialHash, issuer, _subject, credential.validFrom);
        return true;
    }

    function registerSignature(bytes32 _credentialHash, address issuer, bytes calldata signature) external returns (bool){
        return _registerSignature(_credentialHash, issuer, signature);
    }

    function revoke(bytes32 _credentialHash) external override returns (bool) {
        CredentialMetadata storage credential = credentials[_credentialHash][msg.sender];

        require(credential.subject != address(0), "credential hash doesn't exist");
        require(credential.status, "Credential is already revoked");

        credential.status = false;
        credentials[_credentialHash][msg.sender] = credential;
        emit CredentialRevoked(_credentialHash, msg.sender, block.timestamp);
        return true;
    }

    function exist(bytes32 _credentialHash, address issuer) override external view returns (bool exist){
        CredentialMetadata memory credential = credentials[_credentialHash][issuer];
        return (credential.subject != address(0));
    }

    function revoked(address issuer, bytes32 _credentialHash) external view returns (bool isValid){
        CredentialMetadata memory credential = credentials[_credentialHash][issuer];
        return !credential.status;
    }

    function verifyIssuer(address issuer, address signer) external pure returns (bool isValid){
        return (issuer == signer);
    }

    function _registerSignature(bytes32 _credentialHash, address issuer, bytes calldata _signature) private onlyIssuer returns (bool){
        CredentialMetadata storage credential = credentials[_credentialHash][issuer];
        require(credential.subject != address(0), "Credential doesn't exists");
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
            emit SignatureRegistered(credential.issuer, signExist, _newSignature);
            return true;
        }
    }

    function getSigners(bytes32 _credentialHash, address _issuer) external view returns (uint8 signers){
        CredentialMetadata memory credential = credentials[_credentialHash][_issuer];
        if (credential.subject != address(0)) {
            return uint8(credential.signatures.length);
        }
        return 0;
    }

    function isSigner(bytes32 _credentialHash, address _issuer, bytes memory _signature) external view returns (bool){
        CredentialMetadata memory credential = credentials[_credentialHash][_issuer];
        require(credential.subject != address(0), "Credential doesn't exists");
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

    function getIssuer(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external pure returns (address issuer){
        return ecrecover(digest, v, r, s);
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, msg.sender), "Caller is not a issuer 2");
        _;
    }

    event SignatureRegistered(address issuer, bool exits, Signature signature);
}