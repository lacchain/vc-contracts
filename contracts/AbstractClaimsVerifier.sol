//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.6.0 <0.7.0;

import "./CredentialRegistry.sol";
import "./ClaimTypes.sol";

contract AbstractClaimsVerifier is ClaimTypes {

    CredentialRegistry registry;

    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    bytes32 constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 DOMAIN_SEPARATOR;

    constructor (
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract,
        address _registryAddress) public {
        DOMAIN_SEPARATOR = hashEIP712Domain(
            EIP712Domain({
        name : name,
        version : version,
        chainId : chainId,
        verifyingContract : verifyingContract
        }));
        registry = CredentialRegistry(_registryAddress);
    }

    function hashEIP712Domain(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip712Domain.name)),
                keccak256(bytes(eip712Domain.version)),
                eip712Domain.chainId,
                eip712Domain.verifyingContract
            ));
    }

    function _registerCredential(bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes calldata signature) internal returns (bool){
        return registry.registerCredential(_credentialHash, _from, _exp, signature);
    }

    function _registerSignature(bytes32 _credentialHash, bytes calldata signature) internal returns (bool){
        return registry.registerSignature(_credentialHash, signature);
    }

    function _validPeriod(uint256 validFrom, uint256 validTo) internal view returns (bool) {
        return (validFrom <= block.timestamp) && (block.timestamp < validTo);
    }

    function _verifySigners(bytes32 _digest) internal view returns (uint8){
        return registry.getSigners(_digest);
    }

    function _isSigner(bytes32 _digest, bytes memory _signature) internal view returns (bool){
        return registry.isSigner(_digest, _signature);
    }

    function _exist(bytes32 digest) internal view returns (bool){
        return registry.exist(digest);
    }

    function _verifyRevoked(bytes32 digest) internal view returns (bool){
        return registry.status(digest) == 2;
    }

    function _getCredential(bytes32 credentialHash) internal view returns (CredentialMetadata memory){
        return registry.getCredential(credentialHash);
    }

}
