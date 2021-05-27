In this repository are the smart contracts based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712) and [EIP-1812](https://eips.ethereum.org/EIPS/eip-1812) to perform the verification process of "Verifiable Credentials" on-chain.

## Structure

The main objective is to have a global credential repository that works in a generic way for any type of Verifiable Credential. 
That is why within the contracts there is the **CredentialRegistry** whose function is to maintain the main registry. However, it is not intended to interact directly with applications. 
That is why there is a contract that serves as a Facade to be able to register each type of credential, this contract is called **ClaimsVerifier**, and it is in charge of both registering the credential hashes and verifying them by making internal calls to the **CredentialRegistry**.

- **CredentialRegistry**: Master credential record
- **AbstractClaimsVerifier**: Abstract class that represents a credential verifier
- **ClaimsVerifier**: Class that allows verifying a specific type of credential (inherits from **AbstractClaimVerifier**). Receive the **CredentialRegistry** address as a constructor argument
- **ClaimTypes**: Generic class that defines EIP712 domain types for credentials
- **ICredentialRegistry**: Interface that defines the main methods of a **CredentialRegistry**, as well as the metadata of each credential
- **Migrations**: Truffle deployment control class

### Security roles

The contracts make use of the [OpenZeppelin Access Control System](https://docs.openzeppelin.com/contracts/2.x/access-control), for which 2 roles have been defined:

- **ISSUER_ROLE**: 0x114e74f6ea3íritu19998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122 
- **SIGNER_ROLE**: 0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70

The **ISSUER_ROLE** should be assigned to any account that is going to register a credential in the **ClaimsVerifier** contract.

The **SIGNER_ROLE** should be assigned to any account that is going to sign a credential within the **ClaimsVerifier** contract. Note: The issuer does not count as a signer, since by default the signer will send its signature when registering the credential.

There is an additional use of the **ISSUER_ROLE**, and that in order to interact with the **CredentialRegistry**, the **ClaimsVerifier** contract address must be registered as an issuer in the **CredentialRegistry**. The latter makes more sense when considering that there will be different types of credentials and therefore Claims Verifiers.

### Pre-requisites

- NodeJS  > 12.4
- OpenZeppelin CLI > 2.8.2
- OpenZeppelin Contracts @ 3.0.0

## Deploy contracts

1. Initialize OpenZeppelin project
```
$ oz init
```

2. Deploy **CredentialRegistry**
```
$ oz deploy
```

3. Deploy **ClaimsVerifier** using the **CredentialRegistry** address as init argument
```
$ oz deploy
```

4. Assign **ClaimsVerifier** address as **ISSUER_ROLE** to the **CredentialRegistry** using the ```grantRole``` function
```
$ oz send-tx
```

5. Assign the **ISSUER_ROLE** and **SIGNER_ROLE** to the corresponding address accounts in the **ClaimsVerifier** contract using the grantRole function
```
$ oz send-tx
```

## Setup

### Install dependencies
```
$ npm i
```

### Run Truffle Test
```
$ truffle test
```