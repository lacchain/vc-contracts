const crypto = require( 'crypto' );
const moment = require( "moment" );
const web3Abi = require( "web3-eth-abi" );
const web3Utils = require( "web3-utils" );
const ethUtil = require( "ethereumjs-util" );
const { expect } = require("chai");
const { ethers, lacchain } = require("hardhat");

const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3( "VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)" );
const EIP712DOMAIN_TYPEHASH = web3Utils.soliditySha3( "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" );

const sleep = seconds => new Promise( resolve => setTimeout( resolve, seconds * 1e3 ) );

function sha256( data ) {
	const hashFn = crypto.createHash( 'sha256' );
	hashFn.update( data );
	return hashFn.digest( 'hex' );
}

function getCredentialHash( vc, issuer, claimsVerifierContractAddress ) {
	const hashDiplomaHex = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;

	const encodeEIP712Domain = web3Abi.encodeParameters(
		['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
		[EIP712DOMAIN_TYPEHASH, web3Utils.sha3( "EIP712Domain" ), web3Utils.sha3( "1" ), 648529, claimsVerifierContractAddress]
	);
	const hashEIP712Domain = web3Utils.soliditySha3( encodeEIP712Domain );

	const validFrom = new Date( vc.issuanceDate ).getTime();
	const validTo = new Date( vc.expirationDate ).getTime();
	const subjectAddress = vc.credentialSubject.id.split( ':' ).slice( -1 )[0];
	const encodeHashCredential = web3Abi.encodeParameters(
		['bytes32', 'address', 'address', 'bytes32', 'uint256', 'uint256'],
		[VERIFIABLE_CREDENTIAL_TYPEHASH, issuer.address, subjectAddress, hashDiplomaHex, Math.round( validFrom / 1000 ), Math.round( validTo / 1000 )]
	);
	const hashCredential = web3Utils.soliditySha3( encodeHashCredential );

	const encodedCredentialHash = web3Abi.encodeParameters( ['bytes32', 'bytes32'], [hashEIP712Domain, hashCredential.toString( 16 )] );
	return web3Utils.soliditySha3( '0x1901'.toString( 16 ) + encodedCredentialHash.substring( 2, 131 ) );
}

function signCredential( credentialHash, issuer ) {
	const rsv = ethUtil.ecsign(
		Buffer.from( credentialHash.substring( 2, 67 ), 'hex' ),
		Buffer.from( issuer.privateKey, 'hex' )
	);
	return ethUtil.toRpcSig( rsv.v, rsv.r, rsv.s );
}

describe("Verifiable Credentials", function () {
	this.timeout(400000);

	let credentialRegistryAddress, claimsVerifierAddress;

	const accounts = lacchain.getSigners();

	const subject = accounts[1].address;
	const issuer = {
		address: accounts[0].address, //'0x47adc0faa4f6eb42b499187317949ed99e77ee85'
		privateKey: 'effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b'
	};
	const signers = [{
		address: accounts[2].address, //'0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9'
		privateKey: '09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a'
	}, {
		address: accounts[3].address, //'0x4222ec932c5a68b80e71f4ddebb069fa02518b8a'
		privateKey: '6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1'
	}];

	const vc = {
		"@context": "https://www.w3.org/2018/credentials/v1",
		id: "73bde252-cb3e-44ab-94f9-eba6a8a2f28d",
		type: "VerifiableCredential",
		issuer: `did:lac:main:${issuer.address}`,
		issuanceDate: moment().toISOString(),
		expirationDate: moment().add( 1, 'years' ).toISOString(),
		credentialSubject: {
			id: `did:lac:main:${subject}`,
			data: 'test'
		},
		proof: []
	}

	before( async() => {
		const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry", accounts[0]);
		const credentialRegistry = await lacchain.deployContract(CredentialRegistry);

		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = await lacchain.deployContract(ClaimsVerifier, credentialRegistry.address);

		claimsVerifierAddress = claimsVerifier.address;
		credentialRegistryAddress = credentialRegistry.address;
		console.log('ClaimsVerifier', claimsVerifier.address);
		console.log('CredentialRegistry', credentialRegistry.address);

		const tx1 = await credentialRegistry.grantRole( '0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122', claimsVerifier.address );
		await tx1.wait();
		const tx2 = await claimsVerifier.grantRole( '0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122', issuer.address );
		await tx2.wait();
		const tx3 = await claimsVerifier.grantRole( '0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70', signers[0].address );
		await tx3.wait();
		const tx4 = await claimsVerifier.grantRole( '0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70', signers[1].address );
		await tx4.wait();
	} )

	it( "should register a VC", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const credentialHash = getCredentialHash( vc, issuer, claimsVerifier.address );
		const signature = await signCredential( credentialHash, issuer );

		const tx = await claimsVerifier.registerCredential( subject, credentialHash,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 ),
			signature, { from: issuer.address } );

		vc.proof.push( {
			id: vc.issuer,
			type: "EcdsaSecp256k1Signature2019",
			proofPurpose: "assertionMethod",
			verificationMethod: `${vc.issuer}#vm-0`,
			domain: claimsVerifier.address,
			proofValue: signature
		} );

		await tx.wait();

		return expect( tx.hash ).to.not.null;
	} );

	it( "should fail verify additional signers", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );
		const result = await claimsVerifier.verifyCredential( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], rsv.v, rsv.r, rsv.s );

		const additionalSigners = result[3];

		expect( additionalSigners ).to.equal( false );
	} );

	it( "should register additional signatures to the VC", async() => {
		const claimsVerifier1 = await ethers.getContractAt("ClaimsVerifier", claimsVerifierAddress, accounts[2]);

		const credentialHash = getCredentialHash( vc, issuer, claimsVerifierAddress );
		const signature1 = await signCredential( credentialHash, signers[0] );

		const tx1 = await claimsVerifier1.connect(accounts[2]).registerSignature( credentialHash, issuer.address, signature1, { from: accounts[2].address } );

		vc.proof.push( {
			id: `did:lac:main:${signers[0]}`,
			type: "EcdsaSecp256k1Signature2019",
			proofPurpose: "assertionMethod",
			verificationMethod: `did:lac:main:${signers[0]}#vm-0`,
			domain: claimsVerifierAddress,
			proofValue: signature1
		} );

		const receipt1 = await tx1.wait();

		expect( receipt1.status ).to.equal( 1 );

		const claimsVerifier2 = await ethers.getContractAt("ClaimsVerifier", claimsVerifierAddress, accounts[3]);

		const signature2 = await signCredential( credentialHash, signers[1] );
		const tx2 = await claimsVerifier2.connect(accounts[3]).registerSignature( credentialHash, issuer.address, signature2 );

		vc.proof.push( {
			id: `did:lac:main:${signers[1]}`,
			type: "EcdsaSecp256k1Signature2019",
			proofPurpose: "assertionMethod",
			verificationMethod: `did:lac:main:${signers[1]}#vm-0`,
			domain: claimsVerifierAddress,
			proofValue: signature2
		} );

		const receipt2 = await tx2.wait();

		return expect( receipt2.status ).to.equal( 1 );
	} );

	it( "should verify a VC", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );
		const result = await claimsVerifier.verifyCredential( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], rsv.v, rsv.r, rsv.s );

		const credentialExists = result[0];
		const isNotRevoked = result[1];
		const issuerSignatureValid = result[2];
		const additionalSigners = result[3];
		const isNotExpired = result[4];

		expect( credentialExists ).to.equal( true );
		expect( isNotRevoked) .to.equal( true );
		expect( issuerSignatureValid ).to.equal( true );
		expect( additionalSigners ).to.equal( true );
		expect( isNotExpired ).to.equal( true );
	} );

	it( "should verify additional signatures", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;

		const sign1 = await claimsVerifier.verifySigner( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], vc.proof[1].proofValue );

		expect( sign1 ).to.equal( true );

		const sign2 = await claimsVerifier.verifySigner( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], vc.proof[2].proofValue );

		expect( sign2 ).to.equal( true );
	} );

	it( "should revoke the credential", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry", accounts[0]);
		const credentialRegistry = CredentialRegistry.attach( credentialRegistryAddress );

		const credentialHash = getCredentialHash( vc, issuer, claimsVerifier.address );

		const tx = await credentialRegistry.revokeCredential( credentialHash );
		const receipt = await tx.wait();

		expect( receipt.status ).to.equal( 1 );
	} );

	it( "should fail the verification process due credential status", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const data = `0x${sha256( JSON.stringify( vc.credentialSubject ) )}`;
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );
		const result = await claimsVerifier.verifyCredential( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			data,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 )
		], rsv.v, rsv.r, rsv.s );

		const isNotRevoked = result[1];

		expect( isNotRevoked ).to.equal( false );
	} );

	it( "should verify credential status using the CredentialRegistry", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("ClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

		const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry", accounts[0]);
		const credentialRegistry = CredentialRegistry.attach( credentialRegistryAddress );

		const credentialHash = getCredentialHash( vc, issuer, claimsVerifier.address );

		const result = await credentialRegistry.status( issuer.address, credentialHash );

		expect( result ).to.equal( false );
	} );
} );