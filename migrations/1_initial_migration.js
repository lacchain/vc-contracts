const Migrations = artifacts.require("Migrations");
const CredentialRegistry = artifacts.require("CredentialRegistry");
const ClaimsVerifier = artifacts.require("ClaimsVerifier");

module.exports = async function (deployer) {
  await deployer.deploy(Migrations);
  const registry = await deployer.deploy(CredentialRegistry);
  const verifier = await deployer.deploy(ClaimsVerifier, registry.address);
  await registry.grantRole( await registry.ISSUER_ROLE(), verifier.address );
};
