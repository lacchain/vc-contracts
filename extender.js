const { extendEnvironment } = require("hardhat/config");
const { lazyObject } = require( "hardhat/plugins" );
const { GasModelProvider, GasModelSigner } = require( "@lacchain/gas-model-provider" );

extendEnvironment((hre) => {
  hre.lacchain = lazyObject(() => {
    const gasModelProvider = new GasModelProvider( hre.network.config.url );
    return {
      provider: gasModelProvider,
      getSigners: () => {
        const { accounts, nodeAddress, expiration } = hre.network.config;
        return accounts.map( account => new GasModelSigner(account, gasModelProvider, nodeAddress, expiration));
      },
      deployContract: async (Contract, ...params) => {
        const contract = await Contract.deploy(...params);
        const receipt = await contract.deployTransaction.wait();
        return new hre.ethers.Contract(receipt.contractAddress, Contract.interface, Contract.signer);
      }
    };
  });
});