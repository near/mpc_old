# Chain Signatures Contract on Ethereum

## Overview

This repository contains the Solidity code for the Chain Signatures contract, which is deployed on the Ethereum blockchain.

## Setup

To setup the project, you can use the following command:

```bash
npm install
```

## Compile

To compile the contract, you can use the following command:

```bash
npx hardhat compile
```

## Testing

To unit test the contract, you can use the following command:

```bash
npx hardhat test
```

To do a quick end-to-end test, you can use the following command:
```bash
npx hardhat node
```

Then in a separate terminal, you can run the following command to deploy the contract:
```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --network localhost
```

Then run this command to run the responder (mpc node expects to be this role):

```bash
npx hardhat run scripts/responder.js
```

Then in a separate terminal, run the following command to execute the `sign.js` script (mpc client expects to be this role):
```bash
npx hardhat run scripts/sign.js
```