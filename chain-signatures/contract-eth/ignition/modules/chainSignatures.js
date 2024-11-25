const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const DEFAULT_PUBLIC_KEY = {
  x: "0xfc115813e59a914d7566a4b1d4263048faf6b6dab6893c4d65d39fb123da5651",
  y: "0x223a08726b9adf0032a1347611e35e9f14b7a8e7ee31a5d904190a4ef6fa47e1"
};

module.exports = buildModule("ChainSignaturesModule", (m, args = {}) => {
  const deployPublicKey = args.publicKey || DEFAULT_PUBLIC_KEY;
  const chainSignatures = m.contract("ChainSignatures", [deployPublicKey]);

  return { chainSignatures };
});

// npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters '{"publicKey": {"x": "0xYOUR_X_VALUE", "y": "0xYOUR_Y_VALUE"}}'