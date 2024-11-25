const hre = require("hardhat");

async function main() {
  // Get the deployed contract address
  const deployments = require('../ignition/deployments/chain-31337/deployed_addresses.json');
  const contractAddress = deployments[Object.keys(deployments).pop()];
  
  const chainSignatures = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  console.log("Watching for SignatureRequested events...");
  
  // Set up event listener
  chainSignatures.on("SignatureRequested", (requestId, epsilon, payloadHash, event) => {
    console.log("\nNew SignatureRequested event detected!");
    console.log({
      requestId: requestId.toString(),
      epsilon: epsilon.toString(),
      payloadHash: payloadHash.toString(),
      blockNumber: event.blockNumber,
      transactionHash: event.transactionHash
    });

    // Respond to the signature request
    (async () => {
      try {
        // Example signature values - these would need to be generated properly
        const signature = {
            bigR: {
              x: '0xeb20f3b6c5882e018bef8f44ce452115c535983de7236e29343b3bc5c648f895',
              y: '0x40d8f8ea1b662fb9e18d17fe5b9bfd6f2d3eac49d9fefba8bfb895e4770cd1f8'
            },
            s: '0x5f06f4bc377e509eda49ec73074d62962cb0c5d48c0800580fad3e19ec620c09',
          recoveryId: 0
        };
        
        console.log("Responding with signature...");
        const tx = await chainSignatures.respond(requestId, signature);
        const receipt = await tx.wait();

        console.log("Signature submitted successfully!");
        console.log("Transaction hash:", receipt.transactionHash);
      } catch (error) {
        console.error("Error submitting signature:", error.message); 
      }
    })();
  });

  // Keep the script running
  process.stdin.resume();
}

main().catch(console.error);