const hre = require("hardhat");

async function main() {
  // Get the deployed contract address
  const deployments = require('../ignition/deployments/chain-31337/deployed_addresses.json');
  const contractAddress = deployments[Object.keys(deployments).pop()];
  
  const chainSignatures = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  try {
    // Verify contract exists
    const code = await hre.ethers.provider.getCode(contractAddress);
    if (code === "0x") throw new Error("No contract deployed at this address");

    // Get public key data
    const publicKey = await chainSignatures.getPublicKey();
    console.log("Public key:", {
      x: publicKey.x?.toString() || 'undefined',
      y: publicKey.y?.toString() || 'undefined'
    });

  } catch (error) {
    console.error("Error:", error.message);
  }


  // Sign a test message
  try {
    const testMessage = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
    const testPath = "test";
    const signatureDeposit = await chainSignatures.getSignatureDeposit();
    
    console.log("Requesting signature for message:", testMessage);
    console.log("Using path:", testPath);
    console.log("Required deposit:", signatureDeposit.toString(), "wei");

    // Get signer and make sure it's connected to the provider
    const signer = (await hre.ethers.getSigners())[1];
    const chainSignaturesWithSigner = chainSignatures.connect(signer);
    
    const tx = await chainSignaturesWithSigner.sign({payload: testMessage, path: testPath, keyVersion: 0}, {
      value: signatureDeposit
    });
    const receipt = await tx.wait();

    const requestEvent = receipt.logs.find(log => 
      chainSignatures.interface.parseLog(log)?.name === "SignatureRequested"
    );

    if (requestEvent) {
      const parsedEvent = chainSignatures.interface.parseLog(requestEvent);
      console.log("Signature requested successfully!");
      console.log("Request ID:", parsedEvent.args.requestId);
      console.log("Epsilon:", parsedEvent.args.epsilon.toString());
      console.log("Payload Hash:", parsedEvent.args.payloadHash.toString());

      // Add event listener for SignatureResponded
      console.log("Waiting for signature response...");
      const filter = chainSignatures.filters.SignatureResponded(parsedEvent.args.requestId);
      
      chainSignatures.once(filter, (requestId, signature, event) => {
        console.log("\nSignature response received!");
        console.log("Request ID:", requestId.toString());
        console.log("Signature:", {
          r: signature.r.toString(),
          s: signature.s.toString()
        });
      });
    }

  } catch (error) {
    console.error("Error requesting signature:", error.message);
  }

  // Keep script running to wait for event
  await new Promise(() => {});

}

main().catch(console.error);