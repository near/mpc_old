const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ChainSignatures", function () {
  let ChainSignatures;
  let chainSignatures;
  let owner;
  let addr1;
  let addr2;
  let publicKey;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    // Define the public key as a byte array
    const publicKeyArray = [4, 252, 17, 88, 19, 229, 154, 145, 77, 117, 102, 164, 177, 212, 38, 48, 72, 250, 246, 182, 218, 182, 137, 60, 77, 101, 211, 159, 177, 35, 218, 86, 81, 34, 58, 8, 114, 107, 154, 223, 0, 50, 161, 52, 118, 17, 227, 94, 159, 20, 183, 168, 231, 238, 49, 165, 217, 4, 25, 10, 78, 246, 250, 71, 225];    
    const x = publicKeyArray.slice(1, 33);
    const y = publicKeyArray.slice(33);
    const xHex = '0x' + x.map(byte => byte.toString(16).padStart(2, '0')).join('');
    const yHex = '0x' + y.map(byte => byte.toString(16).padStart(2, '0')).join('');
    console.log("===", xHex, yHex);
    ChainSignatures = await ethers.getContractFactory("ChainSignatures");
    publicKey = { x: xHex, y: yHex };
    chainSignatures = await ChainSignatures.deploy(publicKey);
  });

  describe("deriveEpsilon", function () {
    it("should generate correct epsilon values", async function () {
      const testPath = "test";
      expect(addr1.address).to.equal('0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
      const epsilon = await chainSignatures.deriveEpsilon(testPath, addr1.address);
      expect(epsilon).to.equal('0x0C38479E8053A632CC3E1CAC05ED33D7733C908FDC256AFEBB9396206A05D86D');
    });
  });

  describe("deriveKey", function () {
    it("should correctly derive a new key", async function () {  
      const testEpsilon = "0x4B2E9854C775F5ECC88004EB6DCF7CEB775D74D0E313CD5FA5E5994A4B57E11C";

      // Call the deriveKey function
      const derivedKey = await chainSignatures.deriveKey(publicKey, testEpsilon);

      // Expected result (pre-computed)
      const expectedKey = [4, 61, 180, 85, 68, 190, 105, 61, 77, 29, 98, 156, 72, 81, 164, 172, 168, 69, 147, 213, 125, 211, 91, 128, 86, 30, 33, 45, 76, 244, 53, 201, 151, 102, 232, 86, 211, 60, 3, 198, 104, 188, 58, 29, 122, 92, 192, 58, 64, 41, 109, 249, 139, 98, 172, 72, 168, 76, 122, 111, 28, 130, 172, 239, 41];
      const expectedX = '0x' + expectedKey.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const expectedY = '0x' + expectedKey.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');

      // Assert that the derived key matches the expected key
      expect(derivedKey.x).to.equal(expectedX);
      expect(derivedKey.y).to.equal(expectedY);
    });

    it("should correctly derive a new key from derived epsilon", async function () {  
      const derivedEpsilon = "0x0C38479E8053A632CC3E1CAC05ED33D7733C908FDC256AFEBB9396206A05D86D";

      // Call the deriveKey function
      const derivedKey = await chainSignatures.deriveKey(publicKey, derivedEpsilon);

      // Expected result (pre-computed)
      const expectedKey = [4, 190, 143, 8, 126, 40, 72, 115, 4, 123, 130, 29, 196, 122, 34, 228, 26, 20, 35, 250, 206, 151, 165, 156, 80, 108, 174, 28, 201, 170, 194, 76, 62, 12, 129, 226, 158, 161, 199, 99, 154, 106, 237, 60, 51, 66, 251, 34, 189, 109, 197, 189, 114, 141, 17, 10, 82, 55, 232, 178, 0, 131, 170, 202, 41];
      const expectedX = '0x' + expectedKey.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const expectedY = '0x' + expectedKey.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');

      // Assert that the derived key matches the expected key
      expect(derivedKey.x).to.equal(expectedX);
      expect(derivedKey.y).to.equal(expectedY);
    });
  });

  describe("checkECSignature", function () {
    it("should verify a valid signature", async function () {
      // precomputed from rust
      const derivedKey = [4, 190, 143, 8, 126, 40, 72, 115, 4, 123, 130, 29, 196, 122, 34, 228, 26, 20, 35, 250, 206, 151, 165, 156, 80, 108, 174, 28, 201, 170, 194, 76, 62, 12, 129, 226, 158, 161, 199, 99, 154, 106, 237, 60, 51, 66, 251, 34, 189, 109, 197, 189, 114, 141, 17, 10, 82, 55, 232, 178, 0, 131, 170, 202, 41];
      const derivedKeyX = '0x' + derivedKey.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const derivedKeyY = '0x' + derivedKey.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      
      const bigR = [4, 235, 32, 243, 182, 197, 136, 46, 1, 139, 239, 143, 68, 206, 69, 33, 21, 197, 53, 152, 61, 231, 35, 110, 41, 52, 59, 59, 197, 198, 72, 248, 149, 64, 216, 248, 234, 27, 102, 47, 185, 225, 141, 23, 254, 91, 155, 253, 111, 45, 62, 172, 73, 217, 254, 251, 168, 191, 184, 149, 228, 119, 12, 209, 248];
      const bigRX = '0x' + bigR.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const bigRY = '0x' + bigR.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      
      const s = "0x5F06F4BC377E509EDA49EC73074D62962CB0C5D48C0800580FAD3E19EC620C09";

      const msgHash = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";

      const isValid = await chainSignatures.checkECSignature(
        { x: derivedKeyX, y: derivedKeyY },
        { x: bigRX, y: bigRY },
        s,
        msgHash,
        0
      );

      expect(isValid).to.be.true;
    });
  });

  describe("Signing requests", function () {
    it("Should create a signature request", async function () {
      const payload = ethers.keccak256(ethers.toUtf8Bytes("Test payload"));
      const path = "test/path";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();
      const epsilon = await chainSignatures.deriveEpsilon(path, addr1.address);
      const requestId = 
        ethers.solidityPackedKeccak256(
          ["bytes32", "address", "string"],
          [payload, addr1.address, path]
        );

      await expect(chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0}, { value: requiredDeposit }))
        .to.emit(chainSignatures, "SignatureRequested")
        .withArgs(requestId, addr1.address, epsilon, payload, path);
    });

    it("Should not allow creating a request with insufficient deposit", async function () {
      const payload = ethers.keccak256(ethers.toUtf8Bytes("Test payload"));
      const path = "test/path";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();

      await expect(chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0}, { value: requiredDeposit - 1n }))
        .to.be.revertedWith("Insufficient deposit");
    });

    it("Respond to a signature request", async function () {
      const payload = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
      const path = "test";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();

      const tx = await chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0}, { value: requiredDeposit });
      const receipt = await tx.wait();
      console.log(receipt)
      const requestId = receipt.logs[0].args[0];

      const derivedKey = [4, 190, 143, 8, 126, 40, 72, 115, 4, 123, 130, 29, 196, 122, 34, 228, 26, 20, 35, 250, 206, 151, 165, 156, 80, 108, 174, 28, 201, 170, 194, 76, 62, 12, 129, 226, 158, 161, 199, 99, 154, 106, 237, 60, 51, 66, 251, 34, 189, 109, 197, 189, 114, 141, 17, 10, 82, 55, 232, 178, 0, 131, 170, 202, 41];
      const derivedKeyX = '0x' + derivedKey.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const derivedKeyY = '0x' + derivedKey.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const bigR = [4, 235, 32, 243, 182, 197, 136, 46, 1, 139, 239, 143, 68, 206, 69, 33, 21, 197, 53, 152, 61, 231, 35, 110, 41, 52, 59, 59, 197, 198, 72, 248, 149, 64, 216, 248, 234, 27, 102, 47, 185, 225, 141, 23, 254, 91, 155, 253, 111, 45, 62, 172, 73, 217, 254, 251, 168, 191, 184, 149, 228, 119, 12, 209, 248];
      const bigRX = '0x' + bigR.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const bigRY = '0x' + bigR.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const s = "0x5F06F4BC377E509EDA49EC73074D62962CB0C5D48C0800580FAD3E19EC620C09".toLowerCase();
      const msgHash = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9".toLowerCase();
      const response = { bigR: { x: bigRX, y: bigRY }, s: s, recoveryId: 0 };
      console.log("===", requestId, response);
      // This form doesn't work, possible hardhat bug
      // await expect(chainSignatures.connect(owner).respond(requestId, response))
      //   .to.emit(chainSignatures, "SignatureResponded")
      //   .withArgs(requestId, [[ethers.BigNumber.from(bigRX), ethers.BigNumber.from(bigRY)], ethers.BigNumber.from(s), 0]);
      const tx2 = await chainSignatures.connect(owner).respond(requestId, response);
      const receipt2 = await tx2.wait();
      const responseEvent = receipt2.logs.find(log => 
        chainSignatures.interface.parseLog(log)?.name === "SignatureResponded"
      );
      const parsedEvent = chainSignatures.interface.parseLog(responseEvent);
      
      expect(parsedEvent.args[0]).to.equal(requestId);
      expect(parsedEvent.args[1][0][0]).to.equal(bigRX);
      expect(parsedEvent.args[1][0][1]).to.equal(bigRY);
      expect(parsedEvent.args[1][1]).to.equal(s);
      expect(parsedEvent.args[1][2]).to.equal(0);
    });
  });

  describe("Signature deposit", function () {
    it("Should return correct deposit amount", async function () {
      expect(await chainSignatures.getSignatureDeposit()).to.equal(1);

      for (let i = 0; i < 4; i++) {
        const payload = ethers.keccak256(ethers.toUtf8Bytes(`Test payload ${i}`));
        const path = `test/path/${i}`;
        const requiredDeposit = await chainSignatures.getSignatureDeposit();
        await chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0}, { value: requiredDeposit });
      }

      expect(await chainSignatures.getSignatureDeposit()).to.equal(ethers.parseEther("0.004"));
    });
  });

});
