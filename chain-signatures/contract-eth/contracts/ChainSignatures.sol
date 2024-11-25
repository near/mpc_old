// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./Secp256k1.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol"; // Import Hardhat's console library


contract ChainSignatures {
    struct SignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
    }

    struct SignatureRequest {
        uint256 epsilon;
        uint256 payloadHash;
        address requester;
    }

    struct SignatureResponse {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    // public key in affine form
    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    struct AffinePoint {
        uint256 x;
        uint256 y;
    }

    uint256 public threshold;
    mapping(bytes32 => SignatureRequest) public pendingRequests;
    uint256 public requestCounter;
    PublicKey public publicKey;

    mapping(bytes32 => uint256) public depositToRefund;

    event SignatureRequested(bytes32 indexed requestId, address requester, uint256 epsilon, uint256 payloadHash, string path);
    event SignatureResponded(bytes32 indexed requestId, SignatureResponse response);

    constructor(PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    function getPublicKey() public view returns (PublicKey memory) {
        return publicKey;
    }

    function derivedPublicKey(string memory path, address _predecessor) public view returns (PublicKey memory) {
        address predecessor = _predecessor == address(0) ? msg.sender : _predecessor;
        uint256 epsilon = deriveEpsilon(path, predecessor);
        PublicKey memory _derivedPublicKey = deriveKey(publicKey, epsilon);
        return _derivedPublicKey;
    }

    function deriveKey(PublicKey memory _publicKey, uint256 epsilon) public pure returns (PublicKey memory) {
        // G * epsilon + publicKey
        (uint256 epsilonGx, uint256 epsilonGy) = Secp256k1.ecMul(epsilon, Secp256k1.GX, Secp256k1.GY);
        (uint256 resultX, uint256 resultY) = Secp256k1.ecAdd(epsilonGx, epsilonGy, _publicKey.x, _publicKey.y);
        return PublicKey(resultX, resultY);
    }

    function deriveEpsilon(string memory path, address requester) public pure returns (uint256) {
        string memory requesterStr = Strings.toHexString(uint256(uint160(requester)), 20);
        string memory epsilonString = string.concat("near-mpc-recovery v0.2.0 epsilon derivation:", requesterStr, ",", path);
        console.log("Epsilon String:", epsilonString);
        bytes32 epsilonBytes = keccak256(bytes(epsilonString));
        uint256 epsilon = uint256(epsilonBytes);
        return epsilon;
    }

    function latestKeyVersion() public pure returns (uint32) {
        return 0;
    }

    function sign(SignRequest memory _request) external payable returns (bytes32) {
        bytes32 payload = _request.payload;
        string memory path = _request.path;
        uint32 keyVersion = _request.keyVersion;

        if (keyVersion > latestKeyVersion()) {
            revert("This key version is not supported. Call latest_key_version() to get the latest supported version.");
        }

        uint256 requiredDeposit = getSignatureDeposit();
        require(msg.value >= requiredDeposit, "Insufficient deposit");

        // Concert payload to int as big-endian, check if payload is than the secp256k1 curve order
        uint256 payloadHash = uint256(payload);
        require(
            payloadHash < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "Payload exceeds secp256k1 curve order"
        );

        bytes32 requestId = keccak256(abi.encodePacked(payload, msg.sender, path));
        require(pendingRequests[requestId].requester == address(0), "Request already exists");

        uint256 epsilon = deriveEpsilon(path, msg.sender);
        SignatureRequest memory request = SignatureRequest(epsilon, payloadHash, msg.sender);
        pendingRequests[requestId] = request;
        depositToRefund[requestId] = msg.value - requiredDeposit;
        requestCounter++;

        emit SignatureRequested(requestId, msg.sender, epsilon, payloadHash, path);

        return requestId;
    }
    
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        SignatureRequest storage request = pendingRequests[_requestId];
        require(request.requester != address(0), "Request not found");

        PublicKey memory expectedPublicKey = deriveKey(publicKey, request.epsilon);

        // Check the signature
        require(
            checkECSignature(
                expectedPublicKey,
                _response.bigR,
                uint256(_response.s),
                request.payloadHash,
                _response.recoveryId
            ),
            "Invalid signature"
        );

        emit SignatureResponded(_requestId, _response);

        // Refund excess deposit
        uint256 refund = depositToRefund[_requestId];

        // Clean up
        delete pendingRequests[_requestId];
        delete depositToRefund[_requestId];
        requestCounter--;

        if (refund > 0) {
            payable(request.requester).transfer(refund);
        }
    }

    function getSignatureDeposit() public view returns (uint256) {
        // Simplified deposit calculation
        if (requestCounter <= 3) {
            return 1 wei;
        } else {
            return (requestCounter - 3) * 4 * 1e15; // 0.004 ETH (~1 USD) first request after the first 3
        }
    }

    function checkECSignature(
        PublicKey memory expectedPk,
        AffinePoint memory bigR,
        uint256 s,
        uint256 msgHash,
        uint8 recoveryId
    ) public pure returns (bool) {
        console.log("expectedPk", expectedPk.x, expectedPk.y);
        console.log("signature", bigR.x, s);
        console.log("msgHash", msgHash);
        (uint256 pkX, uint256 pkY) = Secp256k1.recover(msgHash, recoveryId, bigR.x, s);
        console.log("recovered", pkX, pkY);
        return (pkX == expectedPk.x && pkY == expectedPk.y);
    }
}
