// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./EllipticCurve.sol";

/**
 ** @title Secp256k1 Elliptic Curve
 ** @notice Example of particularization of Elliptic Curve for secp256k1 curve
 ** @author Witnet Foundation
 */
library Secp256k1 {
    uint256 public constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant A = 0;
    uint256 public constant B = 7;
    uint256 public constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function ecMul(uint256 _k, uint256 _x, uint256 _y) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(_k, _x, _y, A, P);
    }

    function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecAdd(_x1, _y1, _x2, _y2, A, P);
    }

    /// @dev recovers signer public key point value.
    /// @param digest hashed message
    /// @param recoveryId recovery id
    /// @param r first 32 bytes of signature
    /// @param s last 32 bytes of signature
    /// @return (x, y) EC point
    function recover(
        uint256 digest,
        uint8 recoveryId,
        uint256 r,
        uint256 s
    ) internal pure returns (uint256, uint256) {
        require(r < P && s < N, "Invalid signature");
        require(recoveryId == 0 || recoveryId == 1, "Invalid recovery id");
        
        // Calculate curve point R
        uint256 x = r;
        if (recoveryId >> 1 == 1) {
            x += N;
        }
        require(x < P, "Invalid x coordinate");

        // Calculate R.y = ±sqrt(x³ + 7)
        uint256 y = EllipticCurve.deriveY(recoveryId == 0 ? 0x02 : 0x03, x, A, B, P);
        if ((y % 2 != 0) != (recoveryId % 2 != 0)) {
            y = P - y;
        }

        // Calculate r_inv = r^(-1) mod n
        uint256 r_inv = EllipticCurve.invMod(r, N);
        
        // u1 = -z * r^(-1) mod n
        uint256 u1 = mulmod(N - digest % N, r_inv, N);
        // u2 = s * r^(-1) mod n
        uint256 u2 = mulmod(s, r_inv, N);

        // Q = u1*G + u2*R
        (uint256 x1, uint256 y1) = ecMul(u1, GX, GY);
        (uint256 x2, uint256 y2) = ecMul(u2, x, y);
        (uint256 qx, uint256 qy) = ecAdd(x1, y1, x2, y2);

        return (qx, qy);
    }
}
