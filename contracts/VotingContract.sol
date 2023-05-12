// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./EllipticCurve.sol";

contract VotingContract {
    uint256 public counter;
    uint256 public stakes;
    mapping(uint256 => Vote) public votes;
    mapping(address => bool) public voted;

    // Define the parameters of the secp256r1 elliptic curve
    uint256 private constant N =
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    uint256 private constant A =
        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc;
    uint256 private constant B =
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
    uint256 private constant P =
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 private constant Gx =
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    uint256 private constant Gy =
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;
    Point private G = Point(Gx, Gy); // Generator point

    uint256 public Yx;
    uint256 public Yy;
    Point public Y; // Public key, to be set by the constructor

    Vote public encryptedSum;

    constructor(uint256 yx, uint256 yy) {
        Yx = yx;
        Yy = yy;
        Y = Point(yx, yy);
        require(EllipticCurve.isOnCurve(Yx, Yy, A, B, P), "not on curve haha");
    }

    struct Vote {
        Point C1;
        Point C2;
        address voter;
    }

    struct Point {
        uint256 x;
        uint256 y;
    }

    function castVote(
        uint256 c1x,
        uint256 c1y,
        uint256 c2x,
        uint256 c2y,
        uint256[12] memory proof,
        uint256 stake
    ) external {
        require(EllipticCurve.isOnCurve(c1x, c1y, A, B, P), "not on curve");
        require(EllipticCurve.isOnCurve(c2x, c2y, A, B, P), "not on curve");
        require(voted[msg.sender] == false, "already voted");

        Point memory C1 = Point(c1x, c1y);
        Point memory C2 = Point(c2x, c2y);

        Vote memory vote = Vote(Point(c1x, c1y), Point(c2x, c2y), msg.sender);
        require(verify_proof(C1, C2, proof), "invalid proof");
        vote = homoMul(vote, stake);
        votes[counter] = vote;
        voted[msg.sender] = true;

        if (encryptedSum.C1.x == 0) {
            encryptedSum = vote;
        } else {
            encryptedSum = homoSum(vote, encryptedSum);
        }

        counter++;
        stakes += stake;
    }

    function homoSum(
        Vote memory a,
        Vote memory b
    ) internal pure returns (Vote memory) {
        Point memory C1_prime = sumPoint(a.C1, b.C1);
        Point memory C2_prime = sumPoint(a.C2, b.C2);
        return Vote(C1_prime, C2_prime, address(0));
    }

    function sumPoint(
        Point memory a,
        Point memory b
    ) internal pure returns (Point memory) {
        (uint256 x, uint256 y) = EllipticCurve.ecAdd(a.x, a.y, b.x, b.y, A, P);
        return Point(x, y);
    }

    function subPoint(
        Point memory a,
        Point memory b
    ) internal pure returns (Point memory) {
        (uint256 x, uint256 y) = EllipticCurve.ecSub(a.x, a.y, b.x, b.y, A, P);
        return Point(x, y);
    }

    function mulPoint(
        Point memory a,
        uint256 scalar
    ) internal pure returns (Point memory) {
        (uint256 x, uint256 y) = EllipticCurve.ecMul(scalar, a.x, a.y, A, P);
        return Point(x, y);
    }

    function homoMul(
        Vote memory a,
        uint256 scalar
    ) internal pure returns (Vote memory) {
        Point memory C1_prime = mulPoint(a.C1, scalar);
        Point memory C2_prime = mulPoint(a.C2, scalar);
        return Vote(C1_prime, C2_prime, a.voter);
    }

    function equals(
        Point memory _first,
        Point memory _second
    ) internal pure returns (bool) {
        // Just compare the output of hashing all fields packed
        return (keccak256(abi.encodePacked(_first.x, _first.y)) ==
            keccak256(abi.encodePacked(_second.x, _second.y)));
    }

    function getHash(
        uint256[12] calldata values
    ) internal pure returns (uint256) {
        bytes32 h = sha256(
            abi.encodePacked(
                [
                    values[0],
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    values[7],
                    values[8],
                    values[9],
                    values[10],
                    values[11]
                ]
            )
        );
        return uint256(h);
    }

    function verify_proof(
        Point memory C1,
        Point memory C2,
        uint256[12] memory p
    ) internal view returns (bool) {
        // [0] a0x
        // [1] a0y
        // [2] b0x
        // [3] b0y
        // [4] a1x
        // [5] a1y
        // [6] b1x
        // [7] b1y
        // [8] c0
        // [9] c1
        // [10] f0
        // [11] f1

        bytes32 h = keccak256(
            abi.encodePacked(
                [
                    C1.x,
                    C1.y,
                    C2.x,
                    C2.y,
                    p[0],
                    p[1],
                    p[4],
                    p[5],
                    p[2],
                    p[3],
                    p[6],
                    p[7]
                ]
            )
        );
        uint256 c = uint256(h) % N;
        bool s0 = addmod(p[8], p[9], N) == c;
        bool s1 = equals(
            mulPoint(G, p[10]),
            sumPoint(Point(p[0], p[1]), mulPoint(C1, p[8]))
        );
        bool s2 = equals(
            mulPoint(G, p[11]),
            sumPoint(Point(p[4], p[5]), mulPoint(C1, p[9]))
        );
        bool s3 = equals(
            mulPoint(Y, p[10]),
            sumPoint(Point(p[2], p[3]), mulPoint(C2, p[8]))
        );
        bool s4 = equals(
            mulPoint(Y, p[11]),
            sumPoint(Point(p[6], p[7]), mulPoint(subPoint(C2, G), p[9]))
        );
        return s0 && s1 && s2 && s3 && s4;
    }
}
