// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleAnchor
/// @notice Batched version of the RiskRegistry audit trail. Instead of one transaction per alert,
///         an analyst anchors ONE Merkle root covering many alerts. Anyone can later prove that a
///         specific alert (transaction hash, wallet, score, reason mask) was part of an anchored
///         batch by supplying a short proof, so the cost of anchoring is shared across the batch.
/// @dev    Leaf   = keccak256(keccak256(txHash | subject | riskScore | reasonMask))   (double hash,
///                  so a leaf can never be confused with an inner node).
///         Parent = keccak256(min(a, b) | max(a, b)); an odd node is carried up unchanged.
///         scripts/merkle-lib.js builds the same tree off-chain.
contract MerkleAnchor {
    struct Batch {
        bytes32 root;
        address anchoredBy;
        uint64 anchoredAt;
        uint32 count; // number of alerts the root covers
    }

    address public owner;
    mapping(address => bool) public isAnalyst;

    Batch[] private _batches;
    mapping(bytes32 => uint256) private _batchIdPlusOne; // root => id + 1

    event BatchAnchored(uint256 indexed batchId, bytes32 indexed root, uint32 count, address indexed by);
    event AnalystSet(address indexed analyst, bool allowed);

    error NotOwner();
    error NotAnalyst();
    error EmptyRoot();
    error EmptyBatch();
    error AlreadyAnchored(bytes32 root, uint256 batchId);
    error UnknownBatch(uint256 batchId);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAnalyst() {
        if (!isAnalyst[msg.sender]) revert NotAnalyst();
        _;
    }

    constructor() {
        owner = msg.sender;
        isAnalyst[msg.sender] = true;
        emit AnalystSet(msg.sender, true);
    }

    function setAnalyst(address analyst, bool allowed) external onlyOwner {
        isAnalyst[analyst] = allowed;
        emit AnalystSet(analyst, allowed);
    }

    /// @notice Anchor the Merkle root of `count` alerts.
    function anchorBatch(bytes32 root, uint32 count) external onlyAnalyst returns (uint256 batchId) {
        if (root == bytes32(0)) revert EmptyRoot();
        if (count == 0) revert EmptyBatch();
        uint256 existing = _batchIdPlusOne[root];
        if (existing != 0) revert AlreadyAnchored(root, existing - 1);

        batchId = _batches.length;
        _batches.push(Batch({root: root, anchoredBy: msg.sender, anchoredAt: uint64(block.timestamp), count: count}));
        _batchIdPlusOne[root] = batchId + 1;
        emit BatchAnchored(batchId, root, count, msg.sender);
    }

    function batchCount() external view returns (uint256) {
        return _batches.length;
    }

    function getBatch(uint256 batchId) external view returns (Batch memory) {
        if (batchId >= _batches.length) revert UnknownBatch(batchId);
        return _batches[batchId];
    }

    /// @notice The leaf for one alert; identical to leafHash() in scripts/merkle-lib.js.
    function leafOf(bytes32 txHash, address subject, uint8 riskScore, uint16 reasonMask) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(txHash, subject, riskScore, reasonMask))));
    }

    /// @notice True when `leaf` is covered by the root of `batchId`, given its sibling hashes.
    function verify(uint256 batchId, bytes32 leaf, bytes32[] calldata proof) public view returns (bool) {
        if (batchId >= _batches.length) revert UnknownBatch(batchId);
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == _batches[batchId].root;
    }

    /// @notice Convenience: verify an alert from its fields instead of a precomputed leaf.
    function verifyAlert(
        uint256 batchId,
        bytes32 txHash,
        address subject,
        uint8 riskScore,
        uint16 reasonMask,
        bytes32[] calldata proof
    ) external view returns (bool) {
        return verify(batchId, leafOf(txHash, subject, riskScore, reasonMask), proof);
    }
}
