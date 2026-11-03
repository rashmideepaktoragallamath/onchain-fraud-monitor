// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RiskRegistry
/// @notice Tamper-evident audit trail for a transaction-monitoring system.
///         Off-chain detection engines score transactions; authorised analysts
///         anchor the resulting alerts here so that neither the alert nor its
///         review history can be silently altered or deleted afterwards.
/// @dev    Personal data never goes on-chain: only hashes, addresses that are
///         already public, a 0-100 score and a bitmask of reason codes.
contract RiskRegistry {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    enum Status {
        Open,
        Reviewed,
        Escalated,
        Dismissed
    }

    struct Alert {
        bytes32 txHash; // hash of the monitored transaction
        address subject; // wallet the alert is about
        address raisedBy; // analyst who anchored the alert
        uint64 raisedAt; // block timestamp
        uint64 updatedAt; // last status change
        uint16 reasonMask; // bit i set => reason code i triggered
        uint8 riskScore; // 1..100
        Status status;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    uint8 public constant MAX_RISK_SCORE = 100;

    address public owner;
    address public pendingOwner;

    mapping(address => bool) public isAnalyst;
    mapping(address => bytes32) public watchlistReason; // non-zero => watchlisted

    Alert[] private _alerts;
    mapping(bytes32 => uint256) private _alertIdPlusOne; // txHash => id + 1

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event AlertRaised(
        uint256 indexed alertId,
        bytes32 indexed txHash,
        address indexed subject,
        uint8 riskScore,
        uint16 reasonMask
    );
    event AlertStatusChanged(uint256 indexed alertId, Status from, Status to, address indexed by);
    event AnalystUpdated(address indexed analyst, bool enabled);
    event WatchlistUpdated(address indexed account, bool listed, bytes32 reason);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotOwner();
    error NotPendingOwner();
    error NotAnalyst();
    error ZeroAddress();
    error EmptyTxHash();
    error InvalidRiskScore(uint8 score);
    error NoReasonGiven();
    error AlreadyReported(bytes32 txHash, uint256 alertId);
    error UnknownAlert(uint256 alertId);
    error InvalidTransition(Status from, Status to);
    error EmptyReason();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAnalyst() {
        if (!isAnalyst[msg.sender]) revert NotAnalyst();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        owner = msg.sender;
        isAnalyst[msg.sender] = true;
        emit OwnershipTransferred(address(0), msg.sender);
        emit AnalystUpdated(msg.sender, true);
    }

    /*//////////////////////////////////////////////////////////////
                           ALERT LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Anchor a new alert. A transaction can be reported only once.
    function raiseAlert(bytes32 txHash, address subject, uint8 riskScore, uint16 reasonMask)
        external
        onlyAnalyst
        returns (uint256 alertId)
    {
        if (txHash == bytes32(0)) revert EmptyTxHash();
        if (subject == address(0)) revert ZeroAddress();
        if (riskScore == 0 || riskScore > MAX_RISK_SCORE) revert InvalidRiskScore(riskScore);
        if (reasonMask == 0) revert NoReasonGiven();

        uint256 existing = _alertIdPlusOne[txHash];
        if (existing != 0) revert AlreadyReported(txHash, existing - 1);

        alertId = _alerts.length;
        _alerts.push(
            Alert({
                txHash: txHash,
                subject: subject,
                raisedBy: msg.sender,
                raisedAt: uint64(block.timestamp),
                updatedAt: uint64(block.timestamp),
                reasonMask: reasonMask,
                riskScore: riskScore,
                status: Status.Open
            })
        );
        _alertIdPlusOne[txHash] = alertId + 1;

        emit AlertRaised(alertId, txHash, subject, riskScore, reasonMask);
    }

    /// @notice Move an alert through review. Escalated and Dismissed are final.
    ///         Allowed: Open -> Reviewed | Escalated | Dismissed,
    ///                  Reviewed -> Escalated | Dismissed.
    function updateStatus(uint256 alertId, Status newStatus) external onlyAnalyst {
        if (alertId >= _alerts.length) revert UnknownAlert(alertId);
        Alert storage a = _alerts[alertId];
        Status current = a.status;

        bool allowed = (current == Status.Open && newStatus != Status.Open)
            || (current == Status.Reviewed && (newStatus == Status.Escalated || newStatus == Status.Dismissed));
        if (!allowed) revert InvalidTransition(current, newStatus);

        a.status = newStatus;
        a.updatedAt = uint64(block.timestamp);
        emit AlertStatusChanged(alertId, current, newStatus, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                               WATCHLIST
    //////////////////////////////////////////////////////////////*/

    /// @notice Flag an address (e.g. sanctioned or known-bad). `reason` must be non-zero.
    function addToWatchlist(address account, bytes32 reason) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (reason == bytes32(0)) revert EmptyReason();
        watchlistReason[account] = reason;
        emit WatchlistUpdated(account, true, reason);
    }

    function removeFromWatchlist(address account) external onlyOwner {
        delete watchlistReason[account];
        emit WatchlistUpdated(account, false, bytes32(0));
    }

    function isWatchlisted(address account) external view returns (bool) {
        return watchlistReason[account] != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                             ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function setAnalyst(address analyst, bool enabled) external onlyOwner {
        if (analyst == address(0)) revert ZeroAddress();
        isAnalyst[analyst] = enabled;
        emit AnalystUpdated(analyst, enabled);
    }

    /// @notice Step 1 of a two-step handover; protects against typos in the new owner address.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Step 2: the new owner confirms.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function alertCount() external view returns (uint256) {
        return _alerts.length;
    }

    function getAlert(uint256 alertId) external view returns (Alert memory) {
        if (alertId >= _alerts.length) revert UnknownAlert(alertId);
        return _alerts[alertId];
    }

    /// @return found whether the transaction has been reported, and its alert id if so.
    function alertIdOf(bytes32 txHash) external view returns (bool found, uint256 alertId) {
        uint256 v = _alertIdPlusOne[txHash];
        return (v != 0, v == 0 ? 0 : v - 1);
    }
}
