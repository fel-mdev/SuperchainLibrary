// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    IL2ToL2CrossDomainMessenger,
    ISuperchainTokenBridge,
    ISuperchainWETH,
    ICrossL2Inbox,
    Identifier
} from "./Interfaces.sol";

error MessageHashNotRelayed();

/// @dev This library assumes that the messages are relayed via the L2ToL2CrossDomainMessenger.
library SuperchainLibrary {
    address internal constant CROSS_L2_INBOX = 0x4200000000000000000000000000000000000022;
    address internal constant L2_TO_L2_CROSS_DOMAIN_MESSENGER = 0x4200000000000000000000000000000000000023;
    address internal constant SUPERCHAIN_WETH = 0x4200000000000000000000000000000000000024;
    address internal constant SUPERCHAIN_TOKEN_BRIDGE = 0x4200000000000000000000000000000000000028;

    /// @notice Check if the current message is a cross L2 message. Returns true if it is, false otherwise.
    function isCrossL2Message() internal view returns (bool isCrossL2Message_) {
        isCrossL2Message_ = msg.sender == L2_TO_L2_CROSS_DOMAIN_MESSENGER;
    }

    /// @notice Get the sender of the L2<->L2 message. If this is not a cross L2 message being relayed, it will return address(0).
    function msgSender() internal view returns (address msgSender_) {
        msgSender_ = IL2ToL2CrossDomainMessenger(L2_TO_L2_CROSS_DOMAIN_MESSENGER).crossDomainMessageSender();
    }

    /// @notice Get the source chain id of the L2<->L2 message. If this is not a cross L2 message being relayed, it will return 0.
    function source() internal view returns (uint256 source_) {
        source_ = IL2ToL2CrossDomainMessenger(L2_TO_L2_CROSS_DOMAIN_MESSENGER).crossDomainMessageSource();
    }

    /// @notice Get the sender and source chain id of the L2<->L2 message.
    ///         If this is not a cross L2 message being relayed, it will return address(0) and 0 respectively.
    function msgSenderAndSource() internal view returns (address msgSender_, uint256 source_) {
        (msgSender_, source_) = IL2ToL2CrossDomainMessenger(L2_TO_L2_CROSS_DOMAIN_MESSENGER).crossDomainContext();
    }

    /// @notice Send an ERC20 token across the superchain.
    /// @param _token The address of the ERC20 token to send.
    /// @param _to The address of the receiver of the ERC20 token on the destination chain.
    /// @param _amount The amount of the ERC20 token to send.
    /// @param _chainId The chain id of the destination chain.
    /// @return msgHash_ The unique hash used to identify the message in the L2ToL2CrossDomainMessenger.
    function crossSendERC20(address _token, address _to, uint256 _amount, uint256 _chainId)
        internal
        returns (bytes32 msgHash_)
    {
        return ISuperchainTokenBridge(SUPERCHAIN_TOKEN_BRIDGE).sendERC20(_token, _to, _amount, _chainId);
    }

    /// @notice Send ETH across the superchain.
    /// @param _to The address of the receiver of the ETH token on the destination chain.
    /// @param _amount The amount of the ETH token to send.
    /// @param _chainId The chain id of the destination chain.
    /// @return msgHash_ The unique hash used to identify the message in the L2ToL2CrossDomainMessenger.
    function crossSendETH(address _to, uint256 _amount, uint256 _chainId) internal returns (bytes32 msgHash_) {
        return ISuperchainWETH(SUPERCHAIN_WETH).sendETH{value: _amount}(_to, _chainId);
    }

    /// @notice Send a message across the superchain.
    /// @param _chainId The chain id of the destination chain.
    /// @param _target The address of the receiver of the message on the destination chain.
    /// @param _message The message to send.
    /// @return msgHash_ The unique hash used to identify the message in the L2ToL2CrossDomainMessenger.
    function crossSendMessage(uint256 _chainId, address _target, bytes memory _message)
        internal
        returns (bytes32 msgHash_)
    {
        return IL2ToL2CrossDomainMessenger(L2_TO_L2_CROSS_DOMAIN_MESSENGER).sendMessage(_chainId, _target, _message);
    }

    /// @notice Verifies that `_from` bridged `_amount` amount of `_token` to `_to` from `_source` chain to this chain and it was relayed via the L2ToL2CrossDomainMessenger with nonce `_nonce`.
    /// @dev    It is expected that any inheriting contract marks hashes/nonces that has been used to successfully verify a deposit to prevent double spending.
    /// @dev    The same way it can lead to theft of funds when a user controlled address is inputted as the `_from` address in the ERC20's transferFrom function,
    ///         it can also lead to theft of funds when a user controlled address is inputted as the `_from` address in the `verifyERC20Deposit` function.
    ///         Only allow _from as a user controllable input if you know what you are doing or/and the action still benefits the _from address and not msg.sender
    /// @dev    Ideally, the only user controlled parameter here should be `_nonce` since we cannot determine it.
    ///
    /// @param _source The source chain id of the deposit.
    /// @param _token The token address of the deposit.
    /// @param _from The address of the sender of the deposit.
    /// @param _to The address of the receiver of the deposit.
    /// @param _amount The amount of the deposit.
    /// @param _nonce The nonce that the L2ToL2CrossDomainMessenger used in relaying the deposit.
    function verifyERC20Deposit(
        uint256 _source,
        address _token,
        address _from,
        address _to,
        uint256 _amount,
        uint256 _nonce
    ) internal view returns (bytes32 hash_) {
        hash_ = _verifyDeposit(
            _source,
            SUPERCHAIN_TOKEN_BRIDGE,
            SUPERCHAIN_TOKEN_BRIDGE,
            abi.encodeCall(ISuperchainTokenBridge.relayERC20, (_token, _from, _to, _amount)),
            _nonce
        );
    }

    /// @notice Verifies that `_from` bridged `_amount` amount of SuperchainWETH to `_to` from `_source` chain to this chain and it was relayed via the L2ToL2CrossDomainMessenger with nonce `_nonce`.
    /// @dev    It is expected that any inheriting contract marks hashes/nonces that has been used to successfully verify a deposit to prevent double spending.
    /// @dev    The same way it can lead to theft of funds when a user controlled address is inputted as the `_from` address in the ERC20's transferFrom function,
    ///         it can also lead to theft of funds when a user controlled address is inputted as the `_from` address in the `verifyERC20Deposit` function.
    ///         Only allow _from as a user controllable input if you know what you are doing or/and the action still benefits the _from address and not msg.sender
    /// @dev    Ideally, the only user controlled parameter here should be `_nonce` since we cannot determine it.
    ///
    /// @param _source The source chain id of the deposit.
    /// @param _from The address of the sender of the deposit.
    /// @param _to The address of the receiver of the deposit.
    /// @param _amount The amount of the deposit.
    /// @param _nonce The nonce that the L2ToL2CrossDomainMessenger used in relaying the deposit.
    function verifyETHDeposit(uint256 _source, address _from, address _to, uint256 _amount, uint256 _nonce)
        internal
        view
        returns (bytes32 hash_)
    {
        hash_ = _verifyDeposit(
            _source,
            SUPERCHAIN_WETH,
            SUPERCHAIN_WETH,
            abi.encodeCall(ISuperchainWETH.relayETH, (_from, _to, _amount)),
            _nonce
        );
    }

    /// @notice Verifies that `_sender` sent `_message` cross L2 to `_target` from `_source` chain to this chain and it was relayed via the L2ToL2CrossDomainMessenger with nonce `_nonce`.
    /// @dev    It is expected that any inheriting contract marks hashes/nonces that has been used to successfully verify a deposit to prevent double spending.
    /// @dev    Ideally, the only user controlled parameter here should be `_nonce` since we cannot determine it.
    ///
    /// @param _source The source chain id of the L2<->L2 message.
    /// @param _sender The address of the sender of the L2<->L2 message.
    /// @param _target The address of the receiver of the L2<->L2 message.
    /// @param _message The message to be relayed.
    /// @param _nonce The nonce that the L2ToL2CrossDomainMessenger used in relaying the message.
    function _verifyDeposit(uint256 _source, address _sender, address _target, bytes memory _message, uint256 _nonce)
        private
        view
        returns (bytes32 hash_)
    {
        // Calculate the hash of the message.
        hash_ = keccak256(
            abi.encode(
                block.chainid, // destination chain id
                _source, // source chain id
                _nonce, // nonce
                _sender, // sender
                _target, // target
                _message // message
            )
        );

        // This can be replayed, so it is advised to also keep a local track of successful messages or nonces that has been consumed,
        // and revert if the same hash is used more than once.
        if (!IL2ToL2CrossDomainMessenger(L2_TO_L2_CROSS_DOMAIN_MESSENGER).successfulMessages(hash_)) {
            revert MessageHashNotRelayed();
        }
    }
}
