// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SuperchainLibrary} from "src/SuperchainLibrary.sol";

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract Deposit {
    address public immutable TOKEN;

    mapping(bytes32 => bool) public successfulMessages;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        TOKEN = _token;
    }

    /// @dev Notice that we use `sender` variable if it is a cross L2 message, and `msg.sender` if it is not.
    ///      The same way that using a
    function depositERC20(uint256 _amount, uint256 _nonce) public {
        if (SuperchainLibrary.isCrossL2Message()) {
            (address sender, uint256 source) = SuperchainLibrary.msgSenderAndSource();
            bytes32 hash = SuperchainLibrary.verifyERC20Deposit(source, TOKEN, sender, address(this), _amount, _nonce);
            successfulMessages[hash] = true;
            balances[sender] += _amount;
        } else {
            bool success = IERC20(TOKEN).transferFrom(msg.sender, address(this), _amount);
            require(success, "Transfer failed");
            balances[msg.sender] += _amount;
        }
    }
}
