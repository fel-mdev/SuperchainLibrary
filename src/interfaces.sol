// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IL2ToL2CrossDomainMessenger {
    function crossDomainContext() external view returns (address, uint256);
    function crossDomainMessageSender() external view returns (address);
    function crossDomainMessageSource() external view returns (uint256);
    function successfulMessages(bytes32 hash) external view returns (bool);
}

interface ISuperchainTokenBridge {
    function relayERC20(address _token, address _from, address _to, uint256 _amount) external;
}

interface ISuperchainWETH {
    function relayETH(address _from, address _to, uint256 _amount) external;
}

interface ICrossL2Inbox {
    function validateMessage(Identifier memory _identifier, bytes memory _message) external;
}

struct Identifier {
    address origin;
    uint256 blockNumber;
    uint256 logIndex;
    uint256 timestamp;
    uint256 chainId;
}
