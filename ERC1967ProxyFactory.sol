// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

import "@thirdweb-dev/contracts/extension/interface/IContractFactory.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Address.sol";
contract ERC1967ProxyFactory is IContractFactory {

    event ProxyDeployed(address indexed implementation, address proxy, address indexed deployer);

    constructor() {}

    function deployProxyByImplementation(
        address _implementation,
        bytes memory _data,
        bytes32 salt
    ) public override returns (address deployedProxy) {

        deployedProxy = address(new ERC1967Proxy{salt: salt}(_implementation, _data));
        emit ProxyDeployed(_implementation, deployedProxy, msg.sender);
    }

}