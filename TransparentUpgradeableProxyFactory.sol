// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

import "@thirdweb-dev/contracts/extension/interface/IContractFactory.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Address.sol";
contract TransparentUpgradeableProxyFactory is IContractFactory {

    ProxyAdmin public upgradeAdmin;

    event ProxyDeployed(address indexed implementation, address proxy, address indexed deployer);

    constructor(ProxyAdmin _admin) {
        upgradeAdmin = _admin;
    }

    function deployProxyByImplementation(
        address _implementation,
        bytes memory _data,
        bytes32 salt
    ) public override returns (address deployedProxy) {

        deployedProxy = address(new TransparentUpgradeableProxy{salt: salt}(_implementation, address(upgradeAdmin), _data));
        emit ProxyDeployed(_implementation, deployedProxy, msg.sender);
    }

}