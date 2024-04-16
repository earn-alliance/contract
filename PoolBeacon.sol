// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

contract PoolBeacon is UpgradeableBeacon {
    constructor(address _defaultAdmin, address _impl) UpgradeableBeacon(_impl) {
        _transferOwnership(_defaultAdmin);
    }
}