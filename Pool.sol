// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";

import "../interfaces/IPool.sol";
import "../interfaces/IContractOpenablePack.sol";

contract Pool is Initializable, AccessControlEnumerableUpgradeable, MulticallUpgradeable, IPool {
    bytes32 private constant OPENER_ROLE = keccak256("OPENER_ROLE");
    uint256 public poolId;

    // deprecated
    uint128 private openStartTimestamp;
    // deprecated
    uint128 private amountDistributedPerOpen;
    // deprecated
    IPoolFactory private factory;
    // deprecated
    IContractOpenablePack private packContract;


    function initialize(address _defaultAdmin, uint256 _poolId, address _factory) public initializer {
        poolId = _poolId;
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _grantRole(OPENER_ROLE, address(_factory));
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControlEnumerableUpgradeable, IERC165Upgradeable) returns(bool) {
        return interfaceId == type(IERC721ReceiverUpgradeable).interfaceId || interfaceId == type(IERC1155ReceiverUpgradeable).interfaceId || AccessControlEnumerableUpgradeable.supportsInterface(interfaceId);
    }

    function onERC721Received(
        address ,
        address ,
        uint256 ,
        bytes calldata 
    ) external pure returns (bytes4) {
        return IERC721ReceiverUpgradeable.onERC721Received.selector;
    }

    function onERC1155Received(
        address ,
        address ,
        uint256 ,
        uint256 ,
        bytes calldata 
    ) external pure returns (bytes4) {
        return IERC1155ReceiverUpgradeable.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address ,
        address ,
        uint256[] calldata ,
        uint256[] calldata ,
        bytes calldata 
    ) external pure returns (bytes4) {
        return IERC1155ReceiverUpgradeable.onERC1155BatchReceived.selector;

    }

    function transferTokens(ITokenBundle.Token[] calldata token, address recipient) external onlyRole(OPENER_ROLE) {
        uint256 len = token.length;
        require(recipient != address(0), '0addr');
        require(len <= 50, '<50');
        for (uint i = 0; i < len; i++) {
            ITokenBundle.Token calldata t = token[i];
            if (t.tokenType == ITokenBundle.TokenType.ERC1155) {
                IERC1155Upgradeable(t.assetContract).safeTransferFrom(address(this), recipient, t.tokenId, t.totalAmount, bytes(""));
            }
            else if (t.tokenType == ITokenBundle.TokenType.ERC721) {
                IERC721Upgradeable(t.assetContract).safeTransferFrom(address(this), recipient, t.tokenId);
            }
            else if (t.tokenType == ITokenBundle.TokenType.ERC20) {
                IERC20Upgradeable(t.assetContract).transfer(recipient, t.totalAmount);
            }
            else {
                revert("!type");
            }
        }
    }
    function transferERC721Tokens(IERC721Upgradeable assetContract, uint256[] calldata tokenIds, address recipient) external onlyRole(OPENER_ROLE) {
        uint256 len = tokenIds.length;
        require(recipient != address(0), '0addr');
        // require(len <= 50, '<50');
        for (uint i = 0; i < len; i++) {
            assetContract.safeTransferFrom(address(this), recipient, tokenIds[i]);
        }
    }

}