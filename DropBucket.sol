// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.17;

import "./TimeboundEIP712UpgradeableWithParam.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155ReceiverUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract DropBucket is TimeboundEIP712UpgradeableWithParam, ReentrancyGuardUpgradeable, UUPSUpgradeable, IERC721ReceiverUpgradeable, IERC1155ReceiverUpgradeable {
    error UnknownTokenType(uint8 tokenType);
    error InvalidSigner(address signer, bytes32 role);

    struct TransferRequest {
        uint256 tokenId;
        address contractAddress;
        uint8 tokenType;
        uint88 amount;
        address to;
    }

    event TransferredToken(address indexed to, address indexed contractAddress, TransferRequest req);

    bytes32 private constant TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    uint8 private constant TOKEN_TYPE_ERC721 = 0;
    uint8 private constant TOKEN_TYPE_ERC1155 = 1;
    uint256 public bucketId;

    function initialize(
        address _defaultAdmin,
        address _tranferrer,
        string memory _name,
        string memory _version,
        uint256 _bucketId
    ) public initializer {
        __TimeboundEIP712UpgradeableWithParam_init(_name, _version);
        __ReentrancyGuard_init();
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _grantRole(TRANSFER_ROLE, _tranferrer);
        bucketId = _bucketId;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

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

    function adminTransferToken(TransferRequest[] memory treq) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        for (uint i = 0; i < treq.length; i++) {
            if (treq[i].tokenType == TOKEN_TYPE_ERC721) {
                _transferERC721(treq[i]);
                emit TransferredToken(treq[i].to, treq[i].contractAddress, treq[i]);
                continue;
            }
            if (treq[i].tokenType == TOKEN_TYPE_ERC1155) {
                _transferERC1155(treq[i]);
                emit TransferredToken(treq[i].to, treq[i].contractAddress, treq[i]);
                continue;
            }
            revert UnknownTokenType(treq[i].tokenType);
        }
    }

    function transferTokens(RequestWithParam calldata _req, bytes calldata _sig) external nonReentrant {
        address signer = _recoverAddress(_req, _sig);
        if(!hasRole(TRANSFER_ROLE, signer)) {
            revert InvalidSigner(signer, TRANSFER_ROLE);
        }
        _processRequest(_req);
        (TransferRequest[] memory treq) = abi.decode(_req.param, (TransferRequest[]));
        for (uint i = 0; i < treq.length; i++) {
            if (treq[i].tokenType == TOKEN_TYPE_ERC721) {
                _transferERC721(treq[i]);
                emit TransferredToken(treq[i].to, treq[i].contractAddress, treq[i]);
                continue;
            }
            if (treq[i].tokenType == TOKEN_TYPE_ERC1155) {
                _transferERC1155(treq[i]);
                emit TransferredToken(treq[i].to, treq[i].contractAddress, treq[i]);
                continue;
            }
            revert UnknownTokenType(treq[i].tokenType);
        }
    }

    function _transferERC721(TransferRequest memory _req) internal {
        IERC721Upgradeable nftContract = IERC721Upgradeable(_req.contractAddress);
        return nftContract.safeTransferFrom(address(this), _req.to, _req.tokenId);
    }
    function _transferERC1155(TransferRequest memory _req) internal {
        IERC1155Upgradeable nftContract = IERC1155Upgradeable(_req.contractAddress);

        return nftContract.safeTransferFrom(address(this), _req.to, _req.tokenId, _req.amount, "");
    }

}