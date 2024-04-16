// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

/// @author thirdweb

//   $$\     $$\       $$\                 $$\                         $$\
//   $$ |    $$ |      \__|                $$ |                        $$ |
// $$$$$$\   $$$$$$$\  $$\  $$$$$$\   $$$$$$$ |$$\  $$\  $$\  $$$$$$\  $$$$$$$\
// \_$$  _|  $$  __$$\ $$ |$$  __$$\ $$  __$$ |$$ | $$ | $$ |$$  __$$\ $$  __$$\
//   $$ |    $$ |  $$ |$$ |$$ |  \__|$$ /  $$ |$$ | $$ | $$ |$$$$$$$$ |$$ |  $$ |
//   $$ |$$\ $$ |  $$ |$$ |$$ |      $$ |  $$ |$$ | $$ | $$ |$$   ____|$$ |  $$ |
//   \$$$$  |$$ |  $$ |$$ |$$ |      \$$$$$$$ |\$$$$$\$$$$  |\$$$$$$$\ $$$$$$$  |
//    \____/ \__|  \__|\__|\__|       \_______| \_____\____/  \_______|\_______/

//  ==========  External imports    ==========

import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155PausableUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/interfaces/IERC2981Upgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import { IERC1155Receiver } from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";

//  ==========  Internal imports    ==========

import "@thirdweb-dev/contracts/external-deps/openzeppelin/metatx/ERC2771ContextUpgradeable.sol";

//  ==========  Features    ==========

import "@thirdweb-dev/contracts/extension/ContractMetadata.sol";
import "@thirdweb-dev/contracts/extension/Ownable.sol";
import "@thirdweb-dev/contracts/extension/PermissionsEnumerable.sol";
import { ERC1155Receiver } from "@thirdweb-dev/contracts/extension/TokenStore.sol";

import "../interfaces/IContractOpenablePack721.sol";
contract ContractOpenablePack721 is
    Initializable,
    ContractMetadata,
    Ownable,
    PermissionsEnumerable,
    ReentrancyGuardUpgradeable,
    ERC1155Upgradeable,
    UUPSUpgradeable,
    IContractOpenablePack721
{
    /*///////////////////////////////////////////////////////////////
                            State variables
    //////////////////////////////////////////////////////////////*/
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.UintSet;
    bytes32 private constant MODULE_TYPE = bytes32("Pack");
    uint256 private constant VERSION = 2;
    // Token name
    string public name;

    // Token symbol
    string public symbol;

    /// @dev Only transfers to or from TRANSFER_ROLE holders are valid, when transfers are restricted.
    bytes32 private transferRole;

    /// @dev Only MINTER_ROLE holders can create packs.
    bytes32 private minterRole;

    /// @dev Only assets with ASSET_ROLE can be packed, when packing is restricted to particular assets.
    bytes32 private assetRole;
    
    
    /// @dev Only assets with RELEASE_ROLE can burn pack and withdraw all escrowed asset.
    bytes32 private releaseRole;

    /// @dev The token Id of the next set of packs to be minted.
    // uint256 public nextTokenIdToMint;

    /*///////////////////////////////////////////////////////////////
                             Mappings
    //////////////////////////////////////////////////////////////*/

    /// @dev Mapping from token ID => total circulating supply of token with that ID.
    mapping(uint256 => uint256) public totalSupply;

    /// @dev Mapping from pack ID => The state of that set of packs.
    mapping(uint256 => PackInfo) private packInfo;

    /// @dev Checks if pack-creator allowed to add more tokens to a packId; set to false after first transfer
    mapping(uint256 => bool) public canUpdatePack;

    mapping(uint256 => bool) public created;

    mapping(uint256 => EnumerableSetUpgradeable.UintSet) private packTokens;

    /*///////////////////////////////////////////////////////////////
                    Constructor + initializer logic
    //////////////////////////////////////////////////////////////*/

    constructor() initializer {}

    /// @dev Initiliazes the contract, like a constructor.
    function initialize(
        address _defaultAdmin,
        string memory _name,
        string memory _symbol
    ) external initializer {
        bytes32 _transferRole = keccak256("TRANSFER_ROLE");
        bytes32 _minterRole = keccak256("MINTER_ROLE");
        bytes32 _assetRole = keccak256("ASSET_ROLE");
        bytes32 _releaseRole = keccak256("RELEASE_ROLE");
        __ERC1155_init("");

        name = _name;
        symbol = _symbol;

        _setupContractURI("");
        _setupOwner(_defaultAdmin);
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _setupRole(_transferRole, _defaultAdmin);
        // _setupRole(_minterRole, _defaultAdmin);
        _setupRole(_transferRole, address(0));

        // note: see `onlyRoleWithSwitch` for ASSET_ROLE behaviour.
        _setupRole(_assetRole, address(0));

        _setRoleAdmin(_minterRole, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(_releaseRole, DEFAULT_ADMIN_ROLE);


        transferRole = _transferRole;
        minterRole = _minterRole;
        releaseRole = _releaseRole;
        assetRole = _assetRole;
    }

    /*///////////////////////////////////////////////////////////////
                            Modifiers
    //////////////////////////////////////////////////////////////*/

    modifier onlyRoleWithSwitch(bytes32 role) {
        _checkRoleWithSwitch(role, _msgSender());
        _;
    }

    /*///////////////////////////////////////////////////////////////
                        Generic contract logic
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the type of the contract.
    function contractType() external pure returns (bytes32) {
        return MODULE_TYPE;
    }

    /// @dev Returns the version of the contract.
    function contractVersion() external pure returns (uint8) {
        return uint8(VERSION);
    }

    /*///////////////////////////////////////////////////////////////
                        ERC 165 / 1155 / 2981 logic
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the URI for a given tokenId.
    function uri(uint256) public pure override returns (string memory) {
        return "";
    }

    /// @dev See ERC 165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC1155Upgradeable, IERC165Upgradeable )
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /*///////////////////////////////////////////////////////////////
                    Pack logic: create | open packs.
    //////////////////////////////////////////////////////////////*/

    /// @dev Creates a pack with the stated contents.
    function createPack(
        IERC721Upgradeable _contractAddress,
        uint256 packId,
        uint256[] calldata _tokenIds,
        uint128 _openStartTimestamp,
        uint128 _amountDistributedPerOpen,
        address _recipient
    ) external payable onlyRoleWithSwitch(minterRole) nonReentrant returns (uint256 packTotalSupply) {
        require(_tokenIds.length > 0, "!Len");
        require(!created[packId], "!created");

        // if (!hasRole(assetRole, address(0))) {
        //     for (uint256 i = 0; i < _contents.length; i += 1) {
        //         _checkRole(assetRole, _contents[i].assetContract);
        //     }
        // }
        packTotalSupply = createOrAddERC721Bundle(
            _contractAddress,
            _tokenIds,
            packId,
            _amountDistributedPerOpen,
            false
        );

        packInfo[packId].openStartTimestamp = _openStartTimestamp;
        packInfo[packId].amountDistributedPerOpen = _amountDistributedPerOpen;

        canUpdatePack[packId] = true;
        created[packId] = true;

        _mint(_recipient, packId, packTotalSupply, "");

        emit PackCreated(packId, _recipient, packTotalSupply);
        return packTotalSupply;
    }

    /// @dev Add contents to an existing packId.
    function addPackContents(
        IERC721Upgradeable _contractAddress,
        uint256 _packId,
        uint256[] calldata _tokenIds,
        address _recipient
    )
        external
        payable
        onlyRoleWithSwitch(minterRole)
        nonReentrant
        returns (uint256 packTotalSupply, uint256 newSupplyAdded)
    {
        require(canUpdatePack[_packId], "!Allowed");
        require(_tokenIds.length > 0, "!Len");
        require(balanceOf(_recipient, _packId) != 0, "!Bal");

        // if (!hasRole(assetRole, address(0))) {
        //     for (uint256 i = 0; i < _contents.length; i += 1) {
        //         _checkRole(assetRole, _contents[i].assetContract);
        //     }
        // }

        uint256 amountPerOpen = packInfo[_packId].amountDistributedPerOpen;
        newSupplyAdded = createOrAddERC721Bundle(_contractAddress, _tokenIds, _packId, amountPerOpen, true);
        packTotalSupply = totalSupply[_packId] + newSupplyAdded;

        _mint(_recipient, _packId, newSupplyAdded, "");

        emit PackUpdated(_packId, _recipient, newSupplyAdded);
    }

    /// @notice Lets a pack owner open packs and receive the packs' reward units.
    function openPack(uint256 _packId, uint256 _amountToOpen, address recipient) external returns (uint256[] memory rewardTokenIds, PackInfo memory pack) {
        address opener = _msgSender();

        require(balanceOf(opener, _packId) >= _amountToOpen, "!Bal");

        pack = packInfo[_packId];
        require(pack.openStartTimestamp <= block.timestamp, "cant open");

        rewardTokenIds = getRewardUnits(_packId, _amountToOpen, pack.amountDistributedPerOpen, recipient);

        _burn(opener, _packId, _amountToOpen);

        emit PackOpened(rewardTokenIds, _packId, recipient, _amountToOpen);
    }

    /// @dev Stores assets within the contract.
    function createOrAddERC721Bundle(
        IERC721Upgradeable contractAddress,
        uint256[] calldata _tokenIds,
        uint256 packId,
        uint256 amountPerOpen,
        bool isUpdate
    ) internal returns (uint256 supplyToMint) {
        uint256 sumOfRewardUnits = _tokenIds.length;
        require(sumOfRewardUnits != 0, "0 amt");
        packInfo[packId].contractAddress = contractAddress;

        require(sumOfRewardUnits % amountPerOpen == 0, "!Amt");
        supplyToMint = sumOfRewardUnits / amountPerOpen;

        if (isUpdate) {
            _addTokenInBundle(_tokenIds, packId);
        } else {
            _createBundle(_tokenIds, packId);
        }
    }

    function setCanUpdatePack(uint256 _packId, bool _bool) external onlyRole(DEFAULT_ADMIN_ROLE) {
        canUpdatePack[_packId] = _bool;
    }

    function updateTokenIdsInBundle(
        uint256 packId,
        uint256[] calldata _tokenIdsToAdd,
        uint256[] calldata _tokenIdsToRemove
    ) external onlyOwner {
        _addTokenInBundle(_tokenIdsToAdd, packId);
        _removeTokenInBundle(_tokenIdsToRemove, packId);
    }

    function _createBundle(uint256[] calldata _tokenIds, uint256 packId) internal {
        _addTokenInBundle(_tokenIds, packId);
    }
    function _addTokenInBundle(uint256[] calldata _tokenIds, uint256 packId) internal {
        uint256 len = _tokenIds.length;

        for (uint256 i = 0; i < len; i++) {
            packTokens[packId].add(_tokenIds[i]);
        }

    }
    function _removeTokenInBundle(uint256[] calldata _tokenIds, uint256 packId) internal {
        uint256 len = _tokenIds.length;

        for (uint256 i = 0; i < len; i++) {
            packTokens[packId].remove(_tokenIds[i]);
        }
    }

    function getTokenCountOfBundle(uint256 _packId) public view returns(uint256) {
        return packTokens[_packId].length();
    }


    /// @dev Returns the reward units to distribute.
    function getRewardUnits(
        uint256 _packId,
        uint256 _numOfPacksToOpen,
        uint256 _tokensPerOpen,
        address recipient
    ) internal returns (uint256[] memory rewardTokenIds) {
        uint256 numOfTokensToDistribute = _numOfPacksToOpen * _tokensPerOpen;
        rewardTokenIds = new uint256[](numOfTokensToDistribute);
        uint256 random = generateRandomValue(recipient);
        for (uint256 i = 0; i < numOfTokensToDistribute; i += 1) {
            uint256 randomVal = uint256(keccak256(abi.encode(random, i)));

            uint256 totalRewardUnits = packTokens[_packId].length();
            uint256 target = randomVal % totalRewardUnits;

            uint256 _tokenId = packTokens[_packId].at(target);
            packTokens[_packId].remove(_tokenId);
            rewardTokenIds[i] = _tokenId;
        }
    }

    /*///////////////////////////////////////////////////////////////
                        Getter functions
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the underlying contents of a pack.
    function getPackContents(uint256 _packId)
        public
        view
        returns (uint256[] memory contents)
    {
        return packTokens[_packId].values();
    }

    /*///////////////////////////////////////////////////////////////
                        Internal functions
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns whether owner can be set in the given execution context.
    function _canSetOwner() internal view override returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /// @dev Returns whether contract metadata can be set in the given execution context.
    function _canSetContractURI() internal view override returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /*///////////////////////////////////////////////////////////////
                        Miscellaneous
    //////////////////////////////////////////////////////////////*/

    function generateRandomValue(address recipient) internal view returns (uint256 random) {
        random = uint256(keccak256(abi.encodePacked(recipient, blockhash(block.number - 1), block.difficulty)));
    }

    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        // if transfer is restricted on the contract, we still want to allow burning and minting
        if (!hasRole(transferRole, address(0)) && from != address(0) && to != address(0)) {
            require(hasRole(transferRole, from) || hasRole(transferRole, to), "!TRANSFER_ROLE");
        }

        if (from == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                totalSupply[ids[i]] += amounts[i];
            }
        } else {
            for (uint256 i = 0; i < ids.length; ++i) {
                // pack can no longer be updated after first transfer from non-zero address
                if (canUpdatePack[ids[i]] && amounts[i] != 0) {
                    canUpdatePack[ids[i]] = false;
                }
            }
        }

        if (to == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                totalSupply[ids[i]] -= amounts[i];
            }
        }
    }

    function burnPack(uint256 _packId) external onlyRole(releaseRole) {
        delete packInfo[_packId];
        canUpdatePack[_packId] = false;
        // burn msg sender's balance
        uint256 b = balanceOf(_msgSender(), _packId);
        _burn(_msgSender(), _packId, b);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

}
