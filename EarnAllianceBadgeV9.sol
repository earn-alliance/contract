// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";

struct BadgeMintTimeboundRequest {
    uint256 tokenId;
    uint256 amount;
    address toAddress;
    uint256 validUntil;
}
struct BadgeMintDynamicSupplyTimeboundRequest {
    uint256 tid;
    uint256 amt;
    address to;
    bytes32 uid;
    uint256 start;
    uint256 until;
    uint256 supply;
    string  url;
    
}

/// @title Earn Alliance MetaBadge Contract
/// @author Earn Alliance, Elliott Williams, Ho Chi Ho
/// @notice This contract mints various badges from the Earn Alliance Ecosystem that are soulbound
/// @dev Contract is liable to be updated without warning
/// @custom:security-contact security@earnalliance.com
contract EarnAllianceBadgeV9 is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ERC1155SupplyUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable
{
    address s_signer; // The Signer must be this address for the message payload for a successful mint

    mapping(uint256 => uint256) private _deprecated_tokenSupply;
    mapping(uint256 => uint256) public maxSupply;

    mapping(uint256 => string) private _uris;

    uint256 private allowedBalancePerToken;

    bytes32 private constant TIMEBOUNDTYPEHASH =
        keccak256("Badge(uint256 tokenId,uint256 amount,address toAddress,uint256 validUntil)");
    bytes32 private constant DYNAMIC_SUPPLY_TIMEBOUND_TYPEHASH =
        keccak256("Badge(uint256 tid,uint256 amt,address to,bytes32 uid,uint256 start,uint256 until,uint256 supply,string url)");

    mapping(bytes32 => bool) private usedUID;
    event MintDynamicSupplyTimebound(bytes32 indexed uid, BadgeMintDynamicSupplyTimeboundRequest input);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialization of contract, called upon deployment
    /// @dev implements EIP712, is upgradeable, pausable, burn function is custom to save space
    /// @param _signer this address will be used to sign all mints
    /// @param name name of the contract (EIP712 required)
    /// @param version version of the contract (EIP712 required)
    function initialize(
        address _signer,
        string memory name,
        string memory version
    ) public initializer {
        __ERC1155_init("");
        __Ownable_init();
        __Pausable_init();
        // __ERC1155Burnable_init();
        __ERC1155Supply_init();
        __UUPSUpgradeable_init();
        __EIP712_init(name, version);
        s_signer = _signer;
    }

    /// @notice set URI.  Where metadata and images will come from
    /// @param newuri the address that the owner would like the new URI to be
    function setURI(string memory newuri, uint256 tokenId) public onlyOwner {
        _setURI(newuri, tokenId);
    }

    function _setURI(string memory newuri, uint256 tokenId) internal virtual {
        _uris[tokenId] = newuri;
    }


    function uri(uint256 tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        return _uris[tokenId];
    }

    /// @notice contractURI, OpenSea compliant metadata standard for Badge Collections
    /// @return URI that holds the metadata for collection

    function contractURI() public pure returns (string memory) {
        return "https://cdn-ea.earnalliance.com/metadata/badges";
    }

    /// @notice pause any token transfers including mints and burns
    /// @dev can only be called by owner
    function pause() public onlyOwner {
        _pause();
    }

    /// @notice unpause any token transfers including mints and burns
    /// @dev can only be called by owner
    function unpause() public onlyOwner {
        _unpause();
    }

    /// @notice burn a badge, can only be called by owner
    /// @dev used custom call instead of inheritable to optimize contract size
    /// @param from what address's badge to burn
    /// @param id what the id of the badge to burn is
    /// @param amount how many to burn
    function badgeBurn(
        address from,
        uint256 id,
        uint256 amount
    ) public virtual onlyOwner {
        _burn(from, id, amount);
    }

    /// @notice Owner can set Max Supply for each badge
    /// @dev returns default value (0) if not set, owner only
    /// @param _id the tokenId of the badge to set supply
    /// @param _supply what to set the new supply as
    function setMaxSupply(uint256 _id, uint256 _supply) public onlyOwner {
        _setMaxSupply(_id, _supply);
    }
    function _setMaxSupply(uint256 _id, uint256 _supply) internal {
        maxSupply[_id] = _supply;
    }

    /// @notice Owner can set Max Supply for each badge
    /// @dev returns default value (0) if not set, owner only
    /// @param _id the tokenId of the badge to set supply
    /// @param _supply what to set the new supply as
    // function setMaxSupply(uint256 _id, uint256 _supply) public onlyOwner {
    //     maxSupply[_id] = _supply;
    // }

    /// @notice Mint an EA Badge, dependent on signature approval and choice of tokenId
    /// @dev param details: https://ethereum.stackexchange.com/a/118415/68000
    /// @param input Interface for tokenId, amount, address
    /// @param r the x-coordinate of a random curve point
    /// @param s signature proof for r
    /// @param v recovery parameter
    function badgeMintTimebound(
        BadgeMintTimeboundRequest calldata input,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        uint256 t = input.tokenId;
        address a = input.toAddress;

        require(verifyTimebound(input, r, s, v), "!sig");
        require(totalSupply(t) < maxSupply[t], "!sup");
        require(balanceOf(input.toAddress, t) < allowedBalancePerToken, "!rep");
        require(input.validUntil > block.timestamp, "!time");

        _mint(a, t, input.amount, bytes("0x"));
    }

    /// @notice Mint an EA Badge, dependent on signature approval and choice of tokenId
    /// @dev param details: https://ethereum.stackexchange.com/a/118415/68000
    /// @param input Interface for tokenId, amount, address
    /// @param r the x-coordinate of a random curve point
    /// @param s signature proof for r
    /// @param v recovery parameter
    function badgeMintDynamicSupplyTimebound(
        BadgeMintDynamicSupplyTimeboundRequest calldata input,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external {
        uint256 t = input.tid;
        address a = input.to;
        // 
        require(input.start <= block.timestamp, "!time");
        require(input.until > block.timestamp, "!time");
        require(!usedUID[input.uid], "!uid");
        require(verifyDynamicSupplyTimebound(input, r, s, v), "!sig");
        _setMaxSupply(t, input.supply);
        _setURI(input.url, t);
        require(totalSupply(t) < maxSupply[t], "!sup");
        require(balanceOf(input.to, t) < allowedBalancePerToken, "!rep");

        _mint(a, t, input.amt, bytes("0x"));
        usedUID[input.uid] = true;
        emit MintDynamicSupplyTimebound(input.uid, input);
    }



    /// @notice Airdrop an EA Badge, dependent on signature approval and choice of tokenId
    /// @dev This is an unbounded loop so be careful not to send to many addresses
    /// @dev gas cost difference should be minor
    /// @param lessThan100AirdropAddresses Interface for tokenId, amount, address
    function badgeAirdropMint(
        address[] memory lessThan100AirdropAddresses,
        uint256 tokenId
    ) external onlyOwner {
        // require whole batch to be mintable without hitting supply limit.
        require(
            (totalSupply(tokenId) + lessThan100AirdropAddresses.length) <
                maxSupply[tokenId],
            "!sup"
        );

        // WARN: This is an anti-pattern, owner need limit addresses sent due to gas limit
        for (uint256 i = 0; i < lessThan100AirdropAddresses.length; i++) {
            if (balanceOf(lessThan100AirdropAddresses[i], tokenId) >= 1) {
                // No Repeats! Skip to next iteration
                continue;
            }

            // Airdrop to address
            _mint(lessThan100AirdropAddresses[i], tokenId, 1, bytes("0x"));
        }
    }

    function verifyTimebound(
        BadgeMintTimeboundRequest calldata badgeMintRequest,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) private view returns (bool) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    TIMEBOUNDTYPEHASH,
                    badgeMintRequest.tokenId,
                    badgeMintRequest.amount,
                    badgeMintRequest.toAddress,
                    badgeMintRequest.validUntil
                )
            )
        );
        // address signer = digest.recover(x.v, x.r, x.s);

        return ecrecover(digest, v, r, s) == s_signer;
    }
    function verifyDynamicSupplyTimebound(
        BadgeMintDynamicSupplyTimeboundRequest calldata req,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) private view returns (bool) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    DYNAMIC_SUPPLY_TIMEBOUND_TYPEHASH,
                    req.tid,
                    req.amt,
                    req.to,
                    req.uid,
                    req.start,
                    req.until,
                    req.supply,
                    keccak256(abi.encodePacked(req.url))
                )
            )
        );

        return ecrecover(digest, v, r, s) == s_signer;
    }

    /// @notice soulbound badges are only able to be transfered by the owner of the contract
    /// @param from from which address shall the badge be sent
    /// @param to send badge to what address
    /// @param id tokenId of the badge to send
    /// @param amount amount of badges to send (should always be 1 due to minting constraints)
    /// @param data any data to go along with txn
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public override {
        require(msg.sender == s_signer, "soulbound");
        _safeTransferFrom(from, to, id, amount, data);
    }

    /// @notice soulbound badges are only able to be batch transfered by the owner of the contract
    /// @param from from which address shall the badge be sent
    /// @param to send badge to what address
    /// @param ids array of tokenIds of the badges to be send
    /// @param amounts amounts of respective badges to send (each should always be 1 due to minting constraints)
    /// @param data any data to go along with txns
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public override {
        require(msg.sender == s_signer, "soulbound");
        _safeBatchTransferFrom(from, to, ids, amounts, data);
    }

    /// @notice hook called before transfer of any type (mint, burn, transfer, etc)
    /// @dev when paused transfers of all kinds are not allowed
    /// @param operator operator of function
    /// @param from from which address shall the badge be sent
    /// @param to send badge to what address
    /// @param ids tokenId of the badges to send
    /// @param amounts amount of badges to send (should always be 1 due to minting constraints)
    /// @param data any data to go along with txns
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {}

    function setAllowedBalancePerToken(uint256 _input) external onlyOwner {
        allowedBalancePerToken = _input;
    }
}
