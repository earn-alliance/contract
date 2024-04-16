// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

// Interface
import "@thirdweb-dev/contracts/infra/interface/IThirdwebContract.sol";
import "@thirdweb-dev/contracts/extension/interface/IPlatformFee.sol";
import "@thirdweb-dev/contracts/extension/interface/IPrimarySale.sol";
import "@thirdweb-dev/contracts/extension/interface/IRoyalty.sol";
import "@thirdweb-dev/contracts/extension/interface/IOwnable.sol";

// Token
import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";

// Access Control + security
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

// Utils
import "@thirdweb-dev/contracts/lib/CurrencyTransferLib.sol";
import "@thirdweb-dev/contracts/lib/FeeType.sol";
import "@thirdweb-dev/contracts/external-deps/openzeppelin/metatx/ERC2771ContextUpgradeable.sol";

// Helper interfaces
import "@openzeppelin/contracts-upgradeable/interfaces/IERC2981Upgradeable.sol";

// OpenSea operator filter
import "@thirdweb-dev/contracts/extension/DefaultOperatorFiltererUpgradeable.sol";

import "./TimeboundEIP712Upgradeable.sol";
import "../interfaces/ISignatureMintERC1155.sol";

contract SignatureMintWithParamsERC1155 is
    Initializable,
    IThirdwebContract,
    IOwnable,
    IRoyalty,
    IPrimarySale,
    IPlatformFee,
    ReentrancyGuardUpgradeable,
    ERC2771ContextUpgradeable,
    AccessControlEnumerableUpgradeable,
    DefaultOperatorFiltererUpgradeable,
    ERC1155Upgradeable,
    TimeboundEIP712Upgradeable,
    ISignatureMintERC1155
{
    bytes32 internal constant TYPEHASH =
        keccak256(abi.encodePacked(
            "MintRequestWithParam(BaseRequest baseRequest,uint256 tokenId,uint256 pricePerToken,uint256 quantity,address to,address currency,bytes param)",
            BASEREQUESTTYPE
        ));

    bytes32 private constant MODULE_TYPE = bytes32("TokenERC1155");
    uint256 private constant VERSION = 1;

    // Token name
    string public name;

    // Token symbol
    string public symbol;

    /// @dev Only TRANSFER_ROLE holders can have tokens transferred from or to them, during restricted transfers.
    bytes32 private constant TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    /// @dev Only MINTER_ROLE holders can sign off on `MintRequest`s.
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");

    /// @dev Max bps in the thirdweb system
    uint256 internal constant MAX_BPS = 10_000;

    /// @dev Owner of the contract (purpose: OpenSea compatibility, etc.)
    address private _owner;

    /// @dev The adress that receives all primary sales value.
    address public primarySaleRecipient;

    /// @dev The adress that receives all primary sales value.
    address public platformFeeRecipient;

    /// @dev The recipient of who gets the royalty.
    address private royaltyRecipient;

    /// @dev The percentage of royalty how much royalty in basis points.
    uint128 private royaltyBps;

    /// @dev The % of primary sales collected by the contract as fees.
    uint128 internal platformFeeBps;

    /// @dev The flat amount collected by the contract as fees on primary sales.
    uint256 internal flatPlatformFee;

    /// @dev Fee type variants: percentage fee and flat fee
    PlatformFeeType internal platformFeeType;

    /// @dev Contract level metadata.
    string public contractURI;

    /// @dev Mapping from mint request UID => whether the mint request is processed.
    mapping(bytes32 => bool) private minted;

    mapping(uint256 => string) private _tokenURI;

    /// @dev Token ID => total circulating supply of tokens with that ID.
    mapping(uint256 => uint256) public totalSupply;

    /// @dev Token ID => the address of the recipient of primary sales.
    mapping(uint256 => address) public saleRecipientForToken;

    /// @dev Token ID => royalty recipient and bps for token
    mapping(uint256 => RoyaltyInfo) private royaltyInfoForToken;

    
    address private signerAddress;

    constructor() initializer {}

    /// @dev Initiliazes the contract, like a constructor.
    function initialize(
        address _defaultAdmin,
        string memory _domainName,
        string memory _name,
        string memory _symbol,
        string memory _contractURI,
        address[] memory _trustedForwarders,
        address _primarySaleRecipient,
        address _royaltyRecipient,
        uint128 _royaltyBps,
        uint128 _platformFeeBps,
        address _platformFeeRecipient,
        address _signerAddress
    ) external initializer {
        // Initialize inherited contracts, most base-like -> most derived.
        __ReentrancyGuard_init();
        __TimeboundEIP712Upgradeable_init(_domainName, "1", _signerAddress);
        __ERC2771Context_init(_trustedForwarders);
        __ERC1155_init("");
        __DefaultOperatorFilterer_init();

        // Initialize this contract's state.
        _setOperatorRestriction(true);
        name = _name;
        symbol = _symbol;
        royaltyRecipient = _royaltyRecipient;
        royaltyBps = _royaltyBps;
        platformFeeRecipient = _platformFeeRecipient;
        primarySaleRecipient = _primarySaleRecipient;
        contractURI = _contractURI;

        require(_platformFeeBps <= MAX_BPS, "!");
        platformFeeBps = _platformFeeBps;

        // Fee type Bps by default
        platformFeeType = PlatformFeeType.Bps;

        _owner = _defaultAdmin;
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        _setupRole(TRANSFER_ROLE, _defaultAdmin);
        _setupRole(TRANSFER_ROLE, address(0));
        signerAddress = _signerAddress;
    }

    ///     =====   Public functions  =====

    /// @dev Returns the module type of the contract.
    function contractType() external pure returns (bytes32) {
        return MODULE_TYPE;
    }

    /// @dev Returns the version of the contract.
    function contractVersion() external pure returns (uint8) {
        return uint8(VERSION);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return hasRole(DEFAULT_ADMIN_ROLE, _owner) ? _owner : address(0);
    }

    /// @dev Returns the URI for a tokenId
    function uri(uint256 _tokenId) public view override returns (string memory) {
        return _tokenURI[_tokenId];
    }

    function setUri(uint256 _tokenId, string memory _uri) external {
        _tokenURI[_tokenId] = _uri;

    }

    /// @dev Lets an account with DEFAULT_ADMIN_ROLE mint an NFT.
    function mintTo(
        address _to,
        uint256 _tokenId,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // `_mintTo` is re-used. `mintTo` just adds a minter role check.
        _mintTo(_to, _tokenId, _amount);
    }

    ///     =====   External functions  =====

    /// @dev See EIP-2981
    function royaltyInfo(uint256 tokenId, uint256 salePrice)
        external
        view
        virtual
        returns (address receiver, uint256 royaltyAmount)
    {
        (address recipient, uint256 bps) = getRoyaltyInfoForToken(tokenId);
        receiver = recipient;
        royaltyAmount = (salePrice * bps) / MAX_BPS;
    }

    //      =====   Setter functions  =====

    /// @dev Lets a module admin set the default recipient of all primary sales.
    function setPrimarySaleRecipient(address _saleRecipient) external onlyRole(DEFAULT_ADMIN_ROLE) {
        primarySaleRecipient = _saleRecipient;
        emit PrimarySaleRecipientUpdated(_saleRecipient);
    }

    /// @dev Lets a module admin update the royalty bps and recipient.
    function setDefaultRoyaltyInfo(address _royaltyRecipient, uint256 _royaltyBps)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_royaltyBps <= MAX_BPS, "!r");

        royaltyRecipient = _royaltyRecipient;
        royaltyBps = uint128(_royaltyBps);

        emit DefaultRoyalty(_royaltyRecipient, _royaltyBps);
    }

    /// @dev Lets a module admin set the royalty recipient for a particular token Id.
    function setRoyaltyInfoForToken(
        uint256 _tokenId,
        address _recipient,
        uint256 _bps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_bps <= MAX_BPS, "!r");

        royaltyInfoForToken[_tokenId] = RoyaltyInfo({ recipient: _recipient, bps: _bps });

        emit RoyaltyForToken(_tokenId, _recipient, _bps);
    }

    /// @dev Lets a module admin update the fees on primary sales.
    function setPlatformFeeInfo(address _platformFeeRecipient, uint256 _platformFeeBps)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_platformFeeBps <= MAX_BPS, "!m");

        platformFeeBps = uint64(_platformFeeBps);
        platformFeeRecipient = _platformFeeRecipient;

        emit PlatformFeeInfoUpdated(_platformFeeRecipient, _platformFeeBps);
    }

    /// @dev Lets a module admin set a flat fee on primary sales.
    function setFlatPlatformFeeInfo(address _platformFeeRecipient, uint256 _flatFee)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        flatPlatformFee = _flatFee;
        platformFeeRecipient = _platformFeeRecipient;

        emit FlatPlatformFeeUpdated(_platformFeeRecipient, _flatFee);
    }

    /// @dev Lets a module admin set a flat fee on primary sales.
    function setPlatformFeeType(PlatformFeeType _feeType) external onlyRole(DEFAULT_ADMIN_ROLE) {
        platformFeeType = _feeType;

        emit PlatformFeeTypeUpdated(_feeType);
    }

    /// @dev Lets a module admin set a new owner for the contract. The new owner must be a module admin.
    function setOwner(address _newOwner) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(hasRole(DEFAULT_ADMIN_ROLE, _newOwner));
        address _prevOwner = _owner;
        _owner = _newOwner;

        emit OwnerUpdated(_prevOwner, _newOwner);
    }

    /// @dev Lets a module admin set the URI for contract-level metadata.
    function setContractURI(string calldata _uri) external onlyRole(DEFAULT_ADMIN_ROLE) {
        contractURI = _uri;
    }

    ///     =====   Getter functions    =====

    /// @dev Returns the platform fee bps and recipient.
    function getPlatformFeeInfo() external view returns (address, uint16) {
        return (platformFeeRecipient, uint16(platformFeeBps));
    }

    /// @dev Returns the flat platform fee and recipient.
    function getFlatPlatformFeeInfo() external view returns (address, uint256) {
        return (platformFeeRecipient, flatPlatformFee);
    }

    /// @dev Returns the platform fee type.
    function getPlatformFeeType() external view returns (PlatformFeeType) {
        return platformFeeType;
    }

    /// @dev Returns default royalty info.
    function getDefaultRoyaltyInfo() external view returns (address, uint16) {
        return (royaltyRecipient, uint16(royaltyBps));
    }

    /// @dev Returns the royalty recipient for a particular token Id.
    function getRoyaltyInfoForToken(uint256 _tokenId) public view returns (address, uint16) {
        RoyaltyInfo memory royaltyForToken = royaltyInfoForToken[_tokenId];

        return
            royaltyForToken.recipient == address(0)
                ? (royaltyRecipient, uint16(royaltyBps))
                : (royaltyForToken.recipient, uint16(royaltyForToken.bps));
    }

    ///     =====   Internal functions  =====

    /// @dev Mints an NFT to `to`
    function _mintTo(
        address _to,
        uint256 _tokenId,
        uint256 _amount
    ) internal virtual {

        _mint(_to, _tokenId, _amount, "");

        emit TokensMinted(_to, _tokenId, _tokenURI[_tokenId], _amount);
    }

    /// @dev Mints an NFT according to the provided mint request.
    function mintWithSignature(MintRequestWithParams calldata _req, bytes calldata _signature) external payable virtual nonReentrant {
        address signer = verifyRequest(_req, _signature);
        address receiver = _req.to;

        _mintTo(receiver, _req.tokenId, _req.quantity);

        collectPrice(_req);

        emit TokensMintedWithSignature(signer, receiver, _req.tokenId, _req);
    }

    /// @dev Verifies that a mint request is valid.
    function verifyRequest(MintRequestWithParams calldata _req, bytes calldata _signature) internal virtual returns (address) {
        bytes memory encoded = abi.encode(_req);
        require(_req.to != address(0), "!r");
        require(_req.quantity > 0, "!q");
        return _processRequest(encoded, _signature);
    }


    /// @dev Collects and distributes the primary sale value of tokens being claimed.
    function collectPrice(MintRequestWithParams calldata _req) internal virtual {
        if (_req.pricePerToken == 0) {
            return;
        }

        uint256 totalPrice = _req.pricePerToken * _req.quantity;
        uint256 platformFees = platformFeeType == PlatformFeeType.Flat
            ? flatPlatformFee
            : ((totalPrice * platformFeeBps) / MAX_BPS);
        require(totalPrice >= platformFees, "!p");

        if (_req.currency == CurrencyTransferLib.NATIVE_TOKEN) {
            require(msg.value == totalPrice, "!t");
        } else {
            require(msg.value == 0, "!m");
        }

        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), platformFeeRecipient, platformFees);
        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), primarySaleRecipient, totalPrice - platformFees);
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
        if (!hasRole(TRANSFER_ROLE, address(0)) && from != address(0) && to != address(0)) {
            require(hasRole(TRANSFER_ROLE, from) || hasRole(TRANSFER_ROLE, to), "!r");
        }

        if (from == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                totalSupply[ids[i]] += amounts[i];
            }
        }

        if (to == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                totalSupply[ids[i]] -= amounts[i];
            }
        }
    }

    /// @dev See {ERC1155-setApprovalForAll}
    function setApprovalForAll(address operator, bool approved)
        public
        override(ERC1155Upgradeable, IERC1155Upgradeable)
        onlyAllowedOperatorApproval(operator)
    {
        super.setApprovalForAll(operator, approved);
    }

    /**
     * @dev See {IERC1155-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public override(ERC1155Upgradeable, IERC1155Upgradeable) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, id, amount, data);
    }

    /**
     * @dev See {IERC1155-safeBatchTransferFrom}.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public override(ERC1155Upgradeable, IERC1155Upgradeable) onlyAllowedOperator(from) {
        super.safeBatchTransferFrom(from, to, ids, amounts, data);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165Upgradeable, IERC165, AccessControlEnumerableUpgradeable, ERC1155Upgradeable, TimeboundEIP712Upgradeable)
        returns (bool)
    {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == type(IERC1155Upgradeable).interfaceId ||
            interfaceId == type(IERC2981Upgradeable).interfaceId ||
            interfaceId == type(IAccessControlEnumerableUpgradeable).interfaceId;
    }

    /// @dev Returns whether operator restriction can be set in the given execution context.
    function _canSetOperatorRestriction() internal virtual override returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function _msgSender()
        internal
        view
        virtual
        override(ContextUpgradeable, ERC2771ContextUpgradeable)
        returns (address sender)
    {
        return ERC2771ContextUpgradeable._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(ContextUpgradeable, ERC2771ContextUpgradeable)
        returns (bytes calldata)
    {
        return ERC2771ContextUpgradeable._msgData();
    }

    function _decodeAsMintRequestWithParams(bytes memory encoded) private pure returns(MintRequestWithParams memory) {
        return abi.decode(encoded, (MintRequestWithParams));
    }

    function _buildHashStruct(bytes memory _req) internal pure override returns(bytes memory){
        MintRequestWithParams memory m = _decodeAsMintRequestWithParams(_req);
        return abi.encode(
            TYPEHASH,
            _hashBase(m.baseRequest),
            m.tokenId,
            m.pricePerToken,
            m.quantity,
            m.to,
            m.currency,
            keccak256(m.param)
        );
    }

    function _getBaseRequest(bytes memory _req) internal pure override returns(BaseRequest memory) {
        MintRequestWithParams memory m = _decodeAsMintRequestWithParams(_req);
        return m.baseRequest;
    }

    function _authrorizeSigner(address _signer) internal override {
        signerAddress = _signer;
    }

    function _isAuthorizedSigner(address _signer) internal view override returns(bool) {
        return signerAddress == _signer;
    }

}