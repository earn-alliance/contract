// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@thirdweb-dev/contracts/extension/interface/IContractFactory.sol";
import "../interfaces/IPoolFactory.sol";
import "../interfaces/IContractOpenablePack.sol";
import "../interfaces/IContractOpenablePack721.sol";
import "./Pool.sol";
import "./TimeboundEIP712Upgradeable.sol";
import {ITokenBundle} from "@thirdweb-dev/contracts/extension/interface/ITokenBundle.sol";

contract PoolFactory is Initializable, AccessControlEnumerableUpgradeable, TimeboundEIP712Upgradeable, UUPSUpgradeable, IPoolFactory, IContractFactory {

    event ProxyDeployed(address indexed implementation, address proxy, address indexed deployer);
    event PackOpenedWithSignature(OpenPackRequest request, ITokenBundle.Token[] tokens);

    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 internal constant TYPEHASH =
        keccak256(abi.encodePacked(
            "OpenPackRequest(BaseRequest baseRequest,uint256 poolId,uint256 amountToOpen,address recipient,uint256 valuePayable)",
            BASEREQUESTTYPE
        ));
    bytes32 private immutable salt;
    address private signer;
    
    uint256 public nextPoolId;
    
    UpgradeableBeacon public poolBeacon;
    IContractOpenablePack public packContract;
    mapping(uint256 => IPool) public poolContract;
    mapping(uint256 => uint256) public openCount;
    address public poolDefaultAdmin;
    IContractOpenablePack721 public packContract721;
    mapping(uint256 => bool) public is721;

    constructor(bytes32 _salt) {
        salt = _salt;
    }

    function initialize(address _defaultAdmin, IContractOpenablePack _packContract, string memory _domainName, address _signer, UpgradeableBeacon _poolBeacon) external initializer {
        packContract = _packContract;
        signer = _signer;
        poolBeacon = _poolBeacon;
        poolDefaultAdmin = _defaultAdmin;
        _grantRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
        TimeboundEIP712Upgradeable.__TimeboundEIP712Upgradeable_init(_domainName, "1", _signer);
    }

    function setPoolDefaultAdmin(address _poolDefaultAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        poolDefaultAdmin = _poolDefaultAdmin;
    }
    function setPackContract721(IContractOpenablePack721 _packContract721) external onlyRole(DEFAULT_ADMIN_ROLE) {
        packContract721 = _packContract721;
    }
    function setPoolBeacon(UpgradeableBeacon _beacon) external onlyRole(DEFAULT_ADMIN_ROLE) {
        poolBeacon = _beacon;
    }
    function createPool(bool _is721) public onlyRole(DEFAULT_ADMIN_ROLE) returns(address _poolAddress) {
        uint256 _poolId = nextPoolId;
        require(poolContract[_poolId] == Pool(address(0)), "alrdy created");
        nextPoolId++;
        // make pool contract address different at different chain
        bytes32 poolIdInfusedSalt = keccak256(abi.encodePacked(salt, block.chainid, _poolId));
        _poolAddress = address(
            new BeaconProxy{salt: poolIdInfusedSalt}(address(poolBeacon), bytes(""))
        );
        
        // initialize
        Address.functionCall(_poolAddress, abi.encodePacked(
            Pool.initialize.selector,
            abi.encode(
                poolDefaultAdmin,
                _poolId,
                address(this)
            )
        ));

        poolContract[_poolId] = IPool(_poolAddress);
        
        if (_is721) {
            is721[_poolId] = true;
        }
        emit PoolCreated(_poolId, _poolAddress);
    }

    function deployProxyByImplementation(address _impl, bytes calldata _data, bytes32) external onlyRole(DEFAULT_ADMIN_ROLE) returns (address poolAddr) {
        // ignore factory, packcontract and poolId
        (bool _is721) = abi.decode(_data[4:], (bool));
        poolAddr = createPool(_is721);
        emit ProxyDeployed(_impl, poolAddr, _msgSender());
    }

    function removePool(uint256 _poolId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (is721[_poolId]) {
            packContract721.burnPack(_poolId);
            return;
        }
        packContract.burnPack(_poolId);
    }

    function resetPool(uint256 _poolId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // only support reset pool for 1155 pool for now
        require(!is721[_poolId], "!p");
        packContract.resetPack(_poolId);
    }

    function supportsInterface(bytes4 interfaceId) public view override(AccessControlEnumerableUpgradeable, TimeboundEIP712Upgradeable, IERC165Upgradeable) returns(bool) {
        return AccessControlEnumerableUpgradeable.supportsInterface(interfaceId) || 
            TimeboundEIP712Upgradeable.supportsInterface(interfaceId) ||
            interfaceId == type(IERC1155ReceiverUpgradeable).interfaceId;
    }

    function _decodeAsOpenPackRequest(bytes memory encoded) private pure returns(OpenPackRequest memory) {
        return abi.decode(encoded, (OpenPackRequest));
    }

    function _buildHashStruct(bytes memory _req) internal pure override returns(bytes memory){
        OpenPackRequest memory m = _decodeAsOpenPackRequest(_req);
        return abi.encode(
            TYPEHASH,
            _hashBase(m.baseRequest),
            m.poolId,
            m.amountToOpen,
            m.recipient,
            m.valuePayable
        );
    }

    function _getBaseRequest(bytes memory _req) internal pure override returns(BaseRequest memory m) {
        m = _decodeAsOpenPackRequest(_req).baseRequest;
    }

    function _authrorizeSigner(address _signer) internal override {
        signer = _signer;
    }

    /// @dev Returns whether a given address is authorized to sign mint requests.
    function _isAuthorizedSigner(address _signer) internal view override returns (bool) {
        return signer == _signer;
    }

    function verifyRequest(OpenPackRequest calldata _req, bytes calldata _signature) internal returns (address) {
        bytes memory encoded = abi.encode(_req);
        (bool _success, address _signer) = verify(encoded, _signature);
        require(_success, "invalid signature");
        _processRequest(encoded, _signature);
        return _signer;
    }

    function onERC1155Received(
        address ,
        address from,
        uint256 ,
        uint256 ,
        bytes calldata 
    ) external pure returns (bytes4) {
        require(from == address(0), "!mint");
        return IERC1155ReceiverUpgradeable.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address ,
        address from,
        uint256[] calldata ,
        uint256[] calldata ,
        bytes calldata 
    ) external pure returns (bytes4) {
        require(from == address(0), "!mint");
        return IERC1155ReceiverUpgradeable.onERC1155BatchReceived.selector;
    }

    function openPackWithSignature(OpenPackRequest calldata _req, bytes calldata _sig) external payable {
        require(_req.valuePayable == msg.value, "!value");
        address opener = _msgSender();
        require(opener == tx.origin, "!EOA");
        require(_req.recipient == tx.origin, "!EOA");
        verifyRequest(_req, _sig);
        if (is721[_req.poolId]) {
            require(packContract721.balanceOf(address(this), _req.poolId) >= _req.amountToOpen, "!Bal");
            (uint256[] memory tokenIds, IContractOpenablePack721.PackInfo memory pack) =  packContract721.openPack(_req.poolId, _req.amountToOpen, _req.recipient);
            poolContract[_req.poolId].transferERC721Tokens(pack.contractAddress, tokenIds, _req.recipient);
            openCount[_req.poolId] += _req.amountToOpen;
            ITokenBundle.Token[] memory _erc721tokens = new ITokenBundle.Token[](tokenIds.length);
            for (uint i = 0; i < tokenIds.length; i++) {
                _erc721tokens[i].assetContract = address(pack.contractAddress);
                _erc721tokens[i].tokenType = ITokenBundle.TokenType.ERC721;
                _erc721tokens[i].tokenId = tokenIds[i];
                _erc721tokens[i].totalAmount = 1;
            }
            emit PackOpenedWithSignature(_req, _erc721tokens);
            return;
        }
        require(packContract.balanceOf(address(this), _req.poolId) >= _req.amountToOpen, "!Bal");

        ITokenBundle.Token[] memory tokens = packContract.openPack(_req.poolId, _req.amountToOpen, _req.recipient);
        poolContract[_req.poolId].transferTokens(tokens, _req.recipient);
        openCount[_req.poolId] += _req.amountToOpen;
        emit PackOpenedWithSignature(_req, tokens);
    }

    function createOrAddPack(uint256 poolId, ITokenBundle.Token[] calldata token, uint256[] calldata numOfRewardUnits, uint128 openStartTimestamp, uint128 amountDistributedPerOpen) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!packContract.created(poolId)) {
            packContract.createPack(
                poolId,
                token,
                numOfRewardUnits,
                openStartTimestamp,
                amountDistributedPerOpen,
                address(this)
            );
            return;
        }
        packContract.addPackContents(
            poolId,
            token,
            numOfRewardUnits,
            address(this)
        );
    }

    function createOrAddPack721(
        IERC721Upgradeable contractAddress,
        uint256 poolId,
        uint256[] calldata token,
        uint128 _openStartTimestamp,
        uint128 _amountDistributedPerOpen
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!packContract721.created(poolId)) {
            packContract721.createPack(
                contractAddress,
                poolId,
                token,
                _openStartTimestamp,
                _amountDistributedPerOpen,
                address(this)
            );
            return;
        }
        packContract721.addPackContents(
            contractAddress,
            poolId,
            token,
            address(this)
        );
    }

    function withdrawAll(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "!balance");
        (bool success, ) = recipient.call{ value: balance } ("");
        require(success, "Transfer failed!");
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    receive() external payable {}
}
