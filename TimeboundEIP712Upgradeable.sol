// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @author thirdweb

import "../interfaces/ITimeboundEIP712.sol";

import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";

abstract contract TimeboundEIP712Upgradeable is Initializable, EIP712Upgradeable, ITimeboundEIP712 {
    using ECDSAUpgradeable for bytes32;
    bytes internal constant BASEREQUESTTYPE = "BaseRequest(uint128 validityStartTimestamp,uint128 validityEndTimestamp,bytes32 uid)";
    bytes32 internal constant BASEREQUESTTYPEHASH = keccak256(BASEREQUESTTYPE);

    /// @dev Mapping from mint request UID => whether the mint request is processed.
    mapping(bytes32 => bool) private minted;

    function supportsInterface(bytes4 interfaceId) public view virtual returns(bool) {
        return interfaceId == type(ITimeboundEIP712).interfaceId;
    }

    function __TimeboundEIP712Upgradeable_init(string memory name, string memory version, address _signer) internal onlyInitializing {
        __EIP712_init(name, version);
        _authrorizeSigner(_signer);
    }

    function __TimeboundEIP712Upgradeable_init_unchained() internal onlyInitializing {}

    /// @dev Verifies that a mint request is signed by an account holding MINTER_ROLE (at the time of the function call).
    function verify(bytes memory _req, bytes calldata _signature)
        public
        view
        virtual
        returns (bool success, address signer)
    {
        signer = _recoverAddress(_req, _signature);
        success = !_hasMinted(_req) && _isAuthorizedSigner(signer);
    }

    /// @dev Verifies a mint request and marks the request as minted.
    function _processRequest(bytes memory _req, bytes calldata _signature) internal returns (address) {
        (bool success, address signer) = verify(_req, _signature);

        require(success, "!r");
        BaseRequest memory m = _getBaseRequest(_req);
        require(
            m.validityStartTimestamp <= block.timestamp && block.timestamp <= m.validityEndTimestamp,
            "!rr"
        );
        minted[m.uid] = true;
        return signer;
    }

    /// @dev Returns the address of the signer of the mint request.
    function _recoverAddress(bytes memory _req, bytes calldata _signature) internal view returns (address) {
        return _hashTypedDataV4(keccak256(_buildHashStruct(_req))).recover(_signature);
    }

    function _hashBase(BaseRequest memory _base) internal pure returns(bytes32)  {
        return keccak256(abi.encode(
            BASEREQUESTTYPEHASH,
            _base.validityStartTimestamp,
            _base.validityEndTimestamp,
            _base.uid
        ));
    }

    function _hasMinted(bytes memory _req) internal view virtual returns(bool) {
        BaseRequest memory m = _getBaseRequest(_req);
        return minted[m.uid];
    }
    /// @dev Resolves 'stack too deep' error in `recoverAddress`.
    function _buildHashStruct(bytes memory _req) internal pure virtual returns (bytes memory);

    function _getBaseRequest(bytes memory _req) internal pure virtual returns(BaseRequest memory);

    function _authrorizeSigner(address _signer) internal virtual;

    /// @dev Returns whether a given address is authorized to sign mint requests.
    function _isAuthorizedSigner(address _signer) internal view virtual returns (bool);

}