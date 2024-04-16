// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/// @author thirdweb

import "../interfaces/ITimeboundEIP712WithParam.sol";

import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";

abstract contract TimeboundEIP712UpgradeableWithParam is Initializable, EIP712Upgradeable, AccessControlEnumerableUpgradeable, ITimeboundEIP712WithParam {
    
    using ECDSAUpgradeable for bytes32;

    bytes internal constant BASEREQUESTTYPE = "BaseRequest(uint128 validityStartTimestamp,uint128 validityEndTimestamp,bytes32 uid)";
    bytes32 internal constant REQUEST_WITH_PARAM_TYPEHASH = keccak256(abi.encodePacked(
        "RequestWithParam(BaseRequest baseRequest,bytes4 funcSig,bytes param)",
        BASEREQUESTTYPE
    ));

    bytes32 internal constant BASEREQUESTTYPEHASH = keccak256(BASEREQUESTTYPE);

    /// @dev Mapping from mint request UID => whether the mint request is processed.
    mapping(bytes32 => bool) private usedUID;

    function supportsInterface(bytes4 interfaceId) public view virtual override returns(bool) {
        return interfaceId == type(ITimeboundEIP712WithParam).interfaceId  || super.supportsInterface(interfaceId);
    }

    function __TimeboundEIP712UpgradeableWithParam_init(string memory name, string memory version) internal onlyInitializing {
        __EIP712_init(name, version);
    }

    function __TimeboundEIP712UpgradeableWithParam_init_unchained() internal onlyInitializing {}

    /// @dev Verifies a mint request and marks the request as usedUID.
    function _processRequest(RequestWithParam calldata _req) internal {
        require(_req.funcSig == msg.sig, "!funcSig");
        require(!_hasUIDUsed(_req), "!uid");
        BaseRequest memory m = _req.baseRequest;
        require(
            m.validityStartTimestamp <= block.timestamp && block.timestamp <= m.validityEndTimestamp,
            "!rr"
        );
        usedUID[m.uid] = true;
    }

    /// @dev Returns the address of the signer of the mint request.
    function _recoverAddress(RequestWithParam calldata _req, bytes calldata _signature) internal view returns (address) {
        return _hashTypedDataV4(keccak256(_buildHashStruct(_req))).recover(_signature);
    }

    function _hasUIDUsed(RequestWithParam calldata _req) private view returns(bool) {
        return usedUID[_req.baseRequest.uid];
    }


    function _buildHashStruct(RequestWithParam calldata _req) private pure returns (bytes memory) {
        return abi.encode(
            REQUEST_WITH_PARAM_TYPEHASH,
            keccak256(abi.encode(
                BASEREQUESTTYPEHASH,
                _req.baseRequest.validityStartTimestamp,
                _req.baseRequest.validityEndTimestamp,
                _req.baseRequest.uid
            )),
            bytes32(_req.funcSig),
            keccak256(_req.param)
        );
    }

}