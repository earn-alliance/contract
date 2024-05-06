// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;
import "./SignatureMintWithParamsERC1155.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract DynamicSupplyLimitERC1155 is SignatureMintWithParamsERC1155, UUPSUpgradeable {
    uint256 public _collectionSupply;

    struct Params {
        uint256 maxCollectionSupply;
    }

    function _decodeParam(bytes calldata _params) private pure returns(Params memory decoded) {
        decoded = abi.decode(_params, (Params));
    }

    function mintWithSignature(MintRequestWithParams calldata _req, bytes calldata _signature) external payable override nonReentrant {
        address signer = verifyRequest(_req, _signature);
        address receiver = _req.to;
        Params memory m = _decodeParam(_req.param);
        uint256 _amountMintable = amountMintable(m.maxCollectionSupply, _req.quantity);
        _mintTo(receiver, _req.tokenId, _amountMintable);
        collectPrice(_req, _amountMintable);
        emit TokensMintedWithSignature(signer, receiver, _req.tokenId, _req);
    }

    function _mintTo(
        address _to,
        uint256 _tokenId,
        uint256 _amount
    ) internal virtual override {
        super._mintTo(_to, _tokenId, _amount);
        _collectionSupply += _amount;
    }

    function collectPrice(MintRequestWithParams calldata _req, uint256 mintedCount) internal {
        if (_req.pricePerToken == 0) {
            return;
        }

        uint256 received = _req.pricePerToken * _req.quantity;
        uint256 refund = _req.pricePerToken * (_req.quantity - mintedCount);
        uint256 totalPrice = received - refund;
        uint256 platformFees = platformFeeType == PlatformFeeType.Flat
            ? flatPlatformFee
            : ((totalPrice * platformFeeBps) / MAX_BPS);
        require(totalPrice >= platformFees, "!cp1");

        if (_req.currency == CurrencyTransferLib.NATIVE_TOKEN) {
            require(msg.value >= totalPrice, "!cp2");
        } else {
            require(msg.value == 0, "!cp3");
        }

        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), platformFeeRecipient, platformFees);
        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), primarySaleRecipient, totalPrice - platformFees);
        CurrencyTransferLib.transferCurrency(_req.currency, address(this), _msgSender(), refund);
    }


    function amountMintable(uint256 maxCollectionSupply, uint256 intendedAmount) internal view returns(uint256){
        uint256 quota = maxCollectionSupply - _collectionSupply;
        return quota > intendedAmount ? intendedAmount : quota;
    }


    function verifyRequest(MintRequestWithParams calldata _req, bytes calldata _signature) internal override returns (address) {
        bytes memory encoded = abi.encode(_req);
        (bool success, address signer) = verify(encoded, _signature);
        require(success, "!sig");
        Params memory p = _decodeParam(_req.param);
        require(_collectionSupply < p.maxCollectionSupply, "!max");
        _processRequest(encoded, _signature);
        return signer;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}