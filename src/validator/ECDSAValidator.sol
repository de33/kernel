// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ERC1271} from "solady/accounts/ERC1271.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {IKernel} from "../interfaces/IKernel.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract ECDSAValidator is IKernelValidator, ERC1271 {
    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function disable(bytes calldata) external payable override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    function enable(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
        address oldOwner = ecdsaValidatorStorage[msg.sender].owner;
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(msg.sender, oldOwner, owner);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        return _validateSignature(_userOp.sender, _userOpHash, _userOp.signature);
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (ValidationData) {
        return _validateSignature(msg.sender, hash, signature);
    }

    function _validateSignature(address sender, bytes32 hash, bytes calldata signature) internal view returns (ValidationData) {
        address owner = ecdsaValidatorStorage[sender].owner;
        bool isValid = SignatureCheckerLib.isValidSignatureNow(owner, hash, signature) ||
            SignatureCheckerLib.isValidSignatureNow(owner, SignatureCheckerLib.toEthSignedMessageHash(hash), signature);
        if (isValid) {
            return ValidationData.wrap(0);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return ecdsaValidatorStorage[msg.sender].owner == _caller;
    }

    function _erc1271Signer() internal view override virtual returns (address) {
        return ecdsaValidatorStorage[msg.sender].owner;
    }

    function _domainNameAndVersion() internal view override returns (string memory, string memory) {
        IKernel(msg.sender).domainNameAndVersion();
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) public view override(ERC1271, IKernelValidator) returns (bytes4 result) {
        return ERC1271.isValidSignature(hash, signature);
    }
}
