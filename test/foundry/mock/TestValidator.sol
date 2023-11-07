// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/interfaces/IKernel.sol";
import "src/interfaces/IKernelValidator.sol";
import {ERC1271} from "solady/accounts/ERC1271.sol";
import "src/common/Types.sol";
import "src/utils/KernelHelper.sol";
import "src/common/Constants.sol";

contract TestValidator is IKernelValidator, ERC1271 {
    event TestValidateUserOp(bytes32 indexed opHash);
    event TestEnable(bytes data);
    event TestDisable(bytes data);

    mapping(address kernel => address) public caller;

    ValidationData public data;

    function test_ignore() public {}

    function sudoSetCaller(address _kernel, address _caller) external {
        caller[_kernel] = _caller;
    }

    function setData(bool success, uint48 validAfter, uint48 validUntil) external {
        data = success
            ? packValidationData(ValidAfter.wrap(validAfter), ValidUntil.wrap(validUntil))
            : SIG_VALIDATION_FAILED;
    }

    function validateSignature(bytes32, bytes calldata) external view override returns (ValidationData) {
        return data;
    }

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData)
    {
        emit TestValidateUserOp(userOpHash);
        return ValidationData.wrap(0);
    }

    function enable(bytes calldata _data) external payable override {
        emit TestEnable(_data);
    }

    function disable(bytes calldata _data) external payable override {
        emit TestDisable(_data);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return _caller == caller[msg.sender];
    }

    function _erc1271Signer() internal view override virtual returns (address) {
        return caller[msg.sender];
    }

    function _domainNameAndVersion() internal view override returns (string memory, string memory) {
        IKernel(msg.sender).domainNameAndVersion();
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) public view override(ERC1271, IKernelValidator) returns (bytes4 result) {
        return ERC1271.isValidSignature(hash, signature);
    }
}