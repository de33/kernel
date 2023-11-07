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
        bytes32 wrappedHash = hashTypedData(hash);
        return _validateSignature(msg.sender, wrappedHash, signature);
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

    function _domainNameAndVersion() internal view override returns (string memory, string memory) {
        return (IKernel(msg.sender).name(), IKernel(msg.sender).version());
    }

    function _erc1271Signer() internal view override virtual returns (address){
        return ecdsaValidatorStorage[msg.sender].owner;
    }

    function hashTypedData(bytes32 structHash) public view returns (bytes32 digest) {
        digest = _domainSeparator();
        assembly {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _domainSeparator() internal view override returns (bytes32 separator) {
        bytes32 versionHash;
        (string memory name, string memory version) = _domainNameAndVersion();
        separator = keccak256(bytes(name));
        versionHash = keccak256(bytes(version));
        assembly {
            let m := mload(0x40)
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), separator)
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), caller())
            separator := keccak256(m, 0xa0)
        }
    }

    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return true;
    }
}
