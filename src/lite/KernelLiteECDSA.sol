pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {Kernel} from "../Kernel.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED, KERNEL_STORAGE_SLOT_1} from "../common/Constants.sol";
import {ExecutionDetail} from "../common/Structs.sol";
import {packValidationData} from "../common/Types.sol";
import {_intersectValidationData} from "../utils/KernelHelper.sol";

struct KernelLiteECDSAStorage {
    address owner;
}

contract KernelLiteECDSA is Kernel {
    error InvalidAccess();

    address public immutable KERNEL_ECDSA_VALIDATOR;
    bytes32 private constant KERNEL_LITE_ECDSA_STORAGE_SLOT =
        0xdea7fea882fba743201b2aeb1babf326b8944488db560784858525d123ee7e97; // keccak256(abi.encodePacked("zerodev.kernel.lite.ecdsa")) - 1

    constructor(IEntryPoint _entryPoint, IKernelValidator _ecdsaValidator) Kernel(_entryPoint) {
        KERNEL_ECDSA_VALIDATOR = address(_ecdsaValidator);
        getKernelLiteECDSAStorage().owner = address(1); // set owner to non-zero address to prevent initialization
    }

    function transferOwnership(address _newOwner) external payable onlyFromEntryPointOrSelf {
        getKernelLiteECDSAStorage().owner = _newOwner;
    }

    // FOR KERNEL USAGE
    function getKernelLiteECDSAStorage() internal pure returns (KernelLiteECDSAStorage storage s) {
        assembly {
            s.slot := KERNEL_LITE_ECDSA_STORAGE_SLOT
        }
    }

    function _setInitialData(IKernelValidator _validator, bytes calldata _data) internal override {
        require(address(_validator) == KERNEL_ECDSA_VALIDATOR, "KernelLiteECDSA: invalid validator");
        require(getKernelLiteECDSAStorage().owner == address(0), "KernelLiteECDSA: already initialized");
        address owner = address(bytes20(_data[0:20]));
        getKernelLiteECDSAStorage().owner = owner;
    }

    function _validateUserOp(UserOperation calldata _op, bytes32 _opHash, uint256)
        internal
        view
        override
        returns (ValidationData)
    {
        address signed = ECDSA.recover(ECDSA.toEthSignedMessageHash(_opHash), _op.signature[4:]); // note that first 4 bytes are for modes
        if (signed != getKernelLiteECDSAStorage().owner) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function _validateSignature(bytes32 _hash, bytes calldata _signature)
        internal
        view
        override
        returns (ValidationData)
    {
        bytes32 wrappedHash = hashTypedData(_hash);
        address owner = getKernelLiteECDSAStorage().owner;
        bool isValid = SignatureCheckerLib.isValidSignatureNow(owner, wrappedHash, _signature) ||
            SignatureCheckerLib.isValidSignatureNow(owner, SignatureCheckerLib.toEthSignedMessageHash(wrappedHash), _signature);
        if (isValid) {
            return ValidationData.wrap(0);
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _validCaller(address _caller, bytes calldata) internal view override returns (bool) {
        return _caller == getKernelLiteECDSAStorage().owner;
    }

    function setDefaultValidator(IKernelValidator, bytes calldata) external payable override onlyFromEntryPointOrSelf {
        revert("not implemented");
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
            mstore(add(m, 0x80), address())
            separator := keccak256(m, 0xa0)
        }
    }

    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return true;
    }
}
