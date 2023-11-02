pragma solidity ^0.8.0;

import {ValidationData} from "./Types.sol";

// constants for kernel metadata
string constant KERNEL_NAME = "Kernel";
string constant KERNEL_VERSION = "0.2.2";

// ERC4337 constants
uint256 constant SIG_VALIDATION_FAILED_UINT = 1;
ValidationData constant SIG_VALIDATION_FAILED = ValidationData.wrap(SIG_VALIDATION_FAILED_UINT);

// keccak256("ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)")
bytes32 constant VALIDATOR_APPROVED_TYPEHASH = 0x3ce406685c1b3551d706d85a68afdaa49ac4e07b451ad9b8ff8b58c3ee964176;

// keccak256("KernelMessage(bytes message)")
bytes32 constant KERNEL_MSG_TYPEHASH = 0x140f761b4e8f7f224b9f246c4f7d2c686aeede7d330745e1276473b1c0cab52f;

// Storage slots
bytes32 constant KERNEL_STORAGE_SLOT = 0x439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd8;
bytes32 constant KERNEL_STORAGE_SLOT_1 = 0x439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd9;
bytes32 constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
