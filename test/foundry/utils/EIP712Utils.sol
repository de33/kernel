// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KERNEL_NAME, KERNEL_VERSION, KERNEL_MSG_TYPEHASH, VALIDATOR_APPROVED_TYPEHASH} from "src/common/Constants.sol";
import {IKernel} from "src/interfaces/IKernel.sol";

library EIP712Utils {

    function test() public {}

    function encodeMessageDataForKernel(bytes memory message, IKernel kernel) internal view returns (bytes memory) {
        bytes32 kernelMessageHash = keccak256(abi.encode(KERNEL_MSG_TYPEHASH, keccak256(message)));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), IKernel(kernel).domainSeparator(), kernelMessageHash);
    }

    function getMessageHashForKernel(bytes memory message, IKernel kernel) internal view returns (bytes32) {
        return keccak256(encodeMessageDataForKernel(message, kernel));
    }

        // computes the hash of a permit
    function getStructHash(
        bytes4 sig,
        uint48 validUntil,
        uint48 validAfter,
        address validator,
        address executor,
        bytes memory enableData
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VALIDATOR_APPROVED_TYPEHASH,
                bytes4(sig),
                uint256(
                    uint256(uint160(validator)) | (uint256(validAfter) << 160) | (uint256(validUntil) << (48 + 160))
                ),
                executor,
                keccak256(enableData)
            )
        );
    }

    function _buildDomainSeparator(string memory name, string memory version, address verifyingContract)
        internal view returns (bytes32)
    {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

        return keccak256(abi.encode(typeHash, hashedName, hashedVersion, block.chainid, address(verifyingContract)));
    }

}
