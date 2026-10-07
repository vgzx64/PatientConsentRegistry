// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {PatientConsentRegistry} from "../src/PatientConsentRegistry.sol";

contract ConsentRegistryFuzzTest is Test {
    PatientConsentRegistry internal registry;

    address internal admin     = makeAddr("admin");
    address internal registrar = makeAddr("registrar");
    address internal patient;
    uint256 internal patientPk;

    function setUp() public {
        (patient, patientPk) = makeAddrAndKey("patient");
        vm.startPrank(admin);
        registry = new PatientConsentRegistry(admin);
        registry.setRegistrar(registrar, true);
        vm.stopPrank();
    }

    function _sign(
        bytes32 docHash,
        uint32 version,
        uint64 expiresAt
    ) internal view returns (bytes memory) {
        uint256 nonce = registry.nonces(patient);
        bytes32 digest = registry.hashConsent(
            patient,
            registrar,
            docHash,
            version,
            expiresAt,
            nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(patientPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Любой ненулевой хеш и любая версия корректно регистрируются
    ///         и дают статус ACTIVE до истечения.
    function testFuzz_RegisterAnyValidHash(
        bytes32 consentId,
        bytes32 docHash,
        uint32 version,
        uint64 expiresAt
    ) public {
        vm.assume(consentId != bytes32(0));
        vm.assume(docHash != bytes32(0));
        vm.assume(expiresAt == 0 || expiresAt > block.timestamp);

        // не позволяем столкнуться с уже использованным id
        vm.assume(!registry.checkConsentExists(consentId));

        bytes memory sig = _sign(docHash, version, expiresAt);
        vm.prank(registrar);
        registry.registerConsent(consentId, patient, docHash, version, expiresAt, sig);

        assertEq(
            uint(registry.getConsentStatus(consentId)),
            uint(PatientConsentRegistry.ConsentStatus.ACTIVE)
        );
    }

    /// @notice Подпись, связывающая другой docHash, никогда не принимается
    ///         при регистрации исходного docHash (защита от подмены).
    function testFuzz_WrongHashSignatureRejected(bytes32 docHash, bytes32 otherHash) public {
        vm.assume(docHash != bytes32(0));
        vm.assume(otherHash != bytes32(0));
        vm.assume(docHash != otherHash);

        bytes32 consentId = keccak256("consent-fuzz");
        bytes memory sig = _sign(otherHash, 1, 0);

        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.InvalidSignature.selector);
        registry.registerConsent(consentId, patient, docHash, 1, 0, sig);
    }
}