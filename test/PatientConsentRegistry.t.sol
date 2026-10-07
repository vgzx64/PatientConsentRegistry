// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {PatientConsentRegistry} from "../src/PatientConsentRegistry.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract PatientConsentRegistryTest is Test {
    PatientConsentRegistry internal registry;

    address internal admin     = makeAddr("admin");
    address internal registrar = makeAddr("registrar");
    address internal patient;      // ключ нужен для подписи
    uint256 internal patientPk;
    address internal attacker  = makeAddr("attacker");

    bytes32 internal constant CONSENT_ID = keccak256("consent-001");
    bytes32 internal constant DOC_HASH   = keccak256("canonical-doc-with-salt");
    uint32  internal constant VERSION    = 1;

    function setUp() public {
        (patient, patientPk) = makeAddrAndKey("patient");

        vm.prank(admin);
        registry = new PatientConsentRegistry(admin);

        vm.prank(admin);
        registry.setRegistrar(registrar, true);
    }

    // ---------- helpers ----------

    function _signConsent(
        address _patient,
        uint256 _pk,
        address _issuer,
        uint64  _expiresAt
    ) internal view returns (bytes memory) {
        uint256 nonce = registry.nonces(_patient);
        bytes32 digest = registry.hashConsent(
            _patient,
            _issuer,
            DOC_HASH,
            VERSION,
            _expiresAt,
            nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ---------- 1. Happy path: register ----------

    function test_RegisterConsent_Success() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);

        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);

        assertEq(uint(registry.getConsentStatus(CONSENT_ID)), uint(PatientConsentRegistry.ConsentStatus.ACTIVE));

        PatientConsentRegistry.Consent memory c = registry.getConsent(CONSENT_ID);
        assertEq(c.patient, patient);
        assertEq(c.issuer, registrar);
        assertEq(c.consentHash, DOC_HASH);
        assertEq(registry.nonces(patient), 1);
    }

    // ---------- 2. Access control: not registrar ----------

    function test_RegisterConsent_RevertIfNotRegistrar() public {
        bytes memory sig = _signConsent(patient, patientPk, attacker, 0);

        vm.prank(attacker);
        vm.expectRevert();
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);
    }

    // ---------- 3. Invalid signature ----------

    function test_RegisterConsent_RevertIfSignatureInvalid() public {
        // Подпись другим ключом
        (, uint256 wrongPk) = makeAddrAndKey("wrong");
        bytes memory sig = _signConsent(patient, wrongPk, registrar, 0);

        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.InvalidSignature.selector);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);
    }

    // ---------- 4. Duplicate consentId ----------

    function test_RegisterConsent_RevertIfDuplicate() public {
        bytes memory sig1 = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig1);

        bytes memory sig2 = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(PatientConsentRegistry.ConsentAlreadyExists.selector, CONSENT_ID)
        );
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig2);
    }

    // ---------- 5. Nonce replay protection ----------

    function test_RegisterConsent_RevertOnReplay() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);

        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);

        // Та же подпись, другой consentId — nonce уже изменился, подпись невалидна
        bytes32 anotherId = keccak256("consent-002");
        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.InvalidSignature.selector);
        registry.registerConsent(anotherId, patient, DOC_HASH, VERSION, 0, sig);
    }

    // ---------- 6. Revoke: success + invariant REVOKED->ACTIVE ----------

    function test_RevokeConsent_SuccessAndNotReactivate() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);

        vm.prank(patient);
        registry.revokeConsent(CONSENT_ID);

        assertEq(uint(registry.getConsentStatus(CONSENT_ID)), uint(PatientConsentRegistry.ConsentStatus.REVOKED));

        // Повторная регистрация того же consentId запрещена
        bytes memory sig2 = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(PatientConsentRegistry.ConsentAlreadyExists.selector, CONSENT_ID)
        );
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig2);
    }

    // ---------- 7. Revoke by attacker ----------

    function test_RevokeConsent_RevertIfNotOwner() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                PatientConsentRegistry.NotConsentOwner.selector,
                attacker,
                patient
            )
        );
        registry.revokeConsent(CONSENT_ID);
    }

    // ---------- 8. Expiry edge case ----------

    function test_ConsentExpiresDynamically() public {
        uint64 expiresAt = uint64(block.timestamp + 1 days);
        bytes memory sig = _signConsent(patient, patientPk, registrar, expiresAt);
        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, expiresAt, sig);

        assertEq(uint(registry.getConsentStatus(CONSENT_ID)), uint(PatientConsentRegistry.ConsentStatus.ACTIVE));

        vm.warp(expiresAt + 1);
        assertEq(uint(registry.getConsentStatus(CONSENT_ID)), uint(PatientConsentRegistry.ConsentStatus.EXPIRED));
    }

    // ---------- 9. Invalid input: empty hash ----------

    function test_RegisterConsent_RevertIfEmptyHash() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.EmptyHash.selector);
        registry.registerConsent(CONSENT_ID, patient, bytes32(0), VERSION, 0, sig);
    }

    // ---------- 10. Pause blocks registration ----------

    function test_Pause_BlocksRegistration() public {
        vm.prank(admin);
        registry.pause();

        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);
    }

    // ---------- 11. Invalid expiry: expiresAt <= block.timestamp ----------

    function test_RegisterConsent_RevertIfInvalidExpiry() public {
        // Case A: expiresAt == block.timestamp (boundary, must revert).
        uint64 atNow = uint64(block.timestamp);
        bytes memory sigNow = _signConsent(patient, patientPk, registrar, atNow);
        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.InvalidExpiry.selector);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, atNow, sigNow);

        // Case B: expiresAt in the past (warp forward, same signed value now stale).
        uint64 pastExpiry = uint64(block.timestamp + 1 days);
        bytes memory sigPast = _signConsent(patient, patientPk, registrar, pastExpiry);
        vm.warp(uint256(pastExpiry) + 1);
        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.InvalidExpiry.selector);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, pastExpiry, sigPast);
    }

    // ---------- 12. Double revoke: REVOKED -> ConsentNotActive ----------

    function test_RevokeConsent_RevertIfAlreadyRevoked() public {
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        registry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);

        vm.prank(patient);
        registry.revokeConsent(CONSENT_ID);

        vm.prank(patient);
        vm.expectRevert(
            abi.encodeWithSelector(
                PatientConsentRegistry.ConsentNotActive.selector,
                PatientConsentRegistry.ConsentStatus.REVOKED
            )
        );
        registry.revokeConsent(CONSENT_ID);
    }

    // ---------- 13. Zero patient address ----------

    function test_RegisterConsent_RevertIfZeroPatient() public {
        // Zero-address check fires before signature recovery, so any sig bytes do.
        bytes memory sig = _signConsent(patient, patientPk, registrar, 0);
        vm.prank(registrar);
        vm.expectRevert(PatientConsentRegistry.ZeroAddress.selector);
        registry.registerConsent(CONSENT_ID, address(0), DOC_HASH, VERSION, 0, sig);
    }
}