// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {PatientConsentRegistry} from "../src/PatientConsentRegistry.sol";

/// @dev Handler ограничивает пространство действий, чтобы fuzz-инвариант
///      не вырождался в мусорные транзакции.
contract Handler is Test {
    PatientConsentRegistry public registry;
    address public admin;
    address public registrar;
    address public patient;
    uint256 public patientPk;

    bytes32[] public seenIds;

    /// @notice Количество успешных registerConsent (успешных = +1 к nonce).
    uint256 public successfulRegisters;

    constructor(
        PatientConsentRegistry _registry,
        address _admin,
        address _registrar,
        address _patient,
        uint256 _pk
    ) {
        registry = _registry;
        admin = _admin;
        registrar = _registrar;
        patient = _patient;
        patientPk = _pk;
    }

    function register(bytes32 consentId, bytes32 docHash) external {
        if (consentId == bytes32(0) || docHash == bytes32(0)) return;
        if (registry.checkConsentExists(consentId)) return;

        uint256 nonce = registry.nonces(patient);
        bytes32 digest = registry.hashConsent(patient, registrar, docHash, 1, 0, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(patientPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(registrar);
        try registry.registerConsent(consentId, patient, docHash, 1, 0, sig) {
            seenIds.push(consentId);
            successfulRegisters++;
        } catch {}
    }

    function revoke(uint256 idx) external {
        if (seenIds.length == 0) return;
        bytes32 consentId = seenIds[idx % seenIds.length];

        vm.prank(patient);
        try registry.revokeConsent(consentId) {} catch {}
    }

    function seenIdsLength() external view returns (uint256) {
        return seenIds.length;
    }
}

contract ConsentRegistryInvariantTest is Test {
    PatientConsentRegistry internal registry;
    Handler internal handler;

    address internal admin     = makeAddr("admin");
    address internal registrar = makeAddr("registrar");
    address internal patient;
    uint256 internal patientPk;

    function setUp() public {
        (patient, patientPk) = makeAddrAndKey("patient");
        vm.prank(admin);
        registry = new PatientConsentRegistry(admin);
        vm.prank(admin);
        registry.setRegistrar(registrar, true);

        handler = new Handler(registry, admin, registrar, patient, patientPk);
        targetContract(address(handler));
    }

    /// @notice INVARIANT 1: отозванное согласие никогда не возвращается
    ///         в состояние ACTIVE или EXPIRED.
    function invariant_RevokedNeverActive() public view {
        uint256 len = handler.seenIdsLength();
        for (uint256 i = 0; i < len; i++) {
            bytes32 id = handler.seenIds(i);
            PatientConsentRegistry.Consent memory c = registry.getConsent(id);
            if (c.status == PatientConsentRegistry.ConsentStatus.REVOKED) {
                // getConsentStatus вычисляет EXPIRED только из ACTIVE,
                // поэтому отозванное согласие обязано остаться ровно REVOKED.
                PatientConsentRegistry.ConsentStatus s = registry.getConsentStatus(id);
                assertEq(
                    uint256(s),
                    uint256(PatientConsentRegistry.ConsentStatus.REVOKED),
                    "revoked consent must stay REVOKED"
                );
            }
        }
    }

    /// @notice INVARIANT 2: nonce пациента равен числу успешных регистраций
    ///         (рост ровно на 1 за каждый успешный registerConsent, без
    ///         уменьшения и без пропусков).
    function invariant_NonceMatchesSuccessfulRegisters() public view {
        assertEq(
            registry.nonces(patient),
            handler.successfulRegisters(),
            "nonce must equal successful register count"
        );
    }
}