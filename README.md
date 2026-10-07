# PatientConsentRegistry — практическая работа №3, вариант 04

**Отрасль:** Здравоохранение. **Сценарий:** фиксация согласия пациента на обработку данных
(`consentId`, `hash согласия`, `статус`). **Toolchain:** Foundry (чётный вариант).

## Метаданные окружения (для отчёта)

| Компонент | Версия |
|---|---|
| forge | `1.8.3` (Commit `cae51ad458f6abb64852b7709eb784352429825d`) |
| Solidity (pragma, автодетект) | `^0.8.37` |
| OpenZeppelin Contracts | `v5.7.0` (`lib/openzeppelin-contracts`, rev `cab19933…`, см. `foundry.lock`) |
| forge-std | `v1.17.0` (`lib/forge-std`, rev `f3dae6e6…`, см. `foundry.lock`) |
| fuzz runs | `512` (`foundry.toml`) |
| invariant runs / depth | `256` / `32` (`foundry.toml`) |

## Команды запуска

```shell
# сборка
forge build

# все тесты (unit + fuzz + invariant)
forge test -vvv

# только модульные тесты
forge test --match-path test/PatientConsentRegistry.t.sol -vvv

# только fuzz-тесты
forge test --match-path test/PatientConsentRegistry.fuzz.t.sol -vvv

# только инвариантные тесты (отчёт по handler-вызовам)
forge test --match-path test/PatientConsentRegistry.invariant.t.sol -vvv
```

## Состав тестов

- `test/PatientConsentRegistry.t.sol` — **13 unit-тестов**: happy path, отказ доступа
  (не-регистратор, не-пациент), невалидная подпись, дубликат `consentId`, replay подпись,
  двойной отзыв, пустой хеш, нулевой адрес пациента, `expiresAt <= block.timestamp`
  (граничные значения), динамическая экспирация (`vm.warp`), пауза.
- `test/PatientConsentRegistry.fuzz.t.sol` — **2 fuzz-теста** (512 прогонов каждый):
  произвольные `consentId/docHash/version/expiresAt`; подмена `docHash` при сохранённой подписи.
- `test/PatientConsentRegistry.invariant.t.sol` — **2 инварианта** (256 прогонов, depth 32)
  поверх `Handler` с действиями `register`/`revoke`:
  1. отозванное согласие никогда не возвращается в `ACTIVE`/`EXPIRED` (остаётся ровно `REVOKED`);
  2. `nonces(patient) == число успешных registerConsent` (монотонный рост ровно на 1).
- `test/ConsentRevocationPhishing.t.sol` — **4 PoC-теста** (Задание 3): эксплуатация
  дефекта `tx.origin` контрактом-приманкой `ConsentPhisher` на уязвимой версии,
  контроль прямого вызова, отбивание атаки после исправления, регрессия легитимного отзыва.

## уязвимость и статический анализ

- `src/PatientConsentRegistryVuln.sol` — управляемо уязвимая копия
  (единственный дефект: авторизация в `revokeConsent` по `tx.origin` вместо `msg.sender`).
  Только для локальной сети / тестовой сети.
- `report/slither-report.md` — команды Slither 0.11.6, сводка (72 → 71 находка),
  классификация: реальные / ложные / информационные, сравнение до-после, ограничения.
- `report/slither-vuln-raw.txt`, `report/slither-fixed-raw.txt` — полные сырые отчёты.
- `report/vulnerability-report.md` — первопричина, нарушенное правило, условия
  эксплуатации, последовательность транзакций, PoC-результаты, фикс, остаточные риски.

```shell
# Slither (по одному контракту за раз)
slither src/PatientConsentRegistryVuln.sol \
  --solc-remaps '@openzeppelin/=lib/openzeppelin-contracts/contracts/ forge-std/=lib/forge-std/src/'
slither src/PatientConsentRegistry.sol \
  --solc-remaps '@openzeppelin/=lib/openzeppelin-contracts/contracts/ forge-std/=lib/forge-std/src/'

# PoC-тесты эксплуатации и проверки исправления
forge test --match-path test/ConsentRevocationPhishing.t.sol -vv
```

## Структура проекта

- `src/PatientConsentRegistry.sol` — контракт (AccessControl + Pausable + EIP-712, 2 роли:
  `ADMIN_ROLE`, `REGISTRAR_ROLE`; в блокчейне только `keccak256`-хеш согласия, без ПДн).
- `src/PatientConsentRegistryVuln.sol` — уязвимая версия для Задания 3 (`tx.origin`).
- `test/` — unit/fuzz/invariant/PoC тесты.
- `report/` — отчёты Slither и отчёт об уязвимости (markdown + raw).
- `script/` — скрипты деплоя (local anvil → Sepolia).
