# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Introduced new enum `PcscCardCommunicationProtocol` that unifies contact and contactless protocol handling:
  - `ISO_14443_4`: For all ISO 14443-4 compliant cards (Type A and Type B)
  - `INNOVATRON_B_PRIME`: For Calypso devices using B Prime protocol
  - `MIFARE_ULTRALIGHT`: For NXP MIFARE Ultralight and UltralightC technologies
  - `ST25_SRT512`: For STMicroelectronics ST25 memory tags
  - `ISO_7816_3`: For contact cards using ISO 7816-3 protocol
- Implemented precise ATR pattern rules aligned with PC/SC Part 3 standards
- Added comprehensive documentation with references to PC/SC specifications
- Enhanced `PcscReader.DisconnectionMode` enum with additional modes:
  - `UNPOWER`: Powers off the card completely (corresponds to PC/SC `SCARD_UNPOWER_CARD`)
  - `EJECT`: Ejects the card if supported by the reader (corresponds to PC/SC `SCARD_EJECT_CARD`)
### Deprecated
- Marked `PcscSupportedContactlessProtocol` as deprecated, to be replaced by `PcscCardCommunicationProtocol`
- Marked `PcscSupportedContactProtocol` as deprecated, to be replaced by `PcscCardCommunicationProtocol`
### Changed
- Updated security provider from `jnasmartcardio` to `jnasmartcardio/cna` version `0.3.0`

## [2.4.2] - 2025-01-27
### Fixed
- Correct card disconnection logic when a card was present and `checkCardPresence()` is called.

## [2.4.1] - 2025-01-22
### Fixed
- Ensures the physical channel is re-established when `checkCardPresence()` (required by the plugin API) is called, in
  case a card was previously connected.

## [2.4.0] - 2024-10-08
### Added
- Added a new method `setProvider(Provider provider)` in `PcscPluginFactoryBuilder` to allow the use of a custom PC/SC
  provider.

## [2.3.1] - 2024-10-01
### Fixed
- Avoid creating multiple contexts when monitoring readers.

## [2.3.0] - 2024-09-24
### Fixed
- Use `jnasmartcardio` lib built with Java 8.
### Added
- Add configurable card monitoring cycle duration through a new method
  `setCardMonitoringCycleDuration(int cycleDuration)` to set the card monitoring cycle duration
  in `PcscPluginFactoryBuilder`, enabling customization of the default 500ms value. Especially useful under Linux
  environments.

## [2.2.3] - 2024-09-18
### Fixed
- Force `net.java.dev.jna:jna:5.15.0` to bypass bug [JDK-8313765](https://bugs.openjdk.org/browse/JDK-8313765).
- Embed `jnasmartcardio-0.2.8-SNAPSHOT.jar` until an official release is published.

## [2.2.2] - 2024-09-16
### Fixed
- Fixed **smartcardio** weaknesses by using [jnasmartcardio](https://github.com/jnasmartcardio/jnasmartcardio) as provider.
- Fixed errors in the distinction between **Reader IO** and **Card IO** exceptions.
### Changed
- Logging improvement.

## [2.2.1] - 2024-04-12
### Changed
- Java source and target levels `1.6` -> `1.8`
### Upgraded
- Gradle `6.8.3` -> `7.6.4`

## [2.2.0] - 2024-03-29
### Added
- Added a note to warn about observability issues when using **Java 16+** to `README.md` file.
- Added project status badges on `README.md` file.
### Fixed
- CI: code coverage report when releasing.
- Documentation of `setDisconnectionMode` (the default value indicated was incorrect).
### Upgraded
- Keyple Plugin API `2.0.0` -> `2.3.0`
- Keyple Util Library `2.3.0` -> `2.3.1` (source code not impacted)

## [2.1.2] - 2023-04-24
### Fixed
- Unnecessary logging in Java 16+ during reflexive calls used to overcome the deficiencies of `smartcard.io` in Windows 
environment.

## [2.1.1] - 2023-04-05
### Changed
- `PcscPluginFactoryBuilder.useContactReaderIdentificationFilter` method marked as deprecated.
### Fixed
- Use default reader type identification filters.
- Logging of the available readers names in the `AbstractPcscPluginAdapter` class.

## [2.1.0] - 2022-07-25
### Added
- `PcscReader.transmitControlCommand` and `PcscReader.getIoctlCcidEscapeCommandId` methods (issue [#9]).
- "CHANGELOG.md" file (issue [eclipse-keyple/keyple#6]).
- CI: Forbid the publication of a version already released (issue [#6]).
### Upgraded
- "Keyple Util Library" to version `2.1.0` by removing the use of deprecated methods.
### Fixed
- Setting the smartcard.io path in the case of MacOS platform.

## [2.0.0] - 2021-10-06
This is the initial release.
It follows the extraction of Keyple 1.0 components contained in the `eclipse-keyple/keyple-java` repository to dedicated repositories.
It also brings many major API changes.

[unreleased]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.4.2...HEAD
[2.4.2]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.4.1...2.4.2
[2.4.1]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.4.0...2.4.1
[2.4.0]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.3.1...2.4.0
[2.3.1]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.3.0...2.3.1
[2.3.0]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.2.3...2.3.0
[2.2.3]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.2.2...2.2.3
[2.2.2]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.2.1...2.2.2
[2.2.1]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.1.2...2.2.0
[2.1.2]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.1.1...2.1.2
[2.1.1]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.1.0...2.1.1
[2.1.0]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/releases/tag/2.0.0

[#9]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/issues/9
[#6]: https://github.com/eclipse-keyple/keyple-plugin-pcsc-java-lib/issues/6

[eclipse-keyple/keyple#6]: https://github.com/eclipse-keyple/keyple/issues/6
