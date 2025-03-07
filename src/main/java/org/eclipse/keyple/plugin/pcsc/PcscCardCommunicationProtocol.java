/* **************************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.plugin.pcsc;

/**
 * List of contactless protocols and technologies identifiable through PC/SC readers.
 *
 * <p>Each enum value associates a protocol or technology with a specific ATR pattern. These
 * patterns follow the PC/SC standard Part 3 for contactless card identification.
 *
 * <p>The ATR patterns can identify both physical cards and virtual cards emulated by NFC devices.
 *
 * <p>See <a href="https://pcscworkgroup.com/">PC/SC Workgroup</a> for more details.
 *
 * @since 2.5.0
 */
public enum PcscCardCommunicationProtocol {

  /**
   * Any ISO 14443-4 compliant card or device (both Type A and Type B).
   *
   * <p>According to PC/SC specifications, ISO 14443-4 contactless cards have a specific ATR
   * structure:
   *
   * <ul>
   *   <li>TS (Initial character): 0x3B - Direct convention
   *   <li>T0 (Format character): 0x8X - Where X varies based on the number of historical bytes
   *   <li>TD1: 0x80 - Indicates protocol T=0 at first level and presence of TD2
   *   <li>TD2: 0x01 - Indicates final protocol T=1
   * </ul>
   *
   * <p>This structure allows for recognition of both Type A and Type B ISO 14443-4 cards,
   * regardless of the number of historical bytes they contain.
   *
   * <p>Excludes Innovatron B Prime cards which have their own specific category.
   *
   * <p>Default rule = <b>{@code 3B8.8001(?!.*5A0A).*}</b>
   *
   * @since 2.5.0
   */
  ISO_14443_4("3B8.8001(?!.*5A0A).*"),

  /**
   * Calypso cards using Innovatron B Prime protocol.
   *
   * <p>According to PC/SC Part 3, B Prime cards use a specific ATR format:
   *
   * <ul>
   *   <li>Starting with 3B8 followed by any hex digit - Indicating direct convention with a
   *       variable number of historical bytes
   *   <li>Followed by 8001 - Indicating TD1=0x80 and TD2=0x01 (protocol T=1)
   *   <li>Followed immediately by the specific B Prime signature 5A0A in the first historical bytes
   * </ul>
   *
   * <p>Default rule = <b>{@code 3B8.8001(80)?5A0A.*}</b>
   *
   * @since 2.5.0
   */
  INNOVATRON_B_PRIME("3B8.8001(80)?5A0A.*"),

  /**
   * NXP MIFARE Ultralight technologies.
   *
   * <p>According to PC/SC Part 3 Supplemental Document:
   *
   * <ul>
   *   <li>Initial bytes: 3B8F8001804F0CA0000003
   *   <li>Card protocol: 0603 (ISO 14443 A part 3)
   *   <li>Card type: 0003 (for Mifare UL)
   * </ul>
   *
   * <p>Default rule = <b>{@code 3B8F8001804F0CA0000003060300030.*}</b>
   *
   * @since 2.5.0
   */
  MIFARE_ULTRALIGHT("3B8F8001804F0CA0000003060300030.*"),

  /**
   * STMicroelectronics ST25/SRT512 memory tags.
   *
   * <p>According to PC/SC Part 3 Supplemental Document:
   *
   * <ul>
   *   <li>Initial bytes: 3B8F8001804F0CA0000003
   *   <li>Card protocol: 0605, 0606, 0607 (ISO 14443 B part 1/2/3)
   *   <li>Card type: 0007 (ST25 tag)
   * </ul>
   *
   * <p>Default rule = <b>{@code 3B8F8001804F0CA0000003060(5|6|7)0007.*}</b>
   *
   * @since 2.5.0
   */
  ST25_SRT512("3B8F8001804F0CA0000003060(5|6|7)0007.*"),

  /**
   * ISO 7816-3 Card (contact communication protocol)
   *
   * <p>Default rule = <b>{@code 3.*}</b>
   *
   * @since 2.5.0
   */
  ISO_7816_3("3.*");

  private final String defaultRule;

  /**
   * (private-package)<br>
   * Gets the default rule associated to the protocol.
   *
   * @return The regular expression pattern as a String
   * @since 2.0.0
   */
  String getDefaultRule() {
    return defaultRule;
  }

  /**
   * Constructor
   *
   * @param defaultRule The default rule as a regular expression pattern.
   */
  PcscCardCommunicationProtocol(String defaultRule) {
    this.defaultRule = defaultRule;
  }
}
