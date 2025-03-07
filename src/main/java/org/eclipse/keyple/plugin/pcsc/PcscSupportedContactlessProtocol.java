/* **************************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://calypsonet.org/
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
 * Non-exhaustive list of protocols supported by common contactless PC/SC readers.
 *
 * <p>Tested with
 *
 * <ul>
 *   <li>Paragon ASK LoGo
 *   <li>ACS ACR 122
 * </ul>
 *
 * <p><b>Note:</b> the definition of ATR for contactless ISO cards and memory cards (a.k.a. storage
 * cards) is defined in the PC/SC standard Part 3, core and supplementary documents. <br>
 * See <a href="https://pcscworkgroup.com/">PC/SC Workgroup</a>
 *
 * @since 2.0.0
 * @deprecated This enum is deprecated and may be removed in future versions. Use {@link
 *     PcscCardCommunicationProtocol} instead.
 */
@Deprecated
public enum PcscSupportedContactlessProtocol {

  /**
   * Fully ISO 14443-4 compliant cards<br>
   * Default rule = <b>{@code
   * 3B8880....................|3B8B80.*|3B8C800150.*|.*4F4D4141544C4153.*}</b>
   *
   * @since 2.0.0
   */
  ISO_14443_4("3B8880....................|3B8B80.*|3B8C800150.*|.*4F4D4141544C4153.*"),
  /**
   * Innovatron Type B Prime protocol<br>
   * Default rule = <b>{@code 3B8F8001805A0...................829000..}</b>
   *
   * @since 2.0.0
   */
  INNOVATRON_B_PRIME_CARD("3B8F8001805A0...................829000.."),
  /**
   * NXP Mifare Ultralight or UltralightC (as per PC/SC standard part3)<br>
   * Default rule = <b>{@code 3B8F8001804F0CA0000003060300030000000068}</b>
   *
   * @since 2.0.0
   */
  MIFARE_ULTRA_LIGHT("3B8F8001804F0CA0000003060300030000000068"),
  /**
   * NXP Mifare Classic 1K (as per PC/SC standard part3)<br>
   * Default rule = <b>{@code 3B8F8001804F0CA000000306030001000000006A}</b>
   *
   * @since 2.0.0
   */
  MIFARE_CLASSIC("3B8F8001804F0CA000000306030001000000006A"),
  /**
   * NXP DESFire or DESFire EV1 or EV2<br>
   * Default rule = <b>{@code 3B8180018080}</b>
   *
   * @since 2.0.0
   */
  MIFARE_DESFIRE("3B8180018080"),
  /**
   * STMicroelectronics ST25 Tag<br>
   * Default rule = <b>{@code 3B8F8001804F0CA000000306070007D0020C00B6}</b>
   *
   * @since 2.0.0
   */
  MEMORY_ST25("3B8F8001804F0CA000000306070007D0020C00B6");

  private final String defaultRule;

  /**
   * (private-package)<br>
   * Gets the default associated to the protocol.
   *
   * @return A byte
   * @since 2.0.0
   */
  String getDefaultRule() {
    return defaultRule;
  }

  /**
   * Constructor
   *
   * @param defaultRule The default rule.
   */
  PcscSupportedContactlessProtocol(String defaultRule) {
    this.defaultRule = defaultRule;
  }
}
