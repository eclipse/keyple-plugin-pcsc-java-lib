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
 * Non-exhaustive list of protocols supported by common contact PC/SC readers.
 *
 * <p>TODO Improve protocol identification
 *
 * @since 2.0.0
 * @deprecated This enum is deprecated and may be removed in future versions. Use {@link
 *     PcscCardCommunicationProtocol} instead.
 */
@Deprecated
public enum PcscSupportedContactProtocol {

  /**
   * ISO7816-3 Card (unspecified communication protocol)<br>
   * Default rule = <b>{@code 3.*}</b>
   *
   * @since 2.0.0
   */
  ISO_7816_3("3.*"),
  /**
   * ISO7816-3 Card communicating with T=0 protocol<br>
   * Default rule = <b>{@code 3.*}</b>
   *
   * @since 2.0.0
   */
  ISO_7816_3_T0("3.*"),
  /**
   * ISO7816-3 Card communicating with T=1 protocol<br>
   * Default rule = <b>{@code 3.*}</b>
   *
   * @since 2.0.0
   */
  ISO_7816_3_T1("3.*");

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
   * @since 2.0.0
   */
  PcscSupportedContactProtocol(String defaultRule) {
    this.defaultRule = defaultRule;
  }
}
