/* **************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/
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

import javax.smartcardio.Card;
import org.eclipse.keyple.core.common.KeypleReaderExtension;

/**
 * PC/SC specific {@link KeypleReaderExtension}.
 *
 * <p>Provides specific settings and methods for configuring a PC/SC reader.
 *
 * @since 2.0.0
 */
public interface PcscReader extends KeypleReaderExtension {

  /**
   * Connection mode to indicate if the application is willing to share the card with other
   * applications.
   *
   * <p>Corresponds to the beginExclusive() and endExclusive() methods of smartcard.io and, at a
   * lower level, to the connection mode defined by PC/SC and used in the SCardConnect function.
   *
   * @since 2.0.0
   */
  enum SharingMode {
    /**
     * Allows simultaneous access to the card
     *
     * @since 2.0.0
     */
    SHARED,
    /**
     * Requests exclusive access to the card
     *
     * @since 2.0.0
     */
    EXCLUSIVE
  }

  /**
   * Available transmission protocols as defined by the PC/SC standard.
   *
   * @since 2.0.0
   */
  enum IsoProtocol {

    /**
     * to connect using any available protocol
     *
     * @since 2.0.0
     */
    ANY("*"),
    /**
     * to connect using T=0 protocol
     *
     * @since 2.0.0
     */
    T0("T=0"),
    /**
     * to connect using T=1 protocol
     *
     * @since 2.0.0
     */
    T1("T=1"),
    /**
     * to connect using T=CL protocol
     *
     * @since 2.0.0
     */
    TCL("T=CL");

    private final String value;

    /**
     * Constructor.
     *
     * <p>Associates the enum value with its corresponding definition in the PC/SC standard.
     *
     * @param value A string
     * @since 2.0.0
     */
    IsoProtocol(String value) {
      this.value = value;
    }

    /**
     * Gets the string expected by smartcard.io / PC/SC to set the card transmission protocol.
     *
     * @return A not empty string.
     * @since 2.0.0
     */
    public String getValue() {
      return value;
    }
  }

  /**
   * Action to be taken after the card is disconnected.
   *
   * @since 2.0.0
   */
  enum DisconnectionMode {
    /**
     * Resets the card. This sends a reset signal to the card while keeping the connection alive.
     *
     * <p>Corresponds to PC/SC `SCARD_RESET_CARD`.
     *
     * @since 2.0.0
     */
    RESET,

    /**
     * Leaves the card in its current state without performing any reset or power down.
     *
     * <p>Corresponds to PC/SC `SCARD_LEAVE_CARD`.
     *
     * @since 2.0.0
     */
    LEAVE,

    /**
     * Completely powers off the card.
     *
     * <p>Corresponds to PC/SC `SCARD_UNPOWER_CARD`.
     *
     * <p>This mode is only available with the default security provider (jnasmartcardio/cna).
     * Depending on the provider used, a runtime error may occur during reader enumeration.
     *
     * @since 2.5.0
     */
    UNPOWER,

    /**
     * Ejects the card (if supported by the reader).
     *
     * <p>Corresponds to PC/SC `SCARD_EJECT_CARD`.
     *
     * <p>This mode is only available with the default security provider (jnasmartcardio/cna).
     * Depending on the provider used, a runtime error may occur during reader enumeration.
     *
     * @since 2.5.0
     */
    EJECT
  }

  /**
   * Changes the PC/SC sharing mode (default value {@link SharingMode#EXCLUSIVE}).
   *
   * <p>This mode will be used when a new {@link Card} is created.
   *
   * <p>If a card is already inserted, changes immediately the mode in the current {@link Card}
   * object.
   *
   * @param sharingMode The {@link SharingMode} to use (must be not null).
   * @return This instance.
   * @throws IllegalArgumentException If sharingMode is null
   * @throws IllegalStateException If the sharing mode setting failed.
   * @since 2.0.0
   */
  PcscReader setSharingMode(SharingMode sharingMode);

  /**
   * Sets the reader transmission mode.
   *
   * <p>A PC/SC reader can be contact or contactless. There is no way by generic programming to know
   * what type of technology a reader uses.
   *
   * <p>Thus, it is the responsibility of the application to give the reader the means to know his
   * own type.
   *
   * <p>This can be done in two ways:
   *
   * <ul>
   *   <li>by invoking this method,
   *   <li>by giving the plugin the means to determine the type from the name of the reader. In the
   *       latter case, the application does not need to call this method, the reader will determine
   *       its type itself using the plugin parameters (see {@link PcscPluginFactoryBuilder}.
   * </ul>
   *
   * <p>The default mode is the name-based determination performed by the plugin. See {@link
   * PcscPluginFactoryBuilder.Builder#useContactlessReaderIdentificationFilter(String)}.
   *
   * @param contactless true to set contactless mode, false to set contact mode.
   * @return This instance.
   * @since 2.0.0
   */
  PcscReader setContactless(boolean contactless);

  /**
   * Changes the protocol to be used by the PC/SC reader when connecting to the card ({@link
   * IsoProtocol#T0}, {@link IsoProtocol#T1}, or {@link IsoProtocol#TCL}), or {@link
   * IsoProtocol#ANY} to connect using any available protocol (default value {@link
   * IsoProtocol#ANY}).
   *
   * @param isoProtocol The {@link IsoProtocol} to use (must be not null).
   * @return This instance.
   * @throws IllegalArgumentException If isoProtocol is null
   * @since 2.0.0
   */
  PcscReader setIsoProtocol(IsoProtocol isoProtocol);

  /**
   * Changes the action to be taken after disconnection (default value {@link
   * DisconnectionMode#RESET}).
   *
   * <p>The card is either reset or left as is.
   *
   * @param disconnectionMode The {@link DisconnectionMode} to use (must be not null).
   * @return This instance.
   * @throws IllegalArgumentException If disconnectionMode is null
   * @since 2.0.0
   */
  PcscReader setDisconnectionMode(DisconnectionMode disconnectionMode);

  /**
   * Transmits a control command to the terminal device.
   *
   * <p>This can be used to access specific features of the reader such as setting parameters,
   * controlling LEDs, a buzzer or any other proprietary function defined by the reader
   * manufacturer.
   *
   * <p>The supplied command identifier is internally converted into a control code expected by the
   * current platform. Its actual value differs if the platform is Windows.
   *
   * @param commandId The command identifier.
   * @param command A not null byte array containing the command data.
   * @return The response data.
   * @throws IllegalStateException If the communication with the reader has failed.
   * @since 2.1.0
   */
  byte[] transmitControlCommand(int commandId, byte[] command);

  /**
   * Helper method that return the PC/SC IOCTL CCID "Escape" command identifier.
   *
   * <p>The PC/SC IOCTL CCID "Escape" command exists for all platforms but the value of its
   * identifier differs from one to another (3500 for Windows, 1 for linux/MacOS).
   *
   * @return The IOCTL CCID "Escape" command identifier adapted to the OS.
   * @since 2.1.0
   */
  int getIoctlCcidEscapeCommandId();
}
