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

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import javax.smartcardio.*;
import jnasmartcardio.Smartcardio;
import org.eclipse.keyple.core.plugin.CardIOException;
import org.eclipse.keyple.core.plugin.ReaderIOException;
import org.eclipse.keyple.core.plugin.TaskCanceledException;
import org.eclipse.keyple.core.plugin.spi.reader.ConfigurableReaderSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.ObservableReaderSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.state.insertion.CardInsertionWaiterBlockingSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.state.processing.CardPresenceMonitorBlockingSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.state.removal.CardRemovalWaiterBlockingSpi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link PcscReaderAdapter}.
 *
 * @since 2.0.0
 */
final class PcscReaderAdapter
    implements PcscReader,
        ConfigurableReaderSpi,
        ObservableReaderSpi,
        CardInsertionWaiterBlockingSpi,
        CardPresenceMonitorBlockingSpi,
        CardRemovalWaiterBlockingSpi {

  private static final Logger logger = LoggerFactory.getLogger(PcscReaderAdapter.class);

  private final CardTerminal terminal;
  private final String name;
  private final PcscPluginAdapter pluginAdapter;
  private final boolean isWindows;
  private final int cardMonitoringCycleDuration;
  private final byte[] pingApdu = HexUtil.toByteArray("00C0000000"); // GET RESPONSE
  private Card card;
  private CardChannel channel;
  private Boolean isContactless;
  private String protocol = IsoProtocol.ANY.getValue();
  private boolean isModeExclusive = true;
  private DisconnectionMode disconnectionMode = DisconnectionMode.RESET;
  private final AtomicBoolean loopWaitCard = new AtomicBoolean();

  private final AtomicBoolean loopWaitCardRemoval = new AtomicBoolean();
  private boolean isObservationActive;

  /**
   * Constructor.
   *
   * @since 2.0.0
   */
  PcscReaderAdapter(
      CardTerminal terminal, PcscPluginAdapter pluginAdapter, int cardMonitoringCycleDuration) {
    this.terminal = terminal;
    this.pluginAdapter = pluginAdapter;
    this.name = terminal.getName();
    this.isWindows = System.getProperty("os.name").toLowerCase().contains("win");
    this.cardMonitoringCycleDuration = cardMonitoringCycleDuration;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void waitForCardInsertion() throws TaskCanceledException, ReaderIOException {

    if (logger.isTraceEnabled()) {
      logger.trace(
          "Reader [{}]: start waiting card insertion (loop latency: {} ms)",
          getName(),
          cardMonitoringCycleDuration);
    }

    // activate loop
    loopWaitCard.set(true);

    try {
      while (loopWaitCard.get()) {
        if (terminal.waitForCardPresent(cardMonitoringCycleDuration)) {
          // card inserted
          if (logger.isTraceEnabled()) {
            logger.trace("Reader [{}]: card inserted", getName());
          }
          return;
        }
        if (Thread.interrupted()) {
          break;
        }
      }
      if (logger.isTraceEnabled()) {
        logger.trace("Reader [{}]: waiting card insertion stopped", getName());
      }
    } catch (CardException e) {
      // here, it is a communication failure with the reader
      throw new ReaderIOException(
          name + ": an error occurred while waiting for a card insertion", e);
    }
    throw new TaskCanceledException(
        name + ": the wait for a card insertion task has been cancelled");
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void stopWaitForCardInsertion() {
    loopWaitCard.set(false);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isProtocolSupported(String readerProtocol) {
    return pluginAdapter.getProtocolRule(readerProtocol) != null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void activateProtocol(String readerProtocol) {
    if (logger.isTraceEnabled()) {
      logger.trace(
          "Reader [{}]: activating protocol [{}] takes no action", getName(), readerProtocol);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void deactivateProtocol(String readerProtocol) {
    if (logger.isTraceEnabled()) {
      logger.trace(
          "Reader [{}]: de-activating protocol [{}] takes no action", getName(), readerProtocol);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isCurrentProtocol(String readerProtocol) {
    String protocolRule = pluginAdapter.getProtocolRule(readerProtocol);
    boolean isCurrentProtocol;
    if (protocolRule != null && !protocolRule.isEmpty()) {
      String atr = HexUtil.toHex(card.getATR().getBytes());
      isCurrentProtocol = Pattern.compile(protocolRule).matcher(atr).matches();
    } else {
      isCurrentProtocol = false;
    }
    return isCurrentProtocol;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void onStartDetection() {
    isObservationActive = true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void onStopDetection() {
    isObservationActive = false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void openPhysicalChannel() throws ReaderIOException {
    if (card != null) {
      return;
    }
    /* init of the card physical channel: if not yet established, opening of a new physical channel */
    try {
      if (logger.isDebugEnabled()) {
        logger.debug(
            "Reader [{}]: open card physical channel for protocol [{}]", getName(), protocol);
      }
      card = this.terminal.connect(protocol);
      if (isModeExclusive) {
        card.beginExclusive();
        if (logger.isDebugEnabled()) {
          logger.debug("Reader [{}]: open card physical channel in exclusive mode", getName());
        }
      } else {
        if (logger.isDebugEnabled()) {
          logger.debug("Reader [{}]: open card physical channel in shared mode", getName());
        }
      }
      channel = card.getBasicChannel();
    } catch (CardException e) {
      throw new ReaderIOException(getName() + ": Error while opening Physical Channel", e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void closePhysicalChannel() throws ReaderIOException {
    // If the reader is observed, the actual disconnection will be done in the card removal sequence
    if (!isObservationActive) {
      disconnect();
    }
  }

  /**
   * Disconnects the current card and resets the context and reader state.
   *
   * <p>This method handles the disconnection of a card, taking into account the specific
   * disconnection mode. If the card is an instance of {@link Smartcardio.JnaCard}, it disconnects
   * using the extended mode specified by {@link #getDisposition(DisconnectionMode)} and resets the
   * reader state to avoid incorrect card detection in subsequent operations. For other card types,
   * it disconnects using the specified disconnection mode directly.
   *
   * <p>If a {@link CardException} occurs during the operation, a {@link ReaderIOException} is
   * thrown with the associated error message.
   *
   * <p>Once the disconnection is handled, the method ensures that the context is reset.
   *
   * @throws ReaderIOException If an error occurs while closing the physical channel.
   */
  private void disconnect() throws ReaderIOException {
    try {
      if (card != null) {
        if (card instanceof Smartcardio.JnaCard) {
          // disconnect using the extended mode allowing UNPOWER
          ((Smartcardio.JnaCard) card).disconnect(getDisposition(disconnectionMode));
          // reset the reader state to avoid bad card detection next time
          resetReaderState();
        } else {
          card.disconnect(disconnectionMode == DisconnectionMode.RESET);
        }
      }
    } catch (CardException e) {
      throw new ReaderIOException("Error while closing physical channel", e);
    } finally {
      resetContext();
    }
  }

  /**
   * Maps a DisconnectionMode to the corresponding SCARD_* constant.
   *
   * @param mode The disconnection mode.
   * @return The corresponding SCARD_* value.
   */
  private static int getDisposition(DisconnectionMode mode) {
    switch (mode) {
      case RESET:
        return Smartcardio.JnaCard.SCARD_RESET_CARD;
      case LEAVE:
        return Smartcardio.JnaCard.SCARD_LEAVE_CARD;
      case UNPOWER:
        return Smartcardio.JnaCard.SCARD_UNPOWER_CARD;
      case EJECT:
        return Smartcardio.JnaCard.SCARD_EJECT_CARD;
      default:
        throw new IllegalArgumentException("Unknown DisconnectionMode: " + mode);
    }
  }

  /**
   * Resets the state of the card reader.
   *
   * <p>This method attempts to reset the reader state based on the current disconnection mode. If
   * the disconnection mode is set to UNPOWER, it reconnects to the terminal and then disconnects
   * without powering off the reader. If any {@link CardException} occurs during this process, it is
   * handled silently.
   */
  private void resetReaderState() {
    try {
      if (disconnectionMode == DisconnectionMode.UNPOWER) {
        terminal.connect("*").disconnect(false);
      }
    } catch (CardException e) {
      // NOP
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isPhysicalChannelOpen() {
    return card != null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean checkCardPresence() throws ReaderIOException {
    try {
      boolean isCardPresent = terminal.isCardPresent();
      closePhysicalChannelSafely();
      return isCardPresent;
    } catch (CardException e) {
      throw new ReaderIOException("Exception occurred in isCardPresent", e);
    }
  }

  private void closePhysicalChannelSafely() {
    try { // NOSONAR
      if (card != null) {
        // Force reconnection next time
        // Do not reset the card after disconnecting
        card.disconnect(false);
      }
    } catch (Exception e) {
      // NOP
    } finally {
      resetContext();
    }
  }

  private void resetContext() {
    card = null;
    channel = null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getPowerOnData() {
    return HexUtil.toHex(card.getATR().getBytes());
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] transmitApdu(byte[] apduCommandData) throws ReaderIOException, CardIOException {
    byte[] apduResponseData;
    if (channel != null) {
      try {
        apduResponseData = channel.transmit(new CommandAPDU(apduCommandData)).getBytes();
      } catch (CardNotPresentException e) {
        throw new CardIOException(name + ": " + e.getMessage(), e);
      } catch (CardException e) {
        if (e.getMessage().contains("CARD")
            || e.getMessage().contains("NOT_TRANSACTED")
            || e.getMessage().contains("INVALID_ATR")) {
          throw new CardIOException(name + ": " + e.getMessage(), e);
        } else {
          throw new ReaderIOException(name + ": " + e.getMessage(), e);
        }
      } catch (IllegalStateException | IllegalArgumentException e) {
        // card could have been removed prematurely
        throw new CardIOException(name + ": " + e.getMessage(), e);
      }
    } else {
      // could occur if the card was removed
      throw new CardIOException(name + ": null channel.");
    }
    return apduResponseData;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isContactless() {
    if (isContactless == null) {
      // First time initialisation, the transmission mode has not yet been determined or fixed
      // explicitly, let's ask the plugin to determine it (only once)
      isContactless = pluginAdapter.isContactless(getName());
    }
    return isContactless;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void onUnregister() {
    /* Nothing to do here in this reader */
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void monitorCardPresenceDuringProcessing()
      throws ReaderIOException, TaskCanceledException {
    waitForCardRemoval();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void stopCardPresenceMonitoringDuringProcessing() {
    stopWaitForCardRemoval();
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void waitForCardRemoval() throws ReaderIOException, TaskCanceledException {
    if (logger.isTraceEnabled()) {
      logger.trace("Reader [{}]: start waiting card removal)", name);
    }
    loopWaitCardRemoval.set(true);
    try {
      if (disconnectionMode == DisconnectionMode.UNPOWER) {
        waitForCardRemovalByPolling();
      } else {
        waitForCardRemovalStandard();
      }
    } finally {
      try {
        disconnect();
      } catch (Exception e) {
        logger.warn("Error while disconnecting card during card removal: {}", e.getMessage());
      }
    }
    if (logger.isTraceEnabled()) {
      if (!loopWaitCardRemoval.get()) {
        logger.trace("Reader [{}]: waiting card removal stopped", name);
      } else {
        logger.trace("Reader [{}]: card removed", name);
      }
    }
    if (!loopWaitCardRemoval.get()) {
      throw new TaskCanceledException(
          name + ": the wait for the card removal task has been cancelled.");
    }
  }

  private void waitForCardRemovalByPolling() throws ReaderIOException {
    try {
      while (loopWaitCardRemoval.get()) {
        transmitApdu(pingApdu);
        Thread.sleep(25);
        if (Thread.interrupted()) {
          return;
        }
      }
    } catch (CardIOException | ReaderIOException e) {
      logger.trace("Expected IOException while waiting for card removal: {}", e.getMessage());
    } catch (InterruptedException e) {
      logger.trace("InterruptedException while waiting for card removal: {}", e.getMessage());
      Thread.currentThread().interrupt();
    }
  }

  private void waitForCardRemovalStandard() throws ReaderIOException {
    try {
      while (loopWaitCardRemoval.get()) {
        if (terminal.waitForCardAbsent(cardMonitoringCycleDuration)) {
          return;
        }
        if (Thread.interrupted()) {
          return;
        }
      }
    } catch (CardException e) {
      throw new ReaderIOException(
          name + ": an error occurred while waiting for the card removal.", e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void stopWaitForCardRemoval() {
    loopWaitCardRemoval.set(false);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The default value is {@link SharingMode#EXCLUSIVE}.
   *
   * @since 2.0.0
   */
  @Override
  public PcscReader setSharingMode(SharingMode sharingMode) {
    Assert.getInstance().notNull(sharingMode, "sharingMode");
    logger.info("Reader [{}]: set sharing mode to [{}]", getName(), sharingMode.name());
    if (sharingMode == SharingMode.SHARED) {
      // if a card is present, change the mode immediately
      if (card != null) {
        try {
          card.endExclusive();
        } catch (CardException e) {
          throw new IllegalStateException("Couldn't disable exclusive mode", e);
        }
      }
      isModeExclusive = false;
    } else if (sharingMode == SharingMode.EXCLUSIVE) {
      isModeExclusive = true;
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public PcscReader setContactless(boolean contactless) {
    logger.info("Reader [{}]: set contactless type to [{}]", getName(), contactless);
    this.isContactless = contactless;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public PcscReader setIsoProtocol(IsoProtocol isoProtocol) {
    Assert.getInstance().notNull(isoProtocol, "isoProtocol");
    logger.info(
        "Reader [{}]: set ISO protocol to [{}] ({})",
        getName(),
        isoProtocol.name(),
        isoProtocol.getValue());
    protocol = isoProtocol.getValue();
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public PcscReader setDisconnectionMode(DisconnectionMode disconnectionMode) {
    Assert.getInstance().notNull(disconnectionMode, "disconnectionMode");
    logger.info("Reader [{}]: set disconnection mode to [{}]", getName(), disconnectionMode.name());
    this.disconnectionMode = disconnectionMode;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] transmitControlCommand(int commandId, byte[] command) {
    Assert.getInstance().notNull(command, "command");
    byte[] response;
    int controlCode = isWindows ? 0x00310000 | (commandId << 2) : 0x42000000 | commandId;
    try {
      if (card != null) {
        response = card.transmitControlCommand(controlCode, command);
      } else {
        Card virtualCard = terminal.connect("DIRECT");
        response = virtualCard.transmitControlCommand(controlCode, command);
        virtualCard.disconnect(false);
      }
    } catch (CardException e) {
      throw new IllegalStateException("Reader failure.", e);
    }
    return response;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getIoctlCcidEscapeCommandId() {
    return isWindows ? 3500 : 1;
  }
}
