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

import de.intarsys.security.smartcard.pcsc.*;
import de.intarsys.security.smartcard.pcsc.nativec._IPCSC;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import org.eclipse.keyple.core.plugin.*;
import org.eclipse.keyple.core.plugin.spi.reader.ConfigurableReaderSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.ObservableReaderSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.state.insertion.CardInsertionWaiterAsynchronousSpi;
import org.eclipse.keyple.core.plugin.spi.reader.observable.state.removal.CardRemovalWaiterAsynchronousSpi;
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
        PCSCStatusMonitor.IStatusListener,
        ConfigurableReaderSpi,
        ObservableReaderSpi,
        CardInsertionWaiterAsynchronousSpi,
        CardRemovalWaiterAsynchronousSpi {

  private static final Logger logger = LoggerFactory.getLogger(PcscReaderAdapter.class);

  private final IPCSCCardReader pcscCardReader;
  private IPCSCContext connectionContext;
  private IPCSCConnection connection;
  private PCSCStatusMonitor monitor;
  private final String name;
  private final PcscPluginAdapter pluginAdapter;
  private final boolean isWindows;
  private final int cardMonitoringCycleDuration;
  private Boolean isContactless;
  private String protocol = IsoProtocol.ANY.getValue();
  private boolean isModeExclusive = true;
  private DisconnectionMode disconnectionMode = DisconnectionMode.RESET;

  private final AtomicBoolean loopWaitCardRemoval = new AtomicBoolean();
  private CardInsertionWaiterAsynchronousApi cardInsertionCallback;
  private CardRemovalWaiterAsynchronousApi cardRemoveCallback;
  private boolean isMonitoringActive;
  private String atr = "";

  /**
   * Constructor.
   *
   * @since 2.0.0
   */
  PcscReaderAdapter(
      IPCSCCardReader pcscCardReader,
      PcscPluginAdapter pluginAdapter,
      int cardMonitoringCycleDuration) {
    this.pcscCardReader = pcscCardReader;
    this.pluginAdapter = pluginAdapter;
    this.name = pcscCardReader.getName();
    this.isWindows = System.getProperty("os.name").toLowerCase().contains("win");
    this.cardMonitoringCycleDuration = cardMonitoringCycleDuration;
    monitor = new PCSCStatusMonitor(pcscCardReader);
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
    isMonitoringActive = true;
    monitor.addStatusListener(this);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void onStopDetection() {
    isMonitoringActive = false;
    monitor.removeStatusListener(this);
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
    /* init of the card physical channel: if not yet established, opening of a new physical channel */
    try {
      if (connection == null) {
        if (logger.isDebugEnabled()) {
          logger.debug(
              "Reader [{}]: open card physical channel for protocol [{}]", getName(), protocol);
        }
        connectionContext = pcscCardReader.getContext().establishContext();
        connection =
            connectionContext.connect(
                "example",
                pcscCardReader.getName(),
                _IPCSC.SCARD_SHARE_SHARED,
                _IPCSC.SCARD_PROTOCOL_Tx);
        //        if (isModeExclusive) {
        //          connection.beginTransaction();
        //          if (logger.isDebugEnabled()) {
        //            logger.debug("Reader [{}]: open card physical channel in exclusive mode",
        // getName());
        //          }
        //        } else {
        //          if (logger.isDebugEnabled()) {
        //            logger.debug("Reader [{}]: open card physical channel in shared mode",
        // getName());
        //          }
        //        }
      }
    } catch (PCSCException e) {
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
    try {
      if (connection != null) {
        connection.disconnect(_IPCSC.SCARD_LEAVE_CARD);
        connectionContext.dispose();
      } else {
        if (logger.isDebugEnabled()) {
          logger.debug(
              "Reader [{}]: card object found null when closing physical channel", getName());
        }
      }
    } catch (PCSCException e) {
      throw new ReaderIOException("Error while closing physical channel", e);
    } finally {
      connection = null;
      connectionContext = null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean isPhysicalChannelOpen() {
    return connection != null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public boolean checkCardPresence() throws ReaderIOException {
    try {
      return pcscCardReader.getState().isPresent();
    } catch (PCSCException e) {
      throw new ReaderIOException("Exception occurred in isCardPresent", e);
    }
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getPowerOnData() {
    return atr;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public byte[] transmitApdu(byte[] apduCommandData) throws ReaderIOException, CardIOException {
    byte[] apduResponseData;
    if (connection != null) {
      try {
        apduResponseData =
            connection.transmit(apduCommandData, 0, apduCommandData.length, 512, true);
      } catch (IllegalStateException | IllegalArgumentException e) {
        // card could have been removed prematurely
        throw new CardIOException(name + ": " + e.getMessage(), e);
      } catch (PCSCException e) {
        throw new RuntimeException(e);
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
      if (connection != null) {
        try {
          connection.endTransaction(_IPCSC.SCARD_LEAVE_CARD);
        } catch (PCSCException e) {
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
    //    Assert.getInstance().notNull(command, "command");
    //    byte[] response;
    //    int controlCode = isWindows ? 0x00310000 | (commandId << 2) : 0x42000000 | commandId;
    //    try {
    //      if (card != null) {
    //        response = card.transmitControlCommand(controlCode, command);
    //      } else {
    //        Card virtualCard = pcscCardReader.connect("DIRECT");
    //        response = virtualCard.transmitControlCommand(controlCode, command);
    //        virtualCard.disconnect(false);
    //      }
    //    } catch (CardException e) {
    //      throw new IllegalStateException("Reader failure.", e);
    //    }
    //    return response;
    return new byte[0];
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

  @Override
  public void onException(IPCSCCardReader reader, PCSCException e) {}

  @Override
  public void onStatusChange(IPCSCCardReader reader, PCSCCardReaderState cardReaderState) {
    if (isMonitoringActive) {
      if (cardReaderState.isPresent()) {
        try {
          atr = HexUtil.toHex(pcscCardReader.getState().getATR());
        } catch (PCSCException e) {
          // TODO
          throw new RuntimeException(e);
        }
        cardInsertionCallback.onCardInserted();
      } else if (cardReaderState.isEmpty()) {
        cardRemoveCallback.onCardRemoved();
      }
    }
  }

  @Override
  public void setCallback(CardInsertionWaiterAsynchronousApi callback) {
    this.cardInsertionCallback = callback;
  }

  @Override
  public void setCallback(CardRemovalWaiterAsynchronousApi callback) {
    this.cardRemoveCallback = callback;
  }
}
