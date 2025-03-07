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

import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import org.eclipse.keyple.core.plugin.PluginIOException;
import org.eclipse.keyple.core.plugin.spi.ObservablePluginSpi;
import org.eclipse.keyple.core.plugin.spi.reader.ReaderSpi;
import org.eclipse.keyple.core.util.json.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link PcscPlugin}.
 *
 * @since 2.0.0
 */
final class PcscPluginAdapter implements PcscPlugin, ObservablePluginSpi {

  private static final Logger logger = LoggerFactory.getLogger(PcscPluginAdapter.class);

  /**
   * Singleton instance of the class
   *
   * <p>'volatile' qualifier ensures that read access to the object will only be allowed once the
   * object has been fully initialized. <br>
   * This qualifier is required for "lazy-singleton" pattern with double-check method, to be
   * thread-safe.
   */
  private static volatile PcscPluginAdapter INSTANCE; // NOSONAR: lazy-singleton pattern.

  private static final int MONITORING_CYCLE_DURATION_MS = 1000;

  private static final Map<String, String> protocolRulesMap = new ConcurrentHashMap<>();

  // initializes the protocol rules map with default values
  static {
    // contactless protocols
    protocolRulesMap.put(
        PcscCardCommunicationProtocol.ISO_14443_4.name(),
        PcscCardCommunicationProtocol.ISO_14443_4.getDefaultRule());
    protocolRulesMap.put(
        PcscCardCommunicationProtocol.INNOVATRON_B_PRIME.name(),
        PcscCardCommunicationProtocol.INNOVATRON_B_PRIME.getDefaultRule());
    protocolRulesMap.put(
        PcscCardCommunicationProtocol.MIFARE_ULTRALIGHT.name(),
        PcscCardCommunicationProtocol.MIFARE_ULTRALIGHT.getDefaultRule());
    protocolRulesMap.put(
        PcscCardCommunicationProtocol.ST25_SRT512.name(),
        PcscCardCommunicationProtocol.ST25_SRT512.getDefaultRule());

    // contacts protocols
    protocolRulesMap.put(
        PcscCardCommunicationProtocol.ISO_7816_3.name(),
        PcscCardCommunicationProtocol.ISO_7816_3.getDefaultRule());

    // legacy protocols for compatibility
    protocolRulesMap.put(
        PcscSupportedContactProtocol.ISO_7816_3_T0.name(),
        PcscSupportedContactProtocol.ISO_7816_3_T0.getDefaultRule());
    protocolRulesMap.put(
        PcscSupportedContactProtocol.ISO_7816_3_T1.name(),
        PcscSupportedContactProtocol.ISO_7816_3_T1.getDefaultRule());
  }

  private CardTerminals terminals;
  private boolean isCardTerminalsInitialized;

  private Pattern contactlessReaderIdentificationFilterPattern;
  private int cardMonitoringCycleDuration;

  /** Constructor. */
  PcscPluginAdapter() {}

  /**
   * Gets the single instance.
   *
   * @return This instance.
   * @since 2.0.0
   */
  static PcscPluginAdapter getInstance() {
    if (INSTANCE == null) {
      synchronized (PcscPluginAdapter.class) {
        if (INSTANCE == null) {
          INSTANCE = new PcscPluginAdapter();
        }
      }
    }
    return INSTANCE;
  }

  /**
   * Creates a new instance of {@link ReaderSpi} from a {@link CardTerminal}.
   *
   * <p>Note: this method is platform dependent.
   *
   * @param terminal A smartcard.io {@link CardTerminal}.
   * @return A not null reference.
   * @since 2.0.0
   */
  PcscReaderAdapter createReader(CardTerminal terminal) {
    return new PcscReaderAdapter(terminal, this, cardMonitoringCycleDuration);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public int getMonitoringCycleDuration() {
    return MONITORING_CYCLE_DURATION_MS;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public Set<String> searchAvailableReaderNames() throws PluginIOException {
    Set<String> readerNames = new HashSet<>();
    if (logger.isTraceEnabled()) {
      logger.trace("Plugin [{}]: search available reader", getName());
    }
    for (CardTerminal terminal : getCardTerminalList()) {
      readerNames.add(terminal.getName());
    }
    if (logger.isTraceEnabled()) {
      logger.trace("Plugin [{}]: readers found: {}", getName(), JsonUtil.toJson(readerNames));
    }
    return readerNames;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public String getName() {
    return PcscPluginFactoryAdapter.PLUGIN_NAME;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public Set<ReaderSpi> searchAvailableReaders() throws PluginIOException {
    Set<ReaderSpi> readerSpis = new HashSet<>();
    logger.info("Plugin [{}]: search available readers", getName());
    for (CardTerminal terminal : getCardTerminalList()) {
      readerSpis.add(createReader(terminal));
    }
    for (ReaderSpi readerSpi : readerSpis) {
      logger.info("Plugin [{}]: reader found: [{}]", getName(), readerSpi.getName());
    }
    return readerSpis;
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public void onUnregister() {
    /* Nothing to do here in this plugin */
  }

  /**
   * (private) Gets the list of terminals provided by smartcard.io.
   *
   * <p>The aim is to handle the exception possibly raised by the underlying smartcard.io method.
   *
   * @return An empty list if no reader is available.
   * @throws PluginIOException If an error occurs while accessing the list.
   */
  private List<CardTerminal> getCardTerminalList() throws PluginIOException {

    // parse the current readers list to create the ReaderSpi(s) associated with new reader(s)
    try {
      if (!isCardTerminalsInitialized) {
        terminals = TerminalFactory.getDefault().terminals();
        isCardTerminalsInitialized = true;
      }
      return terminals.list();
    } catch (Exception e) {
      if (e.getMessage().contains("SCARD_E_NO_READERS_AVAILABLE")) {
        logger.error("Plugin [{}]: no reader available", getName());
      } else if (e.getMessage().contains("SCARD_E_NO_SERVICE")
          || e.getMessage().contains("SCARD_E_SERVICE_STOPPED")) {
        logger.error("Plugin [{}]: no smart card service error", getName());
        // the CardTerminals object is no more valid
        isCardTerminalsInitialized = false;
      } else if (e.getMessage().contains("SCARD_F_COMM_ERROR")) {
        logger.error("Plugin [{}]: reader communication error", getName());
      } else {
        throw new PluginIOException("Could not access terminals list", e);
      }
    }
    return new ArrayList<>(0);
  }

  /**
   * {@inheritDoc}
   *
   * @since 2.0.0
   */
  @Override
  public ReaderSpi searchReader(String readerName) throws PluginIOException {
    if (logger.isTraceEnabled()) {
      logger.trace("Plugin [{}]: search reader [{}]", getName(), readerName);
    }
    for (CardTerminal terminal : getCardTerminalList()) {
      if (readerName.equals(terminal.getName())) {
        if (logger.isTraceEnabled()) {
          logger.trace("Plugin [{}]: reader found", getName());
        }
        return createReader(terminal);
      }
    }
    if (logger.isTraceEnabled()) {
      logger.trace("Plugin [{}]: reader not found", getName());
    }
    return null;
  }

  /**
   * Gets the protocol rule associated to the provided protocol.
   *
   * <p>The protocol rule is a regular expression to be applied on the ATR.
   *
   * @param readerProtocol The reader protocol.
   * @return Null if no protocol rules defined for the provided protocol.
   * @since 2.0.0
   */
  String getProtocolRule(String readerProtocol) {
    return protocolRulesMap.get(readerProtocol);
  }

  /**
   * Attempts to determine the transmission mode of the reader whose name is provided.<br>
   * This determination is made by a test based on a regular expression.
   *
   * @param readerName A string containing the reader name
   * @return True if the reader is contactless, false if not.
   * @since 2.0.0
   */
  boolean isContactless(String readerName) {
    return contactlessReaderIdentificationFilterPattern.matcher(readerName).matches();
  }

  /**
   * Sets the filter to identify contactless readers.
   *
   * @param contactlessReaderIdentificationFilterPattern A regular expression pattern.
   * @return The object instance.
   * @since 2.0.0
   */
  PcscPluginAdapter setContactlessReaderIdentificationFilterPattern(
      Pattern contactlessReaderIdentificationFilterPattern) {
    this.contactlessReaderIdentificationFilterPattern =
        contactlessReaderIdentificationFilterPattern;
    return this;
  }

  /**
   * Adds a map of rules to the current default map.
   *
   * <p>Already existing items are overridden, new items are added.
   *
   * @param protocolRulesMap The regex based filter.
   * @return The object instance.
   * @since 2.0.0
   */
  PcscPluginAdapter addProtocolRulesMap(Map<String, String> protocolRulesMap) {
    if (!protocolRulesMap.isEmpty()) {
      logger.info(
          "Plugin [{}]: add protocol identification rules: {}",
          getName(),
          JsonUtil.toJson(protocolRulesMap));
    } else {
      logger.info("Plugin [{}]: use default protocol identification rules", getName());
    }
    PcscPluginAdapter.protocolRulesMap.putAll(protocolRulesMap);
    return this;
  }

  /**
   * Sets the cycle duration for card presence/absence monitoring.
   *
   * @param cardMonitoringCycleDuration The duration of the card monitoring cycle in milliseconds.
   * @return The object instance.
   * @since 2.3.0
   */
  PcscPluginAdapter setCardMonitoringCycleDuration(int cardMonitoringCycleDuration) {
    this.cardMonitoringCycleDuration = cardMonitoringCycleDuration;
    return this;
  }

  /**
   * Sets the security provider to be used and inserts it at the first position.
   *
   * @param provider The security provider to be set.
   * @return The object instance.
   * @since 2.4.0
   */
  PcscPluginAdapter setProvider(Provider provider) {
    Security.insertProviderAt(provider, 1);
    return this;
  }
}
