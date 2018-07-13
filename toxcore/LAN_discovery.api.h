/*
 * LAN discovery implementation.
 */

#include "DHT.h"

namespace lan_discovery {

/**
 * Interval in seconds between LAN discovery packet sending.
 */
const INTERVAL = 10;

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 */
static int32_t send(uint16_t port, DHT dht);

/**
 * Sets up packet handlers.
 */
static void init(DHT dht);

/**
 * Clear packet handlers.
 */
static void kill(DHT dht);

}

/**
 * Is IP a local ip or not.
 */
static bool ip_is_local(IP ip);

/**
 * checks if a given IP isn't routable
 *
 *  return 0 if ip is a LAN ip.
 *  return -1 if it is not.
 */
static int32_t ip_is_lan(IP ip);
