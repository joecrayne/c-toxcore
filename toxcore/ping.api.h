/*
 * Buffered pinging using cyclic arrays.
 */

#include "crypto_core.h"
#include "DHT.h"
#include "network.h"

class Ping {

static this new(DHT dht);
void kill();

/**
 * Add nodes to the to_ping list.
 *
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int32_t add(const uint8_t[crypto.PUBLIC_KEY_SIZE] public_key, IP_Port ip_port);
void iterate();

int32_t send_request(IP_Port ipp, const uint8_t[crypto.PUBLIC_KEY_SIZE] public_key);

}
