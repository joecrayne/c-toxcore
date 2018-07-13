/*
 * Implementation of an efficient array to store that we pinged something.
 */

#include "network.h"

class Ping_Array {

/**
 * Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static this new(uint32_t size, uint32_t timeout);

/**
 * Free all the allocated memory in a Ping_Array.
 */
void kill();

/**
 * Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t add(const uint8_t[length] data, uint32_t length);

/**
 * Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int32_t check(uint8_t[length] data, uint32_t length, uint64_t ping_id);

}
