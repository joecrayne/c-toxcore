/*
 * Utilities.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 * This file is donated to the Tox Project.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "logger.h"
#include "crypto_core.h"

#ifdef __cplusplus
extern "C" {
#endif

bool is_power_of_2(uint64_t x);

/* Functions for groupchat extended keys */
const uint8_t *get_enc_key(const uint8_t *key);
const uint8_t *get_sig_pk(const uint8_t *key);
void set_sig_pk(uint8_t *key, const uint8_t *sig_pk);
const uint8_t *get_sig_sk(const uint8_t *key);
void set_sig_sk(uint8_t *key, const uint8_t *sig_sk);
const uint8_t *get_chat_id(const uint8_t *key);


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);

int id_cmp(const uint8_t *first_id, const uint8_t *second_id);

/* compares two group chat_id's */
bool chat_id_equal(const uint8_t *dest, const uint8_t *src);

uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

// For printing purposes
char *id_toa(const uint8_t *id);

void host_to_net(uint8_t *num, uint16_t numbytes);
void net_to_host(uint8_t *num, uint16_t numbytes);

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items);

/* Converts 8 bytes to uint64_t */
void get_be64(uint64_t *dest, const uint8_t *bytes);

/* Converts 4 bytes to uint32_t */
void get_be32(uint32_t *dest, const uint8_t *bytes);

/* Converts 2 bytes to uint16_t */
void get_be16(uint16_t *dest, const uint8_t *bytes);

/* Convert uint64_t to byte string of size 8 */
void put_be64(uint8_t *dest, uint64_t value);

/* Convert uint32_t to byte string of size 4 */
void put_be32(uint8_t *dest, uint32_t value);

/* Convert uint16_t to byte string of size 2 */
void put_be16(uint8_t *dest, uint16_t value);

/* Returns -1 if failed or 0 if success */
int create_recursive_mutex(pthread_mutex_t *mutex);

int32_t max_s32(int32_t a, int32_t b);
int32_t min_s32(int32_t a, int32_t b);
uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

#define IDSTRING_LEN (CRYPTO_PUBLIC_KEY_SIZE * 2 + 1)
char *id_to_string(const uint8_t *pk, char *id_str, size_t length);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_UTIL_H
