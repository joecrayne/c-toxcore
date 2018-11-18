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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "util.h"

#include "crypto_core.h" /* for CRYPTO_PUBLIC_KEY_SIZE */
#include "DHT.h"
#include "network.h" /* for current_time_monotonic */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

bool is_power_of_2(uint64_t x)
{
    return x != 0 && (x & (~x + 1)) == x;
}


const uint8_t *get_enc_key(const uint8_t *key)
{
    return key;
}

const uint8_t *get_sig_pk(const uint8_t *key)
{
    return key + ENC_PUBLIC_KEY;
}

void set_sig_pk(uint8_t *key, const uint8_t *sig_pk)
{
    memcpy(key + ENC_PUBLIC_KEY, sig_pk, SIG_PUBLIC_KEY);
}

const uint8_t *get_sig_sk(const uint8_t *key)
{
    return key + ENC_SECRET_KEY;
}

void set_sig_sk(uint8_t *key, const uint8_t *sig_sk)
{
    memcpy(key + ENC_SECRET_KEY, sig_sk, SIG_SECRET_KEY);
}

const uint8_t *get_chat_id(const uint8_t *key)
{
    return key + ENC_PUBLIC_KEY;
}


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return public_key_cmp(dest, src) == 0;
}

int id_cmp(const uint8_t *first_id, const uint8_t *second_id)
{
    return memcmp(first_id, second_id, ENC_PUBLIC_KEY);
}

bool chat_id_equal(const uint8_t *dest, const uint8_t *src)
{
    return memcmp(dest, src, CHAT_ID_SIZE) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
    return CRYPTO_PUBLIC_KEY_SIZE;
}

/* id_str should be of length at least IDSTRING_LEN */
char *id_to_string(const uint8_t *pk, char *id_str, size_t length)
{
    if (length < IDSTRING_LEN) {
        snprintf(id_str, length, "Bad buf length");
        return id_str;
    }

    for (uint32_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        sprintf(&id_str[i * 2], "%02X", pk[i]);
    }

    id_str[CRYPTO_PUBLIC_KEY_SIZE * 2] = 0;
    return id_str;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
    uint32_t i;
    VLA(uint8_t, buff, numbytes);

    for (i = 0; i < numbytes; ++i) {
        buff[i] = num[numbytes - i - 1];
    }

    memcpy(num, buff, numbytes);
#endif
}

void net_to_host(uint8_t *num, uint16_t numbytes)
{
    host_to_net(num, numbytes);
}

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items)
{
    if (ary == nullptr) {
        return;
    }

    size_t i;

    for (i = 0; i < n_items; ++i) {
        if (ary[i] != nullptr) {
            free(ary[i]);
        }
    }

    free(ary);
}

/* Converts 8 bytes to uint64_t */
void get_be64(uint64_t *dest, const uint8_t *bytes)
{
    *dest =
        ((uint64_t) bytes[0] << 56) |
        ((uint64_t) bytes[1] << 48) |
        ((uint64_t) bytes[2] << 40) |
        ((uint64_t) bytes[3] << 32) |
        ((uint64_t) bytes[4] << 24) |
        ((uint64_t) bytes[5] << 16) |
        ((uint64_t) bytes[6] <<  8) |
        ((uint64_t) bytes[7]) ;
}

/* Converts 4 bytes to uint32_t */
void get_be32(uint32_t *dest, const uint8_t *bytes)
{
    *dest =
        ((uint32_t) bytes[0] << 24) |
        ((uint32_t) bytes[1] << 16) |
        ((uint32_t) bytes[2] <<  8) |
        ((uint32_t) bytes[3]);
}

/* Converts 2 bytes to uint16_t */
void get_be16(uint16_t *dest, const uint8_t *bytes)
{
    *dest =
        ((uint16_t) bytes[0] <<  8) |
        ((uint16_t) bytes[1]);
}

/* Convert uint64_t to byte string of size 8 */
void put_be64(uint8_t *dest, uint64_t value)
{
    dest[0] = (value >> 56);
    dest[1] = (value >> 48);
    dest[2] = (value >> 40);
    dest[3] = (value >> 32);
    dest[4] = (value >> 24);
    dest[5] = (value >> 16);
    dest[6] = (value >>  8);
    dest[7] = (value);
}

/* Convert uint32_t to byte string of size 4 */
void put_be32(uint8_t *dest, uint32_t value)
{
    dest[0] = (value >> 24);
    dest[1] = (value >> 16);
    dest[2] = (value >>  8);
    dest[3] = (value);
}

/* Convert uint16_t to byte string of size 2 */
void put_be16(uint8_t *dest, uint16_t value)
{
    dest[0] = (value >> 8);
    dest[1] = (value);
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    /* Create queue mutex */
    if (pthread_mutex_init(mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    return 0;
}

int32_t max_s32(int32_t a, int32_t b)
{
    return a > b ? a : b;
}

int32_t min_s32(int32_t a, int32_t b)
{
    return a < b ? a : b;
}

uint16_t min_u16(uint16_t a, uint16_t b)
{
    return a < b ? a : b;
}

uint32_t min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}
