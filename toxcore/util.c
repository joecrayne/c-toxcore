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

char *id_toa(const uint8_t *id)
{
    char *str = (char *)malloc(CRYPTO_PUBLIC_KEY_SIZE * 2 + 1);

    for (int i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        sprintf(str + 2 * i, "%02x", id[i]);
    }

    return str;
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
void bytes_to_U64(uint64_t *dest, const uint8_t *bytes)
{
#ifdef WORDS_BIGENDIAN
    *dest =
        ((uint64_t) bytes[0])       |
        ((uint64_t) bytes[1] <<  8) |
        ((uint64_t) bytes[2] << 16) |
        ((uint64_t) bytes[3] << 24) |
        ((uint64_t) bytes[4] << 32) |
        ((uint64_t) bytes[5] << 40) |
        ((uint64_t) bytes[6] << 48) |
        ((uint64_t) bytes[7] << 56) ;
#else
    *dest =
        ((uint64_t) bytes[0] << 56) |
        ((uint64_t) bytes[1] << 48) |
        ((uint64_t) bytes[2] << 40) |
        ((uint64_t) bytes[3] << 32) |
        ((uint64_t) bytes[4] << 24) |
        ((uint64_t) bytes[5] << 16) |
        ((uint64_t) bytes[6] <<  8) |
        ((uint64_t) bytes[7]) ;
#endif
}

/* Converts 4 bytes to uint32_t */
void bytes_to_U32(uint32_t *dest, const uint8_t *bytes)
{
#ifdef WORDS_BIGENDIAN
    *dest =
        ((uint32_t) bytes[0])       |
        ((uint32_t) bytes[1] <<  8) |
        ((uint32_t) bytes[2] << 16) |
        ((uint32_t) bytes[3] << 24) ;
#else
    *dest =
        ((uint32_t) bytes[0] << 24) |
        ((uint32_t) bytes[1] << 16) |
        ((uint32_t) bytes[2] <<  8) |
        ((uint32_t) bytes[3]);
#endif
}

/* Converts 2 bytes to uint16_t */
void bytes_to_U16(uint16_t *dest, const uint8_t *bytes)
{
#ifdef WORDS_BIGENDIAN
    *dest =
        ((uint16_t) bytes[0])       |
        ((uint16_t) bytes[1] <<  8) ;
#else
    *dest =
        ((uint16_t) bytes[0] <<  8) |
        ((uint16_t) bytes[1]);
#endif
}

/* Convert uint64_t to byte string of size 8 */
void u64_to_bytes(uint8_t *dest, uint64_t value)
{
#ifdef WORDS_BIGENDIAN
    dest[0] = (value);
    dest[1] = (value >>  8);
    dest[2] = (value >> 16);
    dest[3] = (value >> 24);
    dest[4] = (value >> 32);
    dest[5] = (value >> 40);
    dest[6] = (value >> 48);
    dest[7] = (value >> 56);
#else
    dest[0] = (value >> 56);
    dest[1] = (value >> 48);
    dest[2] = (value >> 40);
    dest[3] = (value >> 32);
    dest[4] = (value >> 24);
    dest[5] = (value >> 16);
    dest[6] = (value >>  8);
    dest[7] = (value);
#endif
}

/* Convert uint32_t to byte string of size 4 */
void u32_to_bytes(uint8_t *dest, uint32_t value)
{
#ifdef WORDS_BIGENDIAN
    dest[0] = (value);
    dest[1] = (value >>  8);
    dest[2] = (value >> 16);
    dest[3] = (value >> 24);
#else
    dest[0] = (value >> 24);
    dest[1] = (value >> 16);
    dest[2] = (value >>  8);
    dest[3] = (value);
#endif
}

/* Convert uint16_t to byte string of size 2 */
void u16_to_bytes(uint8_t *dest, uint16_t value)
{
#ifdef WORDS_BIGENDIAN
    dest[0] = (value);
    dest[1] = (value >> 8);
#else
    dest[0] = (value >> 8);
    dest[1] = (value);
#endif
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

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len)
{
    uint32_t hash = 0;

    for (uint32_t i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}
