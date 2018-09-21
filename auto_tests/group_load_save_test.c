/* Tests that we can make a friend connection.
 *
 * This is the simplest test that brings up two toxes that can talk to each
 * other. It's useful as a copy/pasteable starting point for testing other
 * features.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;
} State;

#include "run_auto_test.h"

static void friend_connection_test(Tox **toxes, State *state)
{
    TOX_ERR_GROUP_NEW err;
    tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"group", 5, &err);
    ck_assert_msg(err == TOX_ERR_GROUP_NEW_OK, "%d", err);

    toxes[0] = reload_tox(toxes[0], toxes[1], &state[0].index);
    ck_assert(toxes[0] != nullptr);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, friend_connection_test, false);
    return 0;
}
