#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    uint32_t index;
    bool friend_in_group;

    bool joined;
    uint32_t conference;
    uint32_t received;
} State;

#include "run_auto_test.h"

#define NUM_MESSAGES 20000

static const uint8_t *ping = (const uint8_t *)"ping";
static const uint8_t *pong = (const uint8_t *)"pong";

static void handle_invite(
    Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type,
    const uint8_t *cookie, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->index, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->index);

    TOX_ERR_CONFERENCE_JOIN err;
    state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                  "attempting to join the conference returned with an error: %d", err);
    fprintf(stderr, "tox%u joined conference %u\n", state->index, state->conference);
    state->joined = true;
}

static void handle_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_peer_list_changed(#%u, %u, _)\n",
            state->index, conference_number);

    TOX_ERR_CONFERENCE_PEER_QUERY err;
    uint32_t const count = tox_conference_peer_count(tox, conference_number, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                  "failed to get conference peer count: err = %d", err);
    printf("tox%u has %u peers\n", state->index, count);
    state->friend_in_group = count == 2;
}

static void handle_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                           TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    if (tox_conference_peer_number_is_ours(tox, conference_number, peer_number, nullptr)) {
        return;
    }

    ++state->received;

    fprintf(stderr, "tox%u, message %6u: \"%s\")\n", state->index, state->received, message);

    const uint8_t *const response = memcmp(message, ping, 4) == 0 ? pong : ping;

    TOX_ERR_CONFERENCE_SEND_MESSAGE err;
    tox_conference_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, response, 5, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,
                  "failed to send response: err = %d", err);
}

static void conference_peer_nick_test(Tox **toxes, State *state)
{
    // Conference callbacks.
    tox_callback_conference_invite(toxes[0], handle_invite);
    tox_callback_conference_invite(toxes[1], handle_invite);
    tox_callback_conference_peer_list_changed(toxes[0], handle_peer_list_changed);
    tox_callback_conference_peer_list_changed(toxes[1], handle_peer_list_changed);
    tox_callback_conference_message(toxes[0], handle_message);
    tox_callback_conference_message(toxes[1], handle_message);

    // Set the names of the toxes.
    tox_self_set_name(toxes[0], (const uint8_t *)"test-tox-0", 10, nullptr);
    tox_self_set_name(toxes[1], (const uint8_t *)"test-tox-1", 10, nullptr);

    {
        // Create new conference, tox0 is the founder.
        TOX_ERR_CONFERENCE_NEW err;
        state[0].conference = tox_conference_new(toxes[0], &err);
        state[0].joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state[0].conference);
    }

    {
        // Invite friend.
        TOX_ERR_CONFERENCE_INVITE err;
        tox_conference_invite(toxes[0], 0, state[0].conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK,
                      "attempting to invite a friend returned with an error: %d", err);
        fprintf(stderr, "tox0 invited tox1\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive and peers to be in the group\n");

    while (!state[0].joined || !state[1].joined || !state[0].friend_in_group || !state[1].friend_in_group) {
        tox_iterate(toxes[0], &state[0]);
        tox_iterate(toxes[1], &state[1]);

        c_sleep(ITERATION_INTERVAL);
    }

    fprintf(stderr, "Bouncing messages\n");
    TOX_ERR_CONFERENCE_SEND_MESSAGE err;
    tox_conference_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, ping, 5, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,
                  "failed to send initial message: err = %d", err);

    while (state[0].received < NUM_MESSAGES && state[1].received < NUM_MESSAGES) {
        tox_iterate(toxes[0], &state[0]);
        tox_iterate(toxes[1], &state[1]);

        ck_assert_msg(state[0].friend_in_group, "tox0: friend has dropped out of the group");
        ck_assert_msg(state[1].friend_in_group, "tox1: friend has dropped out of the group");

        c_sleep(1);
    }

    fprintf(stderr, "Test complete\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, conference_peer_nick_test);
    return 0;
}
