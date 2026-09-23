#ifndef BULL_STATE_MACHINE_H
#define BULL_STATE_MACHINE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
enum bull_state { BULL_ERROR, BULL_IDLE, BULL_PENDING, BULL_DECIDED };
enum bull_decision { BULL_NONE, BULL_DENY, BULL_APPROVE };
typedef struct {
    enum bull_state state;
    uint8_t request[512];
    size_t request_len;
    uint64_t deadline, released_since, yes_since, no_since;
    bool armed, release_tracking, yes_tracking, no_tracking;
} bull_machine;
void bull_clear(bull_machine *m, bool healthy);
bool bull_request(bull_machine *m, const uint8_t *data, size_t len,
                  uint64_t now, uint32_t ttl_ms);
enum bull_decision bull_buttons(bull_machine *m, bool yes, bool no,
                               bool connected, uint64_t now);
#endif
