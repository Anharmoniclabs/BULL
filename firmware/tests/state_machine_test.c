#include "state_machine.h"
#include <assert.h>
static void pending(bull_machine *m) {
    const uint8_t packet[] = {1, 2, 3};
    bull_clear(m, true);
    assert(bull_request(m, packet, sizeof(packet), 0, 30000));
    assert(!bull_request(m, packet, sizeof(packet), 1, 30000));
}
int main(void) {
    bull_machine m;
    bull_clear(&m, false);
    assert(!bull_request(&m, (uint8_t[]){1}, 1, 0, 30000));
    pending(&m);
    assert(bull_buttons(&m, true, false, true, 0) == BULL_NONE);
    assert(bull_buttons(&m, true, false, true, 1000) == BULL_NONE);
    bull_buttons(&m, false, false, true, 1001);
    bull_buttons(&m, false, false, true, 1031);
    bull_buttons(&m, true, false, true, 1100);
    assert(bull_buttons(&m, true, false, true, 1879) == BULL_NONE);
    assert(bull_buttons(&m, true, false, true, 1880) == BULL_APPROVE);
    assert(bull_buttons(&m, true, false, true, 2000) == BULL_NONE);
    pending(&m);
    bull_buttons(&m, false, false, true, 0);
    bull_buttons(&m, false, false, true, 30);
    bull_buttons(&m, true, false, true, 100);
    bull_buttons(&m, false, false, true, 200);
    assert(bull_buttons(&m, true, false, true, 1000) == BULL_NONE);
    assert(bull_buttons(&m, true, true, true, 1800) == BULL_DENY);
    assert(m.request_len == 0);
    pending(&m);
    bull_buttons(&m, false, true, true, 0);
    assert(bull_buttons(&m, false, true, true, 29) == BULL_NONE);
    assert(bull_buttons(&m, false, true, true, 30) == BULL_DENY);
    pending(&m);
    assert(bull_buttons(&m, false, false, true, 30000) == BULL_DENY);
    assert(m.request_len == 0);
    pending(&m);
    bull_buttons(&m, true, false, false, 1000);
    assert(m.state == BULL_IDLE && !m.request_len);
    pending(&m);
    bull_clear(&m, false);
    assert(!m.request_len && m.state == BULL_ERROR);
    bull_clear(&m, true);
    uint8_t oversized[513] = {0};
    assert(!bull_request(&m, oversized, sizeof(oversized), 0, 30000));
    assert(!bull_request(&m, oversized, 1, 0, 30001));
    assert(!bull_request(&m, oversized, 1, 0, 0));
    assert(!bull_request(&m, oversized, 1, UINT64_MAX, 1));
    assert(!bull_request(&m, NULL, 1, 0, 30000));
    assert(bull_buttons(&m, true, false, true, 1000) == BULL_NONE);
    return 0;
}
