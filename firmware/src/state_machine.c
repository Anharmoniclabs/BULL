#include "state_machine.h"
#include <string.h>

void bull_clear(bull_machine *m, bool healthy) {
    volatile uint8_t *p = (volatile uint8_t *)m;
    for (size_t i = 0; i < sizeof(*m); i++) p[i] = 0;
    m->state = healthy ? BULL_IDLE : BULL_ERROR;
}

bool bull_request(bull_machine *m, const uint8_t *data, size_t len,
                  uint64_t now, uint32_t ttl_ms) {
    if (m->state != BULL_IDLE || !data || !len || len > sizeof(m->request)
        || !ttl_ms || ttl_ms > 30000 || now > UINT64_MAX - ttl_ms) return false;
    memcpy(m->request, data, len);
    m->request_len = len;
    m->deadline = now + ttl_ms;
    m->state = BULL_PENDING;
    /* Every request requires a fresh stable release followed by a new press. */
    m->armed = m->release_tracking = m->yes_tracking = m->no_tracking = false;
    return true;
}

enum bull_decision bull_buttons(bull_machine *m, bool yes, bool no,
                               bool connected, uint64_t now) {
    if (!connected) {
        bool healthy = m->state != BULL_ERROR;
        bull_clear(m, healthy);
        return BULL_NONE;
    }
    if (m->state != BULL_PENDING) return BULL_NONE;
    if (now >= m->deadline || (yes && no)) {
        bull_clear(m, true);
        return BULL_DENY; /* Local rejection: cleared data must never be signed. */
    }
    if (no) {
        m->yes_tracking = false;
        if (!m->no_tracking) { m->no_tracking = true; m->no_since = now; }
        if (now - m->no_since >= 30) { m->state = BULL_DECIDED; return BULL_DENY; }
    } else m->no_tracking = false;
    if (!m->armed) {
        if (yes || no) m->release_tracking = false;
        else {
            if (!m->release_tracking) { m->release_tracking = true; m->released_since = now; }
            if (now - m->released_since >= 30) m->armed = true;
        }
        return BULL_NONE;
    }
    if (!yes || no) m->yes_tracking = false;
    else {
        if (!m->yes_tracking) { m->yes_tracking = true; m->yes_since = now; }
        /* 30 ms debounce followed by the full deliberate hold. */
        if (now - m->yes_since >= 780) { m->state = BULL_DECIDED; return BULL_APPROVE; }
    }
    return BULL_NONE;
}
