#include "boot_clicks.h"
#include <string.h>
void clicks_clear(boot_clicks *c) { memset(c, 0, sizeof(*c)); }
bool clicks_begin(boot_clicks *c, bool pressed, uint64_t now) {
    if (c->pending || now > UINT64_MAX - 30000) return false;
    clicks_clear(c);
    c->pending = true;
    c->raw = c->stable = pressed;
    c->changed = now;
    c->deadline = now + 30000;
    return true;
}
static enum click_result finish(boot_clicks *c, enum click_result result) {
    clicks_clear(c);
    return result;
}
enum click_result clicks_tick(boot_clicks *c, bool pressed, bool connected, uint64_t now) {
    if (!connected) return finish(c, CLICK_CANCEL);
    if (!c->pending) return CLICK_WAIT;
    if (now >= c->deadline || now < c->changed) return finish(c, CLICK_CANCEL);
    if (pressed != c->raw) { c->raw = pressed; c->changed = now; }
    if (!c->armed) {
        /* A held button at request arrival cannot contribute a click. */
        if (!pressed && now - c->changed >= 30) {
            c->armed = true; c->stable = false;
        }
        return CLICK_WAIT;
    }
    if (c->stable != c->raw && now - c->changed >= 30) {
        c->stable = c->raw;
        if (c->stable) { c->pressing = true; c->pressed_at = now; }
        else if (c->pressing) {
            c->pressing = false;
            if (++c->clicks >= 3) return finish(c, CLICK_NO);
        }
    }
    if (c->pressing && now - c->pressed_at >= 1500) return finish(c, CLICK_CANCEL);
    /* Wait for 600 ms of quiet release: a third press or bounce postpones YES.
     * Never emit YES on the second press itself. */
    if (c->clicks && !c->raw && !c->stable && now - c->changed >= 600)
        return finish(c, c->clicks == 2 ? CLICK_YES : CLICK_CANCEL);
    return CLICK_WAIT;
}
