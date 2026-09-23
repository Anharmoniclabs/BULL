#include "boot_clicks.h"
#include <assert.h>
static boot_clicks c;
static void start(void) {
    clicks_clear(&c); assert(clicks_begin(&c, false, 0));
    assert(!clicks_begin(&c, false, 1));
    assert(clicks_tick(&c, false, true, 30) == CLICK_WAIT);
}
static enum click_result click(uint64_t t) {
    assert(clicks_tick(&c, true, true, t) == CLICK_WAIT);
    assert(clicks_tick(&c, true, true, t+30) == CLICK_WAIT);
    assert(clicks_tick(&c, false, true, t+60) == CLICK_WAIT);
    return clicks_tick(&c, false, true, t+90);
}
int main(void) {
    start(); assert(click(100) == CLICK_WAIT); assert(click(300) == CLICK_WAIT);
    assert(clicks_tick(&c, false, true, 959) == CLICK_WAIT);
    assert(clicks_tick(&c, false, true, 960) == CLICK_YES);
    assert(clicks_tick(&c, false, true, 1000) == CLICK_WAIT);
    start(); click(100); click(300); assert(click(500) == CLICK_NO);
    assert(!c.pending && c.clicks == 0);
    /* Third click beginning exactly at the two-click deadline suppresses YES. */
    start(); click(100); click(300); assert(click(960) == CLICK_NO);
    start(); click(100);
    assert(clicks_tick(&c, false, true, 760) == CLICK_CANCEL);
    start(); click(100); click(300);
    assert(clicks_tick(&c, false, false, 900) == CLICK_CANCEL);
    assert(!c.pending);
    start(); assert(clicks_tick(&c, false, true, 30000) == CLICK_CANCEL);
    start(); clicks_tick(&c, true, true, 100); clicks_tick(&c, true, true, 130);
    assert(clicks_tick(&c, true, true, 1630) == CLICK_CANCEL);
    /* Contact bounce never becomes a click. */
    start();
    for (uint64_t t=100; t<200; t+=10) clicks_tick(&c, (t/10)%2, true, t);
    clicks_tick(&c, false, true, 200); clicks_tick(&c, false, true, 230);
    assert(c.clicks == 0);
    /* Held across request creation must first be released. */
    clicks_clear(&c); assert(clicks_begin(&c, true, 0));
    clicks_tick(&c, true, true, 1000); assert(!c.armed);
    clicks_tick(&c, false, true, 1010); clicks_tick(&c, false, true, 1040);
    assert(c.armed && c.clicks == 0);
    clicks_clear(&c); assert(!c.pending);
    assert(clicks_tick(&c, true, true, 0) == CLICK_WAIT);
    assert(!clicks_begin(&c, false, UINT64_MAX));
    return 0;
}
