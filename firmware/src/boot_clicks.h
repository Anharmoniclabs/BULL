#ifndef BULL_BOOT_CLICKS_H
#define BULL_BOOT_CLICKS_H
#include <stdbool.h>
#include <stdint.h>
/* Diagnostic gesture result, never an approval proof. */
enum click_result { CLICK_WAIT, CLICK_NO, CLICK_YES, CLICK_CANCEL };
typedef struct {
    bool pending, armed, raw, stable, pressing;
    uint8_t clicks;
    uint64_t changed, pressed_at, deadline;
} boot_clicks;
void clicks_clear(boot_clicks *c);
bool clicks_begin(boot_clicks *c, bool pressed, uint64_t now);
enum click_result clicks_tick(boot_clicks *c, bool pressed, bool connected, uint64_t now);
#endif
