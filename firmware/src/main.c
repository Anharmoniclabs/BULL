/* Hardware discovery and button UX build. NEVER emits an approval or signature.
 * Replace with validated secure-element integration before authority use.
 */
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "status_pixel.pio.h"
#include "tusb.h"
#include "state_machine.h"
#include "boot_clicks.h"
extern bool bull_boot_pressed(void);
#include <string.h>
static bull_machine machine;
static uint8_t status[64];
static bool reply;
static boot_clicks gesture;
static bool arm_test;
static uint64_t indication_until;
static void cancel_test(void) {
    clicks_clear(&gesture); arm_test = false;
    memset(status + 23, 0, 41); indication_until = 0;
}

static void probe(void) {
    memset(status, 0, sizeof(status));
    memcpy(status, "BULL-DIAG-3", 11);
    status[11] = 0; /* Probe success never enables approval. */
    gpio_init(12); gpio_set_dir(12, GPIO_IN); gpio_pull_up(12);
    sleep_us(20);
    status[20] = gpio_get(12); status[21] = gpio_get(13);
    /* Probe documented default addresses, then the remaining non-reserved
     * addresses. Only reads and a GPIO wake pulse; no configuration writes. */
    const uint8_t defaults[] = {0x60, 0x35, 0x36, 0x10};
    for (unsigned index = 0; index < 116; index++) {
        uint8_t address = index < 4 ? defaults[index] : (uint8_t)(index - 4 + 8);
        gpio_set_function(12, GPIO_FUNC_SIO);
        gpio_put(12, 0); gpio_set_dir(12, GPIO_OUT);
        sleep_us(100);
        gpio_set_dir(12, GPIO_IN); gpio_pull_up(12);
        sleep_ms(3);
        gpio_set_function(12, GPIO_FUNC_I2C);
        uint8_t wake[4] = {0};
        int n = i2c_read_timeout_us(i2c0, address, wake, 4, false, 2000);
        if (n == 4) {
            status[22]++; /* ACK/read count is not a device identity. */
            if (address == 0x60) status[12] = 1;
            if (!memcmp(wake, (uint8_t[]){4, 0x11, 0x33, 0x43}, 4)) {
                memcpy(status + 13, wake, 4); status[19] = address;
                uint8_t sleep_command = 1;
                i2c_write_timeout_us(i2c0, address, &sleep_command, 1, false, 2000);
                break;
            }
        }
    }
}
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t id,
        hid_report_type_t type, uint8_t *buffer, uint16_t length) {
    (void)instance; (void)id;
    if (type != HID_REPORT_TYPE_INPUT) return 0;
    if (length > sizeof(status)) length = sizeof(status);
    memcpy(buffer, status, length); return length;
}
void tud_hid_set_report_cb(uint8_t instance, uint8_t id,
        hid_report_type_t type, const uint8_t *buffer, uint16_t length) {
    (void)instance; (void)id;
    /* Only STATUS (1), ARM_DIAGNOSTIC (2 + 32-byte challenge), CANCEL (3).
     * No command can synthesize a physical click or issue production authority. */
    if (type != HID_REPORT_TYPE_OUTPUT || length != 64 || id != 0 || instance != 0) {
        cancel_test(); return;
    }
    unsigned pad = buffer[0] == 2 ? 33 : 1;
    for (size_t i = pad; i < length; i++) if (buffer[i]) { cancel_test(); return; }
    switch (buffer[0]) {
    case 1: reply = true; break;
    case 2:
        if (!gesture.pending && !arm_test) {
            cancel_test();
            memcpy(status + 32, buffer + 1, 32);
            arm_test = true;
        }
        break;
    case 3: cancel_test(); reply = true; break;
    default: cancel_test(); break;
    }
}
void tud_umount_cb(void) { bull_clear(&machine, false); cancel_test(); reply = false; }
void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en; bull_clear(&machine, false); cancel_test(); reply = false;
}
int main(void) {
    bull_clear(&machine, false);
    uint offset = pio_add_program(pio0, &status_pixel_program);
    pio_gpio_init(pio0, 17);
    pio_sm_set_consecutive_pindirs(pio0, 0, 17, 1, true);
    pio_sm_config pixel = status_pixel_program_get_default_config(offset);
    sm_config_set_sideset_pins(&pixel, 17);
    sm_config_set_out_shift(&pixel, false, true, 24);
    sm_config_set_fifo_join(&pixel, PIO_FIFO_JOIN_TX);
    sm_config_set_clkdiv(&pixel, (float)clock_get_hz(clk_sys) / 8000000.0f);
    pio_sm_init(pio0, 0, offset, &pixel);
    pio_sm_set_enabled(pio0, 0, true);
    gpio_init(4); gpio_set_dir(4, GPIO_IN); gpio_pull_up(4);
    gpio_init(5); gpio_set_dir(5, GPIO_IN); gpio_pull_up(5);
    i2c_init(i2c0, 100000);
    gpio_set_function(13, GPIO_FUNC_I2C);
    gpio_pull_up(12); gpio_pull_up(13);
    sleep_ms(100); /* Allow external device power-on self-test to settle. */
    probe();
    tusb_init();
    uint64_t next_pixel = 0, next_sample = 0;
    uint32_t last_color = UINT32_MAX;
    bool lit = false;
    while (true) {
        tud_task();
        uint64_t now = to_ms_since_boot(get_absolute_time());
        bool connected = tud_mounted() && !tud_suspended();
        if (!connected) cancel_test();
        if (now >= next_sample) {
            bool pressed = bull_boot_pressed();
            status[26] = pressed;
            if (arm_test && connected) {
                clicks_begin(&gesture, pressed, now); arm_test = false;
            }
            enum click_result event = clicks_tick(&gesture, pressed, connected, now);
            if (event != CLICK_WAIT && connected) {
                status[24] = event; indication_until = now + 1500;
            }
            status[23] = gesture.pending;
            status[25] = gesture.clicks;
            next_sample = now + 5;
        }
        if (now >= next_pixel) { lit = !lit; next_pixel = now + 400; }
        uint32_t color = lit ? 0x001000u : 0; /* Unvalidated hardware: red. */
        if (gesture.pending) color = 0x101000u; /* Yellow: diagnostic pending. */
        else if (now < indication_until)
            color = status[24] == CLICK_YES ? 0x100000u : 0x001000u;
        if (color != last_color) {
            pio_sm_put_blocking(pio0, 0, color << 8); last_color = color;
        }
        status[17] = !gpio_get(4); status[18] = !gpio_get(5);
        if (reply && tud_hid_ready()) {
            tud_hid_report(0, status, sizeof(status)); reply = false;
        }
    }
}
