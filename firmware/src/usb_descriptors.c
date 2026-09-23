#include "tusb.h"
#include "pico/unique_id.h"
#include <string.h>
/* Development VID/PID only. Obtain an assigned identity before distribution. */
static const tusb_desc_device_t device = {
    .bLength = sizeof(tusb_desc_device_t), .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200, .bMaxPacketSize0 = 64, .idVendor = 0xcafe,
    .idProduct = 0x4010, .bcdDevice = 0x0001, .iManufacturer = 1,
    .iProduct = 2, .iSerialNumber = 3, .bNumConfigurations = 1
};
static const uint8_t report[] = { TUD_HID_REPORT_DESC_GENERIC_INOUT(64) };
static const uint8_t configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN, 0, 100),
    TUD_HID_INOUT_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_NONE, sizeof(report), 0x01, 0x81, 64, 10)
};
const uint8_t *tud_descriptor_device_cb(void) { return (const uint8_t *)&device; }
const uint8_t *tud_descriptor_configuration_cb(uint8_t index) { (void)index; return configuration; }
const uint8_t *tud_hid_descriptor_report_cb(uint8_t instance) { (void)instance; return report; }
const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t out[64];
    char serial[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
    pico_get_unique_board_id_string(serial, sizeof(serial));
    const char *s = index == 1 ? "BULL" : "BULL Hardware Authority DIAGNOSTIC";
    if (index == 3) s = serial;
    if (index == 0) { out[0] = 0x0304; out[1] = 0x0409; return out; }
    if (index > 3) return NULL;
    size_t n = strlen(s);
    out[0] = (uint16_t)(0x0300 | (2*n + 2));
    for (size_t i = 0; i < n; i++) out[i+1] = s[i];
    return out;
}
