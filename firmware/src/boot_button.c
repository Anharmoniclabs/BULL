/* BOOTSEL sampling adapted from Raspberry Pi pico-examples/picoboard/button.
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd. SPDX-License-Identifier: BSD-3-Clause
 * Single-core only: no core 1 or DMA may access XIP during this function.
 */
#include "pico/stdlib.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
bool __no_inline_not_in_flash_func(bull_boot_pressed)(void) {
    uint32_t flags = save_and_disable_interrupts();
    uint32_t original = ioqspi_hw->io[1].ctrl;
    hw_write_masked(&ioqspi_hw->io[1].ctrl,
        GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
        IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    for (volatile int delay = 0; delay < 1000; ++delay) { }
    bool pressed = !(sio_hw->gpio_hi_in & (1u << 1));
    ioqspi_hw->io[1].ctrl = original;
    restore_interrupts(flags);
    return pressed;
}
