#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_timer.h"
#include "esp_cpu.h"
#include "esp_pm.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

#include "driver/i2c.h"
#include "driver/gpio.h"

#include "ina.h"

// ===== ML-DSA =====
// Altere MLD_CONFIG_PARAMETER_SET para mudar o nível de segurança:
//   44 → ML-DSA-44 (128 bits)
//   65 → ML-DSA-65 (192 bits)
//   87 → ML-DSA-87 (256 bits)
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"
#include "coins.h"  // COINS_KEYPAIR[1000][64], COINS_ENC[1000][32]

#define N_ITERS              1000
#define WARMUP               100
#define BENCH_START_DELAY_MS 60000

#ifndef INA219_I2C_ADDR
#define INA219_I2C_ADDR 0x40
#endif

#define INA_TASK_STACK   (4096)
#define INA_TASK_PRIO    (4)
#define INA_TASK_CORE    (0)

// Stack da bench task em BYTES — ML-DSA-87 exige ~128 KB
// (buffers pk/sk/sig são alocados no heap, mas a implementação
//  usa stack internamente durante keypair/sign/verify)
#define BENCH_TASK_STACK (128 * 1024)
#define BENCH_TASK_PRIO  (5)
#define BENCH_TASK_CORE  (1)

typedef enum {
    PHASE_IDLE = 0,
    PHASE_BENCH = 1,
    PHASE_NEUTRAL = 2
} phase_t;

static volatile phase_t g_phase = PHASE_IDLE;

typedef struct {
    uint64_t idle_sum_mw;
    uint32_t idle_n;
    uint64_t bench_sum_mw;
    uint32_t bench_n;
} energy_acc_t;

static volatile energy_acc_t g_acc = {0};

static volatile uint64_t g_bench_t0_us = 0;
static volatile uint64_t g_bench_t1_us = 0;

static volatile bool g_ina_ok = false;

// ===== Task INA219 (CPU0) =====

static void ina_task(void *arg)
{
    ina219_t dev;
    ina219_cfg_t cfg = {
        .port           = I2C_NUM_0,
        .sda_io         = GPIO_NUM_21,
        .scl_io         = GPIO_NUM_22,
        .clk_hz         = 100000,
        .i2c_addr       = INA219_I2C_ADDR,
        .shunt_ohms     = 0.100f,
        .max_current_A  = 0.2048f,
        .install_driver = true
    };

    if (ina219_init(&dev, &cfg) != ESP_OK) {
        g_ina_ok = false;
        vTaskDelete(NULL);
        return;
    }

    g_ina_ok = true;

    ina219_set_config(&dev);

    const int INA_PERIOD_MS = 10;
    TickType_t period = pdMS_TO_TICKS(INA_PERIOD_MS);

    if (period == 0) {
        period = 1;
    }

    TickType_t last = xTaskGetTickCount();

    for (;;) {
        int32_t mv = 0;
        int32_t ma = 0;
        int32_t mw = 0;

        if (ina219_read_bus_voltage_mv(&dev, &mv) == ESP_OK &&
            ina219_read_current_ma(&dev, &ma)     == ESP_OK &&
            ina219_read_power_mw(&dev, &mw)       == ESP_OK) {

            phase_t ph = g_phase;

            if (ph == PHASE_IDLE) {
                g_acc.idle_sum_mw += (uint64_t)mw;
                g_acc.idle_n      += 1;
            } else if (ph == PHASE_BENCH) {
                g_acc.bench_sum_mw += (uint64_t)mw;
                g_acc.bench_n      += 1;
            }
        }

        vTaskDelayUntil(&last, period);
    }
}

// ===== Guard RTC (evita re-execução após soft-reset) =====

typedef struct {
    uint32_t magic;
    bool     done;
} rtc_guard_t;

#define GUARD_MAGIC 0xB16B00B5

static RTC_NOINIT_ATTR rtc_guard_t g_guard;

static void guard_init_on_boot(void)
{
    esp_reset_reason_t rr = esp_reset_reason();

    if (rr == ESP_RST_POWERON  ||
        rr == ESP_RST_EXT      ||
        rr == ESP_RST_BROWNOUT ||
        g_guard.magic != GUARD_MAGIC) {

        g_guard.magic = GUARD_MAGIC;
        g_guard.done  = false;
    }
}

// ===== Task de benchmark (CPU1) =====

static void bench_task(void *arg)
{
    if (g_guard.done) {
        for (;;) vTaskDelay(portMAX_DELAY);
    }

#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL;
    esp_pm_lock_handle_t lock_ls  = NULL;

    esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX,    0, "bench", &lock_cpu);
    esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP,  0, "bench", &lock_ls);

    if (lock_cpu) esp_pm_lock_acquire(lock_cpu);
    if (lock_ls)  esp_pm_lock_acquire(lock_ls);
#endif

    // ===== Buffers ML-DSA alocados no heap (chaves são grandes) =====
    uint8_t *pk  = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk  = malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *sig = malloc(CRYPTO_BYTES);

    if (!pk || !sk || !sig) {
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");
        fflush(stdout);
        goto cleanup;
    }

    // ===== Fase de idle — mede consumo de base =====
    g_phase = PHASE_IDLE;
    vTaskDelay(pdMS_TO_TICKS(BENCH_START_DELAY_MS));
    g_phase = PHASE_NEUTRAL;

    // ===== Aquecimento (não contabilizado) =====
    for (int i = 0; i < WARMUP; i++) {
        const int idx  = i % 1000;
        size_t    siglen = 0;

        PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);

        PQCP_MLDSA_NATIVE_MLDSA44_signature_internal(
            sig, &siglen,
            COINS_ENC[idx], 32,
            NULL, 0,
            COINS_ENC[idx],
            sk, 0);

        PQCP_MLDSA_NATIVE_MLDSA44_verify_internal(
            sig, siglen,
            COINS_ENC[idx], 32,
            NULL, 0,
            pk, 0);

        if ((i % 25) == 0) vTaskDelay(0);
    }

    // ===== Benchmark medido =====
    g_bench_t0_us = esp_timer_get_time();
    g_phase       = PHASE_BENCH;

    for (int i = 0; i < N_ITERS; i++) {
        const int idx  = i % 1000;
        size_t    siglen = 0;

        PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);

        PQCP_MLDSA_NATIVE_MLDSA44_signature_internal(
            sig, &siglen,
            COINS_ENC[idx], 32,
            NULL, 0,
            COINS_ENC[idx],
            sk, 0);

        PQCP_MLDSA_NATIVE_MLDSA44_verify_internal(
            sig, siglen,
            COINS_ENC[idx], 32,
            NULL, 0,
            pk, 0);

        if ((i % 25) == 0) vTaskDelay(0);
    }

    g_bench_t1_us = esp_timer_get_time();
    g_phase       = PHASE_NEUTRAL;

    // Aguarda o INA219 processar as últimas amostras
    vTaskDelay(pdMS_TO_TICKS(20));

    // ===== Cálculo e saída de energia =====
    if (!g_ina_ok || (g_acc.idle_n == 0 && g_acc.bench_n == 0)) {
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");
        fflush(stdout);
    } else {
        double P_idle_mW  = g_acc.idle_n  ?
            (double)g_acc.idle_sum_mw  / (double)g_acc.idle_n  : 0.0;
        double P_bench_mW = g_acc.bench_n ?
            (double)g_acc.bench_sum_mw / (double)g_acc.bench_n : 0.0;

        double dP_mW     = P_bench_mW - P_idle_mW;
        double dt_ms     = (double)(g_bench_t1_us - g_bench_t0_us) / 1000.0;
        double E_total_uJ = dP_mW * dt_ms;
        double E_total_mJ = E_total_uJ / 1000.0;
        double E_per_uJ   = N_ITERS ? E_total_uJ / (double)N_ITERS : 0.0;

        printf(
            "ENERGY,%.3f,%.3f,%.3f,%.3f,%.6f,%.6f\n",
            P_idle_mW,
            P_bench_mW,
            dP_mW,
            dt_ms,
            E_total_mJ,
            E_per_uJ
        );
        fflush(stdout);
    }

cleanup:
    free(pk);
    free(sk);
    free(sig);

#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls);  }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    g_guard.done = true;

    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ===== app_main =====

void app_main(void)
{
    guard_init_on_boot();

    xTaskCreatePinnedToCore(
        ina_task,
        "ina_stream",
        INA_TASK_STACK,
        NULL,
        INA_TASK_PRIO,
        NULL,
        INA_TASK_CORE
    );

    xTaskCreatePinnedToCore(
        bench_task,
        "mldsa_bench",
        BENCH_TASK_STACK / sizeof(StackType_t),
        NULL,
        BENCH_TASK_PRIO,
        NULL,
        BENCH_TASK_CORE
    );

    for (;;) vTaskDelay(portMAX_DELAY);
}