// energy_rsa7680_sign.c
// RSA-PSS 7680 bits + energia média (modelo do fluxograma)
//
//  - KEYGEN + SIGN + VERIFY em TODAS as iterações.
//  - Duas tasks: task_ina(Core 0) e bench_task(Core 1).
//  - Fases: PHASE_IDLE, PHASE_BENCH, PHASE_NEUTRAL.
//  - Saída única:
//    ENERGY,P_idle_mW,P_bench_mW,delta_mW,dt_ms,E_total_mJ,E_per_iter_uJ

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

// mbedTLS (RSA)
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"

#include "coins_rsa.h"

// =====================================================
// Parâmetros gerais
// =====================================================

#define N_ITERS              50
#define WARMUP               2
#define BENCH_START_DELAY_MS 60000

#ifndef INA219_I2C_ADDR
#define INA219_I2C_ADDR 0x40
#endif

#define INA_TASK_STACK   (4096)
#define INA_TASK_PRIO    (4)
#define INA_TASK_CORE    (0)

#define BENCH_TASK_STACK (65536)
#define BENCH_TASK_PRIO  (5)
#define BENCH_TASK_CORE  (1)

// =====================================================
// Parâmetros RSA
// =====================================================

#define RSA_KEY_SIZE   7680
#define RSA_EXPONENT   65537
#define SECRET_SIZE    32

#if defined(MBEDTLS_MPI_MAX_SIZE) && (MBEDTLS_MPI_MAX_SIZE < 960)
#error "MBEDTLS_MPI_MAX_SIZE muito pequeno p/ RSA-7680."
#endif

#if defined(MBEDTLS_MPI_MAX_BITS) && (MBEDTLS_MPI_MAX_BITS < 7680)
#error "MBEDTLS_MPI_MAX_BITS muito pequeno p/ RSA-7680."
#endif

#ifndef MBEDTLS_GENPRIME
#define MBEDTLS_GENPRIME
#endif

#ifndef RSA_SEED_BYTES
#define RSA_SEED_BYTES 32
#endif

#ifndef RSA_SEED_COUNT
#define RSA_SEED_COUNT 1000
#endif

#define RSA_MAX_LEN 1024

// =====================================================
// Fases de energia
// =====================================================

typedef enum {
    PHASE_IDLE    = 0,
    PHASE_BENCH   = 1,
    PHASE_NEUTRAL = 2
} phase_t;

static volatile phase_t g_phase = PHASE_IDLE;

// =====================================================
// Acumulador
// =====================================================

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

// =====================================================
// INA TASK
// =====================================================

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
        .max_current_A  = 0.5f,
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

    if (period == 0)
        period = 1;

    TickType_t last = xTaskGetTickCount();

    for (;;) {

        int32_t mv = 0;
        int32_t ma = 0;
        int32_t mw = 0;

        if (ina219_read_bus_voltage_mv(&dev, &mv) == ESP_OK &&
            ina219_read_current_ma(&dev, &ma) == ESP_OK &&
            ina219_read_power_mw(&dev, &mw) == ESP_OK)
        {
            phase_t ph = g_phase;

            if (ph == PHASE_IDLE) {

                g_acc.idle_sum_mw += (uint64_t) mw;
                g_acc.idle_n++;

            } else if (ph == PHASE_BENCH) {

                g_acc.bench_sum_mw += (uint64_t) mw;
                g_acc.bench_n++;
            }
        }

        vTaskDelayUntil(&last, period);
    }
}

// =====================================================
// Guard RTC
// =====================================================

typedef struct {
    uint32_t magic;
    bool done;
} rtc_guard_t;

#define GUARD_MAGIC 0xEC0DEC01u

static RTC_NOINIT_ATTR rtc_guard_t g_guard;

static void guard_init_on_boot(void)
{
    esp_reset_reason_t rr = esp_reset_reason();

    if (rr == ESP_RST_POWERON ||
        rr == ESP_RST_EXT ||
        rr == ESP_RST_BROWNOUT ||
        g_guard.magic != GUARD_MAGIC)
    {
        g_guard.magic = GUARD_MAGIC;
        g_guard.done = false;
    }
}

// =====================================================
// RNG FIXO
// =====================================================

static inline int rng_fixed(
    void *p_rng,
    unsigned char *buf,
    size_t len)
{
    return mbedtls_hmac_drbg_random(
        (mbedtls_hmac_drbg_context *) p_rng,
        buf,
        len
    );
}

// =====================================================
// RSA ITER
// =====================================================

static void rsa_iter(int iter)
{
    mbedtls_rsa_context ctx;
    mbedtls_hmac_drbg_context drbg;

    const mbedtls_md_info_t *md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    const unsigned char *seed =
        SEED[iter % RSA_SEED_COUNT];

    mbedtls_rsa_init(&ctx);

    // RSA-PSS + SHA256
    mbedtls_rsa_set_padding(
        &ctx,
        MBEDTLS_RSA_PKCS_V21,
        MBEDTLS_MD_SHA256
    );

    mbedtls_hmac_drbg_init(&drbg);

    mbedtls_hmac_drbg_seed_buf(
        &drbg,
        md,
        seed,
        RSA_SEED_BYTES
    );

    mbedtls_hmac_drbg_set_reseed_interval(
        &drbg,
        0x7fffffff
    );

    // =================================================
    // KEYGEN
    // =================================================

    int ret = mbedtls_rsa_gen_key(
        &ctx,
        rng_fixed,
        &drbg,
        RSA_KEY_SIZE,
        RSA_EXPONENT
    );

    if (ret != 0)
        goto cleanup;

    size_t klen = mbedtls_rsa_get_len(&ctx);

    if (klen > RSA_MAX_LEN)
        goto cleanup;

    // =================================================
    // HASH
    // =================================================

    unsigned char hash[32];

    int msg_idx = iter % RSA_SEED_COUNT;

    ret = mbedtls_md(
        md,
        input[msg_idx],
        SECRET_SIZE,
        hash
    );

    if (ret != 0)
        goto cleanup;

    // =================================================
    // SIGN
    // =================================================

    unsigned char sig[RSA_MAX_LEN];

    ret = mbedtls_rsa_rsassa_pss_sign(
        &ctx,
        rng_fixed,
        &drbg,
        MBEDTLS_MD_SHA256,
        32,
        hash,
        sig
    );

    if (ret != 0)
        goto cleanup;

    // =================================================
    // VERIFY
    // =================================================

    ret = mbedtls_rsa_rsassa_pss_verify(
        &ctx,
        MBEDTLS_MD_SHA256,
        32,
        hash,
        sig
    );

    if (ret != 0)
        goto cleanup;

cleanup:
    mbedtls_hmac_drbg_free(&drbg);
    mbedtls_rsa_free(&ctx);
}

// =====================================================
// BENCH TASK
// =====================================================

static void bench_task(void *arg)
{
    if (g_guard.done) {

        for (;;)
            vTaskDelay(portMAX_DELAY);
    }

#if CONFIG_PM_ENABLE

    esp_pm_lock_handle_t lock_cpu = NULL;
    esp_pm_lock_handle_t lock_ls  = NULL;

    esp_pm_lock_create(
        ESP_PM_CPU_FREQ_MAX,
        0,
        "bench",
        &lock_cpu
    );

    esp_pm_lock_create(
        ESP_PM_NO_LIGHT_SLEEP,
        0,
        "bench",
        &lock_ls
    );

    if (lock_cpu)
        esp_pm_lock_acquire(lock_cpu);

    if (lock_ls)
        esp_pm_lock_acquire(lock_ls);

#endif

    // =================================================
    // IDLE
    // =================================================

    g_phase = PHASE_IDLE;

    vTaskDelay(pdMS_TO_TICKS(BENCH_START_DELAY_MS));

    // =================================================
    // WARMUP
    // =================================================

    g_phase = PHASE_NEUTRAL;

    for (int i = 0; i < WARMUP; i++) {

        rsa_iter(i);

        vTaskDelay(0);
    }

    // =================================================
    // BENCH
    // =================================================

    g_bench_t0_us = esp_timer_get_time();

    g_phase = PHASE_BENCH;

    for (int i = 0; i < N_ITERS; i++) {

        rsa_iter(i);

        vTaskDelay(0);
    }

    g_bench_t1_us = esp_timer_get_time();

    g_phase = PHASE_NEUTRAL;

    vTaskDelay(pdMS_TO_TICKS(20));

    // =================================================
    // RESULTADOS
    // =================================================

    if (!g_ina_ok ||
        (g_acc.idle_n == 0 && g_acc.bench_n == 0))
    {
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");

        fflush(stdout);
    }
    else {

        uint64_t idle_sum_mw  = g_acc.idle_sum_mw;
        uint32_t idle_n       = g_acc.idle_n;

        uint64_t bench_sum_mw = g_acc.bench_sum_mw;
        uint32_t bench_n      = g_acc.bench_n;

        double P_idle_mW =
            (idle_n ?
             (double) idle_sum_mw / (double) idle_n :
             0.0);

        double P_bench_mW =
            (bench_n ?
             (double) bench_sum_mw / (double) bench_n :
             0.0);

        double dP_mW =
            P_bench_mW - P_idle_mW;

        double dt_ms =
            (double)(g_bench_t1_us - g_bench_t0_us)
            / 1000.0;

        double E_total_uJ =
            dP_mW * dt_ms;

        double E_total_mJ =
            E_total_uJ / 1000.0;

        double E_per_uJ =
            (N_ITERS ?
             E_total_uJ / (double) N_ITERS :
             0.0);

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

#if CONFIG_PM_ENABLE

    if (lock_ls) {

        esp_pm_lock_release(lock_ls);
        esp_pm_lock_delete(lock_ls);
    }

    if (lock_cpu) {

        esp_pm_lock_release(lock_cpu);
        esp_pm_lock_delete(lock_cpu);
    }

#endif

    g_guard.done = true;

    for (;;)
        vTaskDelay(pdMS_TO_TICKS(1000));
}

// =====================================================
// APP MAIN
// =====================================================

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
        "rsa7680_sign_bench",
        BENCH_TASK_STACK,
        NULL,
        BENCH_TASK_PRIO,
        NULL,
        BENCH_TASK_CORE
    );

    for (;;)
        vTaskDelay(portMAX_DELAY);
}