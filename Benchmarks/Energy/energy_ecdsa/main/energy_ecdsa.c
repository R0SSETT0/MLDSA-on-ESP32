// main/energy_ecdsa.c — ECDSA bench + energia média (sem Wi-Fi/HTTP, só impressão final)
// Coerente com o fluxograma:
//
// CPU 0 -> task_ina (Core 0)
//   - Fase idle: PHASE_IDLE      -> coleta P_idle e escreve no acumulador
//   - Fase bench: PHASE_BENCH    -> coleta P_bench e escreve no acumulador
//   - Fases neutras: PHASE_NEUTRAL -> não acumula nada
//
// CPU 1 -> bench_task (Core 1)
//   - Fase idle: delay para coleta do P_idle
//   - Fase neutra: aquecimento de WARMUP iterações
//   - Fase bench: benchmark de N_ITERS com marcação de tempo
//   - Fase neutra final: lê acumulador, calcula P_idle, P_bench, Δt, E_total_mJ,
//                        E_por_op_µJ e imprime CSV (linha única ENERGY,...)
//
// Alterações em relação à versão ECDH/INA226:
//   1. Algoritmo trocado de ECDH para ECDSA (sign + verify por iteração)
//   2. Módulo de corrente trocado de INA226 para INA219

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

// -----------------------------------------------------------------------
// Troca INA226 -> INA219
// Certifique-se de que o componente/driver INA219 está no seu CMakeLists.txt
// e que o header abaixo corresponde ao nome adotado pelo driver que você usa.
// -----------------------------------------------------------------------
#include "ina.h"   // <-- substituído de "ina.h" (INA226)

// mbedTLS (ECDSA)  <-- substituído de mbedtls/ecdh.h
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"       // ECDSA sign/verify
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/sha256.h"      // hash da mensagem antes de assinar

// ===== Parâmetros =====
#define N_ITERS              1000
#define WARMUP               100
#define BENCH_START_DELAY_MS 60000  // Fase idle: janela para medir P_idle

// -----------------------------------------------------------------------
// INA219: endereço I2C padrão (A0=GND, A1=GND) = 0x40
// -----------------------------------------------------------------------
#ifndef INA219_I2C_ADDR
#define INA219_I2C_ADDR 0x40      // <-- era INA226_I2C_ADDR
#endif

#define INA_TASK_STACK   (4096)
#define INA_TASK_PRIO    (4)
#define INA_TASK_CORE    (0)

#define BENCH_TASK_STACK (40960)
#define BENCH_TASK_PRIO  (5)
#define BENCH_TASK_CORE  (1)

// ===== Curva =====
// P-256 — mesma curva da versão ECDH; compatível com ECDSA
#define ECDSA_GID  MBEDTLS_ECP_DP_SECP256R1   // <-- era ECDH_GID

// Tamanho do hash SHA-256 usado como mensagem a assinar
#define HASH_LEN   32

// ===== Fases de energia (fluxograma) =====
typedef enum {
    PHASE_IDLE    = 0,
    PHASE_BENCH   = 1,
    PHASE_NEUTRAL = 2
} phase_t;

static volatile phase_t g_phase = PHASE_IDLE;

// ===== Acumulador de potência (mW) =====
typedef struct {
    uint64_t idle_sum_mw;
    uint32_t idle_n;
    uint64_t bench_sum_mw;
    uint32_t bench_n;
} energy_acc_t;

static volatile energy_acc_t g_acc = {0};

// Janela temporal do bench
static volatile uint64_t g_bench_t0_us = 0;
static volatile uint64_t g_bench_t1_us = 0;

// Flag: INA disponível?
static volatile bool g_ina_ok = false;

// ====== INA219 stream task (CPU0) ======
static void ina_task(void *arg)
{
    ina219_t dev;
    ina219_cfg_t cfg = {
        .port           = I2C_NUM_0,
        .sda_io         = GPIO_NUM_21,
        .scl_io         = GPIO_NUM_22,
        .clk_hz         = 100000,
        .i2c_addr       = 0x40,
        .shunt_ohms     = 0.1f,
        .max_current_A  = 0.4f,
        .install_driver = true
    };

    if (ina219_init(&dev, &cfg) != ESP_OK) {
        g_ina_ok = false;
        vTaskDelete(NULL);
        return;
    }
    g_ina_ok = true;

    const int INA_PERIOD_MS = 10;
    TickType_t period = pdMS_TO_TICKS(INA_PERIOD_MS);
    if (period == 0) period = 1;
    TickType_t last = xTaskGetTickCount();

    for (;;) {
        int32_t mv = 0, ma = 0, mw = 0;

        // INA219 possui registrador POWER com LSB calibrado (20 * current_LSB).
        // Lemos diretamente para consistência com a versão INA226.
        if (ina219_read_bus_voltage_mv(&dev, &mv) == ESP_OK &&
            ina219_read_current_ma(&dev, &ma)     == ESP_OK &&
            ina219_read_power_mw(&dev, &mw)       == ESP_OK)
        {
            phase_t ph = g_phase;
            if (ph == PHASE_IDLE) {
                g_acc.idle_sum_mw  += (uint64_t) mw;
                g_acc.idle_n       += 1;
            } else if (ph == PHASE_BENCH) {
                g_acc.bench_sum_mw += (uint64_t) mw;
                g_acc.bench_n      += 1;
            }
            // PHASE_NEUTRAL → não acumula
        }
        vTaskDelayUntil(&last, period);
    }
}

// ====== Guard RTC para evitar rerun acidental ======
typedef struct { uint32_t magic; bool done; } rtc_guard_t;
#define GUARD_MAGIC 0xECDA0001u   // <-- magic atualizado (era 0xEC0DEC01)
static RTC_NOINIT_ATTR rtc_guard_t g_guard;

static void guard_init_on_boot(void)
{
    esp_reset_reason_t rr = esp_reset_reason();
    if (rr == ESP_RST_POWERON || rr == ESP_RST_EXT ||
        rr == ESP_RST_BROWNOUT || g_guard.magic != GUARD_MAGIC) {
        g_guard.magic = GUARD_MAGIC;
        g_guard.done  = false;
    }
}

// ====== DRBG determinístico (reprodutível) ======
static void hmac_sha256_raw(const void *key, size_t klen,
                             const void *msg, size_t mlen,
                             unsigned char out[32])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md,
                    (const unsigned char *) key, klen,
                    (const unsigned char *) msg, mlen,
                    out);
}

static void make_seed(int iter, char side, unsigned char out[32])
{
    // Prefixo atualizado para refletir ECDSA
    static const char KEY[] = "TCC|ECDSA|SEED|energy";
    char msg[64];
    int n = snprintf(msg, sizeof(msg),
                     "gid=%d|side=%c|iter=%d",
                     (int) ECDSA_GID, side, iter);
    hmac_sha256_raw(KEY, sizeof(KEY) - 1, msg, (size_t) n, out);
}

// ====== Corpo de uma iteração ECDSA ======
// ------------------------------------------------------------------
// Cada iteração executa:
//   1. Geração de par de chaves (privada d + pública Q)
//   2. Hash SHA-256 de uma mensagem sintética
//   3. Assinatura ECDSA (sign)  →  (r, s)
//   4. Verificação ECDSA (verify) da assinatura produzida
//
// Isso modela um ciclo completo sign+verify, equivalente em esforço
// ao handshake ECDH da versão anterior.
// ------------------------------------------------------------------
static inline void ecdsa_iter(int iter)
{
    mbedtls_ecp_group       grp;
    mbedtls_mpi             d;          // chave privada
    mbedtls_ecp_point       Q;          // chave pública
    mbedtls_hmac_drbg_context drbg;
    mbedtls_mpi             r, s;       // componentes da assinatura

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_hmac_drbg_init(&drbg);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Seed determinístico por iteração
    unsigned char seed[32];
    make_seed(iter, 'S', seed);  // 'S' = signer
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hmac_drbg_seed_buf(&drbg, md, seed, sizeof(seed));
    mbedtls_hmac_drbg_set_reseed_interval(&drbg, 0x7fffffff);

    // Carrega a curva
    mbedtls_ecp_group_load(&grp, ECDSA_GID);

    // 1. Geração do par de chaves
    (void) mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                   mbedtls_hmac_drbg_random, &drbg);

    // 2. Mensagem sintética: hash SHA-256 de "iter || side"
    unsigned char hash[HASH_LEN];
    {
        char msg_buf[32];

        int msg_len =
            snprintf(
                msg_buf,
                sizeof(msg_buf),
                "msg|iter=%d",
                iter
            );

        mbedtls_sha256_context sha;

        mbedtls_sha256_init(&sha);

        mbedtls_sha256_starts(&sha, 0);

        mbedtls_sha256_update(
            &sha,
            (const unsigned char *)msg_buf,
            (size_t)msg_len
        );

        mbedtls_sha256_finish(&sha, hash);

        mbedtls_sha256_free(&sha);
    }

    // 3. Assinatura ECDSA
    //    Usamos a interface de baixo nível (sign_det_ext ou sign_restartable)
    //    para compatibilidade ampla com versões do mbedTLS no ESP-IDF.
    (void) mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                              hash, HASH_LEN,
                              mbedtls_hmac_drbg_random, &drbg);

    // 4. Verificação ECDSA
    (void) mbedtls_ecdsa_verify(&grp, hash, HASH_LEN, &Q, &r, &s);

    // Cleanup
    mbedtls_hmac_drbg_free(&drbg);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
}

// ====== Benchmark ECDSA (CPU1) ======
static void bench_task(void *arg)
{
    if (g_guard.done) {
        for (;;) vTaskDelay(portMAX_DELAY);
    }

#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "bench", &lock_cpu);
    esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "bench", &lock_ls);
    if (lock_cpu) esp_pm_lock_acquire(lock_cpu);
    if (lock_ls)  esp_pm_lock_acquire(lock_ls);
#endif

    // ---------- Fase idle ----------
    g_phase = PHASE_IDLE;
    vTaskDelay(pdMS_TO_TICKS(BENCH_START_DELAY_MS));

    // ---------- Fase neutra (warmup) ----------
    g_phase = PHASE_NEUTRAL;

    for (int i = 0; i < WARMUP; i++) {
        ecdsa_iter(i);          // <-- era ecdh_iter
        if ((i % 25) == 0) vTaskDelay(0);
    }

    // ---------- Fase bench ----------
    g_bench_t0_us = esp_timer_get_time();
    g_phase       = PHASE_BENCH;

    for (int i = 0; i < N_ITERS; i++) {
        ecdsa_iter(i);          // <-- era ecdh_iter
        if ((i % 25) == 0) vTaskDelay(0);
    }

    g_bench_t1_us = esp_timer_get_time();
    g_phase       = PHASE_NEUTRAL;

    // Dá tempo de a INA task registrar últimas amostras
    vTaskDelay(pdMS_TO_TICKS(20));

    // ---------- Fase neutra final: calcula e imprime ----------
    if (!g_ina_ok || (g_acc.idle_n == 0 && g_acc.bench_n == 0)) {
        printf("ENERGY,NaN,NaN,NaN,NaN,NaN,NaN\n");
        fflush(stdout);
    } else {
        uint64_t idle_sum_mw  = g_acc.idle_sum_mw;
        uint32_t idle_n       = g_acc.idle_n;
        uint64_t bench_sum_mw = g_acc.bench_sum_mw;
        uint32_t bench_n      = g_acc.bench_n;

        double P_idle_mW  = (idle_n  ? (double) idle_sum_mw  / (double) idle_n  : 0.0);
        double P_bench_mW = (bench_n ? (double) bench_sum_mw / (double) bench_n : 0.0);
        double dP_mW      = P_bench_mW - P_idle_mW;
        double dt_ms      = (double)(g_bench_t1_us - g_bench_t0_us) / 1000.0;

        double E_total_uJ = dP_mW * dt_ms;
        double E_total_mJ = E_total_uJ / 1000.0;
        double E_per_uJ   = (N_ITERS ? E_total_uJ / (double) N_ITERS : 0.0);

        // ENERGY,P_idle_mW,P_bench_mW,delta_mW,dt_ms,E_total_mJ,E_per_iter_uJ
        printf("ENERGY,%.3f,%.3f,%.3f,%.3f,%.6f,%.6f\n",
               P_idle_mW, P_bench_mW, dP_mW, dt_ms, E_total_mJ, E_per_uJ);
        fflush(stdout);
    }

#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls);  }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    g_guard.done = true;
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ====== app_main ======
void app_main(void)
{
    guard_init_on_boot();

    xTaskCreatePinnedToCore(ina_task,
                            "ina_stream",
                            INA_TASK_STACK,
                            NULL,
                            INA_TASK_PRIO,
                            NULL,
                            INA_TASK_CORE);

    xTaskCreatePinnedToCore(bench_task,
                            "ecdsa_bench",          // <-- era "ecdh_bench"
                            BENCH_TASK_STACK,
                            NULL,
                            BENCH_TASK_PRIO,
                            NULL,
                            BENCH_TASK_CORE);

    for (;;) vTaskDelay(portMAX_DELAY);
}