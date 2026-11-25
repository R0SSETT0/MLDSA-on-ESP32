// bench_mldsa.c — Benchmark ML-DSA (CPU1) -> grava CSV -> liga Wi-Fi -> serve HTTP
// Fluxo: app_main -> NVS + SPIFFS -> task_bench (CPU1)
// task_bench: warmup 100 -> benchmark 1000 (buffers) -> escreve CSV -> Wi-Fi + HTTP

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_cpu.h"
#include "esp_pm.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs_flash.h"

#include "esp_spiffs.h"
#include "esp_vfs.h"

// ML-DSA
// Altere MLD_CONFIG_PARAMETER_SET antes de incluir para mudar o nível de segurança:
//   44 → ML-DSA-44 (128 bits)
//   65 → ML-DSA-65 (192 bits)
//   87 → ML-DSA-87 (256 bits)
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"

#include "coins.h"  // COINS_KEYPAIR[1000][64], COINS_ENC[1000][32]

static const char *TAG = "MLDSA_BENCH";

#define WIFI_SSID   "WIFI"
#define WIFI_PASS   "PASS"

#define N_ITERS     30
#define WARMUP      0

#define CSV_PATH    "/spiffs/mldsa87_time.csv"

// ====== Wi-Fi (STA) ======
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;
static char s_ip_str[16] = "0.0.0.0";

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG, "Wi-Fi caiu, reconectando...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)event_data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Wi-Fi OK. IP: %s", s_ip_str);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(const char *ssid, const char *pass)
{
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t h1, h2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &h2));

    wifi_config_t c = {0};
    strlcpy((char *)c.sta.ssid, ssid, sizeof(c.sta.ssid));
    strlcpy((char *)c.sta.password, pass, sizeof(c.sta.password));
    c.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando no AP: %s ...", ssid);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
}

// ====== HTTP server ======
static esp_err_t csv_handler(httpd_req_t *req)
{
    FILE *f = fopen(CSV_PATH, "r");
    if (!f) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/csv");
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        httpd_resp_send_chunk(req, buf, n);
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static httpd_handle_t start_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri = {
            .uri      = "/mldsa87_time.csv",
            .method   = HTTP_GET,
            .handler  = csv_handler,
            .user_ctx = NULL,
        };
        httpd_register_uri_handler(server, &uri);
        return server;
    }
    return NULL;
}

// ====== SPIFFS ======
static void spiffs_init(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = "spiffs",
        .max_files              = 4,
        .format_if_mount_failed = true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
    size_t total = 0, used = 0;
    ESP_ERROR_CHECK(esp_spiffs_info(conf.partition_label, &total, &used));
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u",
             (unsigned)total, (unsigned)used);
}

// ====== task_bench (CPU1) ======
static void task_bench(void *arg)
{
#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu = NULL, lock_ls = NULL;
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "bench", &lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP, 0, "bench", &lock_ls));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_ls));
#endif

    // Buffers de chave e assinatura — alocados no heap por serem grandes
    // ML-DSA-44: sk=2560, pk=1312, sig=2420
    // ML-DSA-65: sk=4032, pk=1952, sig=3309
    // ML-DSA-87: sk=4896, pk=2592, sig=4627
    uint8_t *pk  = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk  = malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *sig = malloc(CRYPTO_BYTES);

    if (!pk || !sk || !sig) {
        ESP_LOGE(TAG, "Falha ao alocar buffers (pk=%u sk=%u sig=%u bytes)",
                 (unsigned)CRYPTO_PUBLICKEYBYTES,
                 (unsigned)CRYPTO_SECRETKEYBYTES,
                 (unsigned)CRYPTO_BYTES);
        goto after_bench;
    }

    // Buffers de tempo (us) e ciclos
    static uint32_t t_keypair_us[N_ITERS], t_sign_us[N_ITERS],
                    t_verify_us[N_ITERS],  t_total_us[N_ITERS];
    static uint32_t c_keypair[N_ITERS],    c_sign[N_ITERS],
                    c_verify[N_ITERS],     c_total[N_ITERS];
    static uint8_t  ok_verify[N_ITERS];

    ESP_LOGI(TAG, "ML-DSA-%d | pk=%u sk=%u sig=%u bytes",
             MLD_CONFIG_PARAMETER_SET,
             (unsigned)CRYPTO_PUBLICKEYBYTES,
             (unsigned)CRYPTO_SECRETKEYBYTES,
             (unsigned)CRYPTO_BYTES);
    ESP_LOGI(TAG, "Aquecimento de %d iteracoes (sem registro)", WARMUP);

    // 1) Aquecimento
    for (int i = 0; i < WARMUP; i++) {
        const int idx = i % 1000;
        size_t siglen = 0;

        // seed do keygen: primeiros 32 bytes de COINS_KEYPAIR[idx]
        PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);

        // mensagem = COINS_ENC[idx] (32 bytes)
        // rnd do sign = COINS_ENC[idx] (32 bytes, mesmo tamanho de MLDSA_RNDBYTES)
        PQCP_MLDSA_NATIVE_MLDSA87_signature_internal(sig, &siglen,
                                       COINS_ENC[idx], 32,
                                       NULL, 0,
                                       COINS_ENC[idx],
                                       sk, 0);

        PQCP_MLDSA_NATIVE_MLDSA87_verify_internal(sig, siglen,
                                    COINS_ENC[idx], 32,
                                    NULL, 0,
                                    pk, 0);

        if ((i % 25) == 0) vTaskDelay(0);
    }

    ESP_LOGI(TAG, "Iniciando benchmark de %d iteracoes", N_ITERS);

    // 2) Benchmark
    for (int i = 0; i < N_ITERS; i++) {
        const int idx = i % 1000;
        size_t siglen = 0;

        // --- KEYGEN ---
        uint64_t t0 = esp_timer_get_time();
        uint32_t c0 = esp_cpu_get_cycle_count();
        PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);
        uint64_t t1 = esp_timer_get_time();
        uint32_t c1 = esp_cpu_get_cycle_count();

        // --- SIGN ---
        // mensagem: COINS_ENC[idx] (32 bytes)
        // rnd:      COINS_ENC[idx] (32 bytes = MLDSA_RNDBYTES, determinístico)
        int ret = PQCP_MLDSA_NATIVE_MLDSA87_signature_internal(sig, &siglen,
                                                 COINS_ENC[idx], 32,
                                                 NULL, 0,
                                                 COINS_ENC[idx],
                                                 sk, 0);
        uint64_t t2 = esp_timer_get_time();
        uint32_t c2 = esp_cpu_get_cycle_count();

        if (ret != 0) {
            ESP_LOGE(TAG, "[%d] sign falhou: %d", i, ret);
            ok_verify[i] = 0;
            goto store_times;
        }

        // --- VERIFY ---
        ret = PQCP_MLDSA_NATIVE_MLDSA87_verify_internal(sig, siglen,
                                          COINS_ENC[idx], 32,
                                          NULL, 0,
                                          pk, 0);
        uint64_t t3 = esp_timer_get_time();
        uint32_t c3 = esp_cpu_get_cycle_count();

        ok_verify[i] = (ret == 0);
        if (ret != 0) ESP_LOGE(TAG, "[%d] verify falhou: %d", i, ret);

        t_verify_us[i] = (uint32_t)(t3 - t2);
        c_verify[i]    = (c3 - c2);
        t_total_us[i]  = (uint32_t)(t3 - t0);
        c_total[i]     = (c3 - c0);

store_times:
        t_keypair_us[i] = (uint32_t)(t1 - t0);
        t_sign_us[i]    = (uint32_t)(t2 - t1);
        c_keypair[i]    = (c1 - c0);
        c_sign[i]       = (c2 - c1);

        if ((i % 25) == 0) vTaskDelay(0);
    }

    // 3) Escreve CSV
    ESP_LOGI(TAG, "Gravando CSV em %s", CSV_PATH);
    {
        FILE *f = fopen(CSV_PATH, "w");
        if (!f) {
            ESP_LOGE(TAG, "Falha ao abrir CSV para escrita");
            goto after_bench;
        }

        fprintf(f, "iter,keypair_us,sign_us,verify_us,total_us,"
                   "keypair_cycles,sign_cycles,verify_cycles,total_cycles,ok\n");

        for (int i = 0; i < N_ITERS; i++) {
            fprintf(f, "%d,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ","
                       "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%u\n",
                    i,
                    t_keypair_us[i], t_sign_us[i], t_verify_us[i], t_total_us[i],
                    c_keypair[i],    c_sign[i],    c_verify[i],    c_total[i],
                    (unsigned)ok_verify[i]);
        }

        fclose(f);
        ESP_LOGI(TAG, "CSV gravado com sucesso.");
    }

after_bench:
    free(pk);
    free(sk);
    free(sig);

#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls); }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    // 4) Wi-Fi + HTTP
    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if (srv) {
        ESP_LOGI(TAG, "Servidor HTTP ativo");
        ESP_LOGI(TAG, "CSV disponivel em: http://%s/mldsa87_time.csv", s_ip_str);
    } else {
        ESP_LOGE(TAG, "Falha ao iniciar servidor HTTP");
    }

    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ====== app_main ======
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    spiffs_init();

    xTaskCreatePinnedToCore(
        task_bench,
        "task_bench",
        128 * 1024 / sizeof(StackType_t),
        NULL,
        5,
        NULL,
        1   // CPU1
    );
}