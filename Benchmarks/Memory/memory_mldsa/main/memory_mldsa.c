// mem_heap_peak_mldsa.c — Medição de pico de HEAP e STACK + CSV + Wi-Fi/HTTP
// Fluxo:
//   app_main -> init NVS + SPIFFS -> cria task_bench (CPU1)
//   task_bench:
//      • aquecimento 100 iterações
//      • benchmark 1000 iterações (keygen+sign+verify)
//      • mede pico de heap e stack
//      • escreve CSV com UMA linha de resultado
//      • liga Wi-Fi e expõe o CSV via HTTP

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_heap_caps.h"

#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "esp_vfs.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"

// ML-DSA
// Altere MLD_CONFIG_PARAMETER_SET para mudar o nível de segurança:
//   44 → ML-DSA-44 (128 bits)
//   65 → ML-DSA-65 (192 bits)
//   87 → ML-DSA-87 (256 bits)
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"

#include "coins.h"  // COINS_KEYPAIR[1000][64], COINS_ENC[1000][32]

// ===== Configurações gerais =====

static const char *TAG = "MEM_HEAP_PEAK";

#define WIFI_SSID  "WIFI"
#define WIFI_PASS  "PASS"

#define CSV_PATH   "/spiffs/mldsa87_memory.csv"

#define WARMUP_ITERS  0
#define BENCH_ITERS   30

// Tamanho de stack da task em BYTES
// ML-DSA-44/65: 96KB | ML-DSA-44: 128KB
#define TASK_STACK   (128 * 1024)

// ===== Wi-Fi (station) =====

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

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,
                                               ESP_EVENT_ANY_ID,
                                               &wifi_event_handler,
                                               NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,
                                               IP_EVENT_STA_GOT_IP,
                                               &wifi_event_handler,
                                               NULL));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid, WIFI_SSID,
            sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, WIFI_PASS,
            sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando ao Wi-Fi...");
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi conectado.");
}

// ===== HTTP server =====

static esp_err_t csv_get_handler(httpd_req_t *req)
{
    FILE *f = fopen(CSV_PATH, "r");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV (%s) para leitura", CSV_PATH);
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/csv");
    char buf[128];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) {
            fclose(f);
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "CSV enviado ao cliente.");
    return ESP_OK;
}

static httpd_handle_t start_file_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;
    esp_err_t ret = httpd_start(&server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao iniciar HTTP server (%s)", esp_err_to_name(ret));
        return NULL;
    }
    httpd_uri_t csv_uri = {
        .uri      = "/mldsa87_memory.csv",
        .method   = HTTP_GET,
        .handler  = csv_get_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &csv_uri);
    ESP_LOGI(TAG, "HTTP server iniciado. Acesse http://%s%s", s_ip_str, csv_uri.uri);
    return server;
}

// ===== SPIFFS =====

static void init_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = NULL,
        .max_files              = 4,
        .format_if_mount_failed = true
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao montar SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }
    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK)
        ESP_LOGI(TAG, "SPIFFS montado, total=%d, usado=%d", (int)total, (int)used);
}

// ===== Helpers de medição de memória =====

static inline size_t stack_used_peak_bytes(void)
{
    UBaseType_t words_min_free = uxTaskGetStackHighWaterMark(NULL);
    size_t bytes_min_free = (size_t)words_min_free * sizeof(StackType_t);
    return (TASK_STACK - bytes_min_free);
}

typedef struct {
    size_t free_start;
    size_t min_free_end;
} heap_scope_t;

static inline void heap_scope_begin(heap_scope_t *s)
{
    s->free_start = heap_caps_get_free_size(MALLOC_CAP_8BIT);
}

static inline void heap_scope_end(heap_scope_t *s)
{
    s->min_free_end = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
}

static inline size_t heap_peak_bytes(const heap_scope_t *s)
{
    if (s->free_start >= s->min_free_end)
        return s->free_start - s->min_free_end;
    return 0;
}

// ===== CSV =====

static esp_err_t write_csv_peaks(size_t heap_peak_B, size_t stack_peak_B)
{
    FILE *f = fopen(CSV_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Falha ao abrir CSV (%s) para escrita", CSV_PATH);
        return ESP_FAIL;
    }
    fprintf(f, "alg,heap_peak_B,stack_peak_B\n");
    fprintf(f, "ML-DSA-%d,%zu,%zu\n",
            MLD_CONFIG_PARAMETER_SET, heap_peak_B, stack_peak_B);
    fclose(f);
    ESP_LOGI(TAG, "CSV gravado em %s", CSV_PATH);
    return ESP_OK;
}

// ===== Task de benchmark (CPU1) =====

static void task_bench(void *arg)
{
    // Buffers alocados no heap — ML-DSA tem chaves grandes
    uint8_t *pk  = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk  = malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *sig = malloc(CRYPTO_BYTES);

    if (!pk || !sk || !sig) {
        ESP_LOGE(TAG, "Falha ao alocar buffers (pk=%u sk=%u sig=%u bytes)",
                 (unsigned)CRYPTO_PUBLICKEYBYTES,
                 (unsigned)CRYPTO_SECRETKEYBYTES,
                 (unsigned)CRYPTO_BYTES);
        goto end_task;
    }

    ESP_LOGI(TAG, "ML-DSA-%d | pk=%u sk=%u sig=%u bytes",
             MLD_CONFIG_PARAMETER_SET,
             (unsigned)CRYPTO_PUBLICKEYBYTES,
             (unsigned)CRYPTO_SECRETKEYBYTES,
             (unsigned)CRYPTO_BYTES);

    // Escopo de heap para medir pico
    heap_scope_t hs;
    heap_scope_begin(&hs);

    // Aquecimento
    ESP_LOGI(TAG, "Aquecimento de %d iteracoes...", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        const int idx = i % 1000;
        size_t siglen = 0;

        PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);
        PQCP_MLDSA_NATIVE_MLDSA87_signature_internal(sig, &siglen,
                                                     COINS_ENC[idx], 32,
                                                     NULL, 0,
                                                     COINS_ENC[idx],
                                                     sk, 0);
        PQCP_MLDSA_NATIVE_MLDSA87_verify_internal(sig, siglen,
                                                  COINS_ENC[idx], 32,
                                                  NULL, 0,
                                                  pk, 0);
        if ((i & 31) == 0) vTaskDelay(0);
    }

    // Benchmark principal
    ESP_LOGI(TAG, "Benchmark de %d iteracoes...", BENCH_ITERS);
    for (int i = 0; i < BENCH_ITERS; i++) {
        const int idx = i % 1000;
        size_t siglen = 0;

        PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(pk, sk, COINS_KEYPAIR[idx]);
        PQCP_MLDSA_NATIVE_MLDSA87_signature_internal(sig, &siglen,
                                                     COINS_ENC[idx], 32,
                                                     NULL, 0,
                                                     COINS_ENC[idx],
                                                     sk, 0);
        PQCP_MLDSA_NATIVE_MLDSA87_verify_internal(sig, siglen,
                                                  COINS_ENC[idx], 32,
                                                  NULL, 0,
                                                  pk, 0);
        if ((i & 31) == 0) vTaskDelay(0);
    }

    heap_scope_end(&hs);

    size_t heap_peak_B  = heap_peak_bytes(&hs);
    size_t stack_peak_B = stack_used_peak_bytes();

    ESP_LOGI(TAG, "Pico de uso de HEAP [B]  = %zu", heap_peak_B);
    ESP_LOGI(TAG, "Pico de uso de STACK [B] = %zu", stack_peak_B);

    printf("HEAP_RESULT,ALG=ML-DSA-%d,HEAP_PEAK_B=%zu,STACK_PEAK_B=%zu\n",
           MLD_CONFIG_PARAMETER_SET, heap_peak_B, stack_peak_B);

    ESP_ERROR_CHECK(write_csv_peaks(heap_peak_B, stack_peak_B));

    free(pk);
    free(sk);
    free(sig);

    wifi_init_sta();
    start_file_server();

    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
    return;

end_task:
    free(pk);
    free(sk);
    free(sig);
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ===== app_main =====

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    init_spiffs();

    xTaskCreatePinnedToCore(task_bench,
                            "task_bench",
                            TASK_STACK / sizeof(StackType_t),
                            NULL,
                            5,
                            NULL,
                            1);  // CPU1
}