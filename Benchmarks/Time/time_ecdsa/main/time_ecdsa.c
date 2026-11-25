// ecdh_time_bench.c — Benchmark ECDH (CPU1) -> grava CSV -> liga Wi-Fi -> serve HTTP

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
#include "esp_rom_uart.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs_flash.h"

#include "esp_spiffs.h"
#include "esp_vfs.h"

// mbedTLS
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/error.h"

#include "coins.h"

static const char *TAG = "ECDSA_BENCH";

#define WIFI_SSID  "WIFI"
#define WIFI_PASS  "PASS"

#define N_ITERS    30
#define WARMUP     0
#define COINS_COUNT 1000

// 256 bits (P-521)
#define ECDSA_GID  MBEDTLS_ECP_DP_SECP521R1
#define HASH_ALG   MBEDTLS_MD_SHA512
#define HASH_LEN   64
#define SIG_MAX    140

#define CSV_PATH   "/spiffs/ecdsa_p521_time.csv"

#define PROGRESS_LINE_BREAK 50
static inline void progress_tick(int i) {
    esp_rom_output_tx_one_char('.');
    if ((i % PROGRESS_LINE_BREAK) == PROGRESS_LINE_BREAK - 1)
        esp_rom_output_tx_one_char('\n');
}

// ---- util erro ----
static void log_mbedtls_err(const char *where, int ret){
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "%s: ret=%d (%s)", where, ret, buf);
}
#define OK_OR_GOTO(call, label) \
    do{int _r=(call); if(_r!=0){log_mbedtls_err(#call,_r); goto label;}}while(0)

// ---- Wi-Fi / HTTP / SPIFFS ----
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t s_wifi_event_group;
static char s_ip_str[16] = "0.0.0.0";

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data){
    if (base==WIFI_EVENT && id==WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base==WIFI_EVENT && id==WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG,"Wi-Fi caiu, reconectando...");
    } else if (base==IP_EVENT && id==IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *e = (const ip_event_got_ip_t *)data;
        snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&e->ip_info.ip));
        ESP_LOGI(TAG, "Wi-Fi OK. IP: %s", s_ip_str);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(const char *ssid, const char *pass){
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t h1,h2;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, &h1));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL, &h2));

    wifi_config_t c = {0};
    strlcpy((char*)c.sta.ssid, ssid, sizeof(c.sta.ssid));
    strlcpy((char*)c.sta.password, pass, sizeof(c.sta.password));
    c.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Conectando no AP: %s ...", ssid);
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
}

static esp_err_t csv_handler(httpd_req_t *req){
    FILE *f = fopen(CSV_PATH, "r");
    if(!f){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "CSV not found");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/csv");
    char buf[1024]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)
        httpd_resp_send_chunk(req, buf, n);
    fclose(f);
    httpd_resp_send_chunk(req,NULL,0);
    return ESP_OK;
}

static httpd_handle_t start_server(void){
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server=NULL;
    if(httpd_start(&server,&config)==ESP_OK){
        httpd_uri_t uri={
            .uri="/ecdsa_p521_time.csv",
            .method=HTTP_GET,
            .handler=csv_handler,
            .user_ctx=NULL
        };
        httpd_register_uri_handler(server,&uri);
        return server;
    }
    return NULL;
}

static void spiffs_init(void){
    esp_vfs_spiffs_conf_t conf = {
        .base_path="/spiffs",
        .partition_label="spiffs",
        .max_files=4,
        .format_if_mount_failed=true
    };
    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
    size_t total=0, used=0;
    ESP_ERROR_CHECK(esp_spiffs_info(conf.partition_label, &total, &used));
    ESP_LOGI(TAG, "SPIFFS montado. total=%u, used=%u",
             (unsigned)total, (unsigned)used);
}

// ===== Benchmark task =====
static void ecdh_bench_task(void *arg)
{
#if CONFIG_PM_ENABLE
    esp_pm_lock_handle_t lock_cpu=NULL, lock_ls=NULL;
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX,0,"ecdsa_bench",&lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_create(ESP_PM_NO_LIGHT_SLEEP,0,"ecdsa_bench",&lock_ls));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_cpu));
    ESP_ERROR_CHECK(esp_pm_lock_acquire(lock_ls));
#endif

    if(!mbedtls_ecdsa_can_do(ECDSA_GID)){
        ESP_LOGE(TAG,"Curva %d não suportada no build", (int)ECDSA_GID);
        goto after_bench;
    }

    // Buffers de medição (tempo em us e ciclos)
    static uint32_t t_keygen_us[N_ITERS];
    static uint32_t t_sign_us[N_ITERS];
    static uint32_t t_verify_us[N_ITERS];
    static uint32_t t_total_us[N_ITERS];
 
    static uint32_t c_keygen[N_ITERS];
    static uint32_t c_sign[N_ITERS];
    static uint32_t c_verify[N_ITERS];
    static uint32_t c_total[N_ITERS];

    static uint8_t  ok_verify[N_ITERS];

    const mbedtls_md_info_t *md_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const mbedtls_md_info_t *md_hash   = mbedtls_md_info_from_type(HASH_ALG);

    ESP_LOGI(TAG,"Warmup (%d) + benchmark (%d) ECDSA no CPU1 (sem Wi-Fi)",
             WARMUP, N_ITERS);

    // ---------- 1) Aquecimento ----------
    for(int i = 0; i < WARMUP; i++){
        const int idx = i % COINS_COUNT;

        mbedtls_ecdsa_context ctx;
        mbedtls_hmac_drbg_context drbg_key, drbg_sign;
        mbedtls_ecdsa_init(&ctx);
        mbedtls_hmac_drbg_init(&drbg_key);
        mbedtls_hmac_drbg_init(&drbg_sign);
 
        mbedtls_hmac_drbg_seed_buf(&drbg_key,  md_sha256, COINS_KEYPAIR[idx], 64);
        mbedtls_hmac_drbg_seed_buf(&drbg_sign, md_sha256, COINS_ENC[idx],     32);
 
        mbedtls_ecdsa_genkey(&ctx, ECDSA_GID, mbedtls_hmac_drbg_random, &drbg_key);
 
        unsigned char hash[HASH_LEN];
        mbedtls_md(md_hash, COINS_ENC[idx], 32, hash);
 
        unsigned char sig[SIG_MAX];
        size_t sig_len = 0;
        mbedtls_ecdsa_write_signature(&ctx, HASH_ALG,
                                      hash, HASH_LEN,
                                      sig, SIG_MAX, &sig_len,
                                      mbedtls_hmac_drbg_random, &drbg_sign);
 
        mbedtls_ecdsa_read_signature(&ctx, hash, HASH_LEN, sig, sig_len);
 
        mbedtls_hmac_drbg_free(&drbg_key);
        mbedtls_hmac_drbg_free(&drbg_sign);
        mbedtls_ecdsa_free(&ctx);
 
        if ((i % 25) == 0) vTaskDelay(0);
    }
    ESP_LOGI(TAG, "Warmup concluído.");

    // ---------- 2) Benchmark ----------
    for (int i = 0; i < N_ITERS; i++) {
        const int idx = i % COINS_COUNT;
 
        mbedtls_ecdsa_context ctx;
        mbedtls_hmac_drbg_context drbg_key, drbg_sign;
        mbedtls_ecdsa_init(&ctx);
        mbedtls_hmac_drbg_init(&drbg_key);
        mbedtls_hmac_drbg_init(&drbg_sign);
 
        if (mbedtls_hmac_drbg_seed_buf(&drbg_key,  md_sha256, COINS_KEYPAIR[idx], 64) != 0) goto iter_fail;
        if (mbedtls_hmac_drbg_seed_buf(&drbg_sign, md_sha256, COINS_ENC[idx],     32) != 0) goto iter_fail;
 
        // mensagem = hash de COINS_ENC[idx]
        unsigned char hash[HASH_LEN];
        mbedtls_md(md_hash, COINS_ENC[idx], 32, hash);
 
        // --- KEYGEN ---
        uint64_t t0 = esp_timer_get_time();
        uint32_t c0 = esp_cpu_get_cycle_count();
        OK_OR_GOTO(mbedtls_ecdsa_genkey(&ctx, ECDSA_GID,
                                        mbedtls_hmac_drbg_random, &drbg_key), iter_fail);
        uint64_t t1 = esp_timer_get_time();
        uint32_t c1 = esp_cpu_get_cycle_count();
 
        // --- SIGN ---
        unsigned char sig[SIG_MAX];
        size_t sig_len = 0;
        OK_OR_GOTO(mbedtls_ecdsa_write_signature(&ctx, HASH_ALG,
                                                 hash, HASH_LEN,
                                                 sig, SIG_MAX, &sig_len,
                                                 mbedtls_hmac_drbg_random, &drbg_sign), iter_fail);
        uint64_t t2 = esp_timer_get_time();
        uint32_t c2 = esp_cpu_get_cycle_count();
 
        // --- VERIFY ---
        int ret_verify = mbedtls_ecdsa_read_signature(&ctx, hash, HASH_LEN, sig, sig_len);
        uint64_t t3 = esp_timer_get_time();
        uint32_t c3 = esp_cpu_get_cycle_count();
 
        ok_verify[i] = (ret_verify == 0);
        if (ret_verify != 0) log_mbedtls_err("verify", ret_verify);
 
        t_keygen_us[i] = (uint32_t)(t1 - t0);
        t_sign_us[i]   = (uint32_t)(t2 - t1);
        t_verify_us[i] = (uint32_t)(t3 - t2);
        t_total_us[i]  = (uint32_t)(t3 - t0);
 
        c_keygen[i] = (c1 - c0);
        c_sign[i]   = (c2 - c1);
        c_verify[i] = (c3 - c2);
        c_total[i]  = (c3 - c0);
 
        mbedtls_hmac_drbg_free(&drbg_key);
        mbedtls_hmac_drbg_free(&drbg_sign);
        mbedtls_ecdsa_free(&ctx);
 
        progress_tick(i);
        if ((i % 25) == 0) vTaskDelay(0);
        continue;
 
iter_fail:
        ok_verify[i] = 0;
        t_keygen_us[i] = t_sign_us[i] = t_verify_us[i] = t_total_us[i] = 0;
        c_keygen[i]    = c_sign[i]    = c_verify[i]    = c_total[i]    = 0;
        mbedtls_hmac_drbg_free(&drbg_key);
        mbedtls_hmac_drbg_free(&drbg_sign);
        mbedtls_ecdsa_free(&ctx);
        if ((i % 25) == 0) vTaskDelay(0);
    }

    // ---------- 3) Escreve buffers no CSV ----------
    {
        FILE *f=fopen(CSV_PATH,"w");
        if(!f){
            ESP_LOGE(TAG,"Falha ao abrir CSV para escrita");
            goto after_bench;
        }
        fprintf(f, "iter,keygen_us,sign_us,verify_us,total_us,"
                   "keygen_cycles,sign_cycles,verify_cycles,total_cycles,ok\n");
        for(int i = 0; i < N_ITERS; i++){
            fprintf(f,
                "%d,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ","
                "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%u\n",
                i,
                t_keygen_us[i], t_sign_us[i], t_verify_us[i], t_total_us[i],
                c_keygen[i],    c_sign[i],    c_verify[i],    c_total[i],
                (unsigned)ok_verify[i]);
        }
        fclose(f);
        ESP_LOGI(TAG,"CSV gravado em %s", CSV_PATH);
    }

after_bench:
#if CONFIG_PM_ENABLE
    if (lock_ls)  { esp_pm_lock_release(lock_ls);  esp_pm_lock_delete(lock_ls); }
    if (lock_cpu) { esp_pm_lock_release(lock_cpu); esp_pm_lock_delete(lock_cpu); }
#endif

    // ---------- 4) Liga Wi-Fi e disponibiliza o CSV ----------
    wifi_init_sta(WIFI_SSID, WIFI_PASS);
    httpd_handle_t srv = start_server();
    if(srv){
        ESP_LOGI(TAG,"Servidor HTTP ativo");
        ESP_LOGI(TAG,"===> ARQUIVO: http://%s/ecdsa_p521_time.csv <===", s_ip_str);
    } else {
        ESP_LOGE(TAG,"Falha ao iniciar servidor HTTP");
    }
    for(;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

// ===== app_main =====
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    spiffs_init();

    // Cria task de benchmark no CPU1 (task_bench do fluxograma)
    xTaskCreatePinnedToCore(
        ecdh_bench_task,
        "ecdsa_bench",
        128 * 1024 / sizeof(StackType_t),
        NULL,
        5,
        NULL,
        1   // CPU1
    );
}

