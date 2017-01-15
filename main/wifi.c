#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdio.h>
#include <stdlib.h>

#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event_loop.h"
#include "lwip/err.h"
#include "lwip/sockets.h"

#include "sdkconfig.h"
#include "wifi.h"

#define MS(ms) ((ms) / portTICK_RATE_MS)
const int SCAN_BIT = BIT0;
const int STRT_BIT = BIT1;
const int DISC_BIT = BIT2;
const int DHCP_BIT = BIT3;

struct known_ap {
    char *ssid;
    char *passwd;
};

#ifdef CONFIG_DNS_SERVER_AP5
#define KNOWN_AP_COUNT 5
#elif CONFIG_DNS_SERVER_AP4
#define KNOWN_AP_COUNT 4
#elif CONFIG_DNS_SERVER_AP3
#define KNOWN_AP_COUNT 3
#elif CONFIG_DNS_SERVER_AP2
#define KNOWN_AP_COUNT 2
#elif CONFIG_DNS_SERVER_AP1
#define KNOWN_AP_COUNT 1
#else
#define KNOWN_AP_COUNT 0
#endif

struct known_ap known_aps[KNOWN_AP_COUNT] = {
#ifdef CONFIG_DNS_SERVER_AP1 
      {.ssid = CONFIG_DNS_SERVER_AP1_SSID, .passwd = CONFIG_DNS_SERVER_AP1_PASSWORD}
#ifdef CONFIG_DNS_SERVER_AP2 
    , {.ssid = CONFIG_DNS_SERVER_AP2_SSID, .passwd = CONFIG_DNS_SERVER_AP2_PASSWORD}
#ifdef CONFIG_DNS_SERVER_AP3 
    , {.ssid = CONFIG_DNS_SERVER_AP3_SSID, .passwd = CONFIG_DNS_SERVER_AP3_PASSWORD}
#ifdef CONFIG_DNS_SERVER_AP4 
    , {.ssid = CONFIG_DNS_SERVER_AP4_SSID, .passwd = CONFIG_DNS_SERVER_AP4_PASSWORD}
#ifdef CONFIG_DNS_SERVER_AP5 
    , {.ssid = CONFIG_DNS_SERVER_AP5_SSID, .passwd = CONFIG_DNS_SERVER_AP5_PASSWORD}
#endif
#endif
#endif
#endif
#endif
};

static esp_err_t
event_handler(void *ctx, system_event_t *event)
{
    EventGroupHandle_t evg = (EventGroupHandle_t)ctx;

    switch(event->event_id) {
        case SYSTEM_EVENT_STA_START:
            ESP_LOGD(__func__, "started");
            xEventGroupSetBits(evg, STRT_BIT);
            break;
        case SYSTEM_EVENT_SCAN_DONE:
            ESP_LOGD(__func__, "Scan done");
            xEventGroupSetBits(evg, SCAN_BIT);
            break;
        case SYSTEM_EVENT_STA_CONNECTED:
            ESP_LOGD(__func__, "connected");
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGD(__func__, "dhcp");
            xEventGroupSetBits(evg, DHCP_BIT);
            break;
        case SYSTEM_EVENT_STA_STOP:
            ESP_LOGD(__func__, "stopped");
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGD(__func__, "disconnected");
            xEventGroupSetBits(evg, DISC_BIT);
            break;
        default:
            ESP_LOGW(__func__, "Unhandled event (%d)", event->event_id);
            break;
    }
    return ESP_OK;
}

esp_err_t
wifi_network_up()
{
    esp_err_t error;
    uint16_t apCount;
    wifi_ap_record_t *list = NULL;
    int i = 0, j, f, match;
    wifi_config_t wifi_config;

    EventGroupHandle_t evg = xEventGroupCreate();
    wifi_scan_config_t scanConf = { .ssid = NULL, .bssid = NULL, .channel = 0, .show_hidden = true };
    tcpip_adapter_init();
    error = esp_event_loop_init(event_handler, evg);
    if (error != ESP_OK) return error;
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    xEventGroupClearBits(evg, STRT_BIT);
    esp_wifi_start();

    int state = 0;
    int done = 0;
    while (!done) {
        switch (state) {
        case 0:
            while (!(xEventGroupWaitBits(evg, STRT_BIT , pdFALSE, pdFALSE, MS(5000)) & STRT_BIT));
            xEventGroupClearBits(evg, SCAN_BIT);
            ESP_ERROR_CHECK(esp_wifi_scan_start(&scanConf, 0));
            while (!(xEventGroupWaitBits(evg, SCAN_BIT , pdFALSE, pdFALSE, MS(5000)) & SCAN_BIT));
            apCount = 0;
            esp_wifi_scan_get_ap_num(&apCount);
            if (!apCount) break;
            free(list);
            list = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * apCount);
            ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&apCount, list));
            i = 0;
        case 1:
            state = 0;
            for (match = 0; i < apCount && !match; i++) {
                for (j = 0; j < KNOWN_AP_COUNT && !match; j++) {
                    match = !strcasecmp((char *)list[i].ssid, known_aps[j].ssid);
                }
            }
            if (!match) break;
            state = 1;
            strncpy((char *)wifi_config.sta.ssid, (char *)list[i-1].ssid, 32);
            strncpy((char *)wifi_config.sta.password, known_aps[j-1].passwd, 64);
            ESP_LOGI(__func__, "Setting WiFi configuration SSID %s...", (char *)wifi_config.sta.ssid);
            esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
            xEventGroupClearBits(evg, DISC_BIT | DHCP_BIT);
            esp_wifi_connect();
            ESP_LOGI(__func__, "Waiting for IP address...");
            state = 2;
        case 2:
            f = xEventGroupWaitBits(evg, DHCP_BIT|DISC_BIT , pdFALSE, pdFALSE, MS(100));
            if (f & DISC_BIT) state = 1;
            done = f & DHCP_BIT;
        }
    }
    free(list);
    return ESP_OK;
}

