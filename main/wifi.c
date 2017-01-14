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

#include "wifi.h"

#define MS(ms) ((ms) / portTICK_RATE_MS)
const int DHCP_BIT = BIT0;
const int SCAN_BIT = BIT1;

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
#ifdef CONFIG_SERVER_AP1 
    {.ssid = CONFIG_SERVER_AP1_SSID,   .passwd = CONFIG_SERVER_AP1_PASSWORD  }
#ifdef CONFIG_SERVER_AP2 
    , {.ssid = CONFIG_SERVER_AP2_SSID,   .passwd = CONFIG_SERVER_AP2_PASSWORD  }
#ifdef CONFIG_SERVER_AP3 
    , {.ssid = CONFIG_SERVER_AP3_SSID,   .passwd = CONFIG_SERVER_AP3_PASSWORD  }
#ifdef CONFIG_SERVER_AP4 
    , {.ssid = CONFIG_SERVER_AP4_SSID,   .passwd = CONFIG_SERVER_AP4_PASSWORD  }
#ifdef CONFIG_SERVER_AP5 
    , {.ssid = CONFIG_SERVER_AP5_SSID,   .passwd = CONFIG_SERVER_AP5_PASSWORD  }
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
        case SYSTEM_EVENT_SCAN_DONE:
            ESP_LOGI("WIFI_EVENT", "Scan done");
            xEventGroupSetBits(evg, SCAN_BIT);
            break;
        case SYSTEM_EVENT_STA_START:
            ESP_LOGD("WIFI_EVENT", "started");
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_STOP:
            ESP_LOGD("WIFI_EVENT", "stopped");
            break;
        case SYSTEM_EVENT_STA_CONNECTED:
            ESP_LOGI("WIFI_EVENT", "connected");
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGW("WIFI_EVENT", "disconnected");
            esp_wifi_connect();
            xEventGroupClearBits(evg, DHCP_BIT);
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGI("WIFI_EVENT", "dhcp");
            xEventGroupSetBits(evg, DHCP_BIT);
            break;
        default:
            ESP_LOGW("WIFI_EVENT", "UNKNOWN (%d)", event->event_id);
            break;
    }
    return ESP_OK;
}

esp_err_t
wifi_network_up()
{
    esp_err_t error;
    EventGroupHandle_t *evg = xEventGroupCreate();

    tcpip_adapter_init();
    error = esp_event_loop_init(event_handler, evg);
    if (error != ESP_OK) return error;
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    int connected = 0;
    while (!connected) {
        uint16_t apCount = 0;
        wifi_scan_config_t scanConf = {
          .ssid = NULL,
          .bssid = NULL,
          .channel = 0,
          .show_hidden = true
        };
        ESP_LOGI(__func__, "Scanning for networks");
        ESP_ERROR_CHECK(esp_wifi_scan_start(&scanConf, 0));
        ESP_LOGD(__func__, "waiting for scan to complete.");
        xEventGroupClearBits(evg, SCAN_BIT);
        while (!(xEventGroupWaitBits(evg, SCAN_BIT , pdFALSE, pdTRUE, MS(100)) & SCAN_BIT));
        esp_wifi_scan_get_ap_num(&apCount);
        if (apCount == 0) continue;

        wifi_ap_record_t *list = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * apCount);
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&apCount, list));
        for (int i = 0; i < apCount; i++) {
            int j, match = 0;
            for (j = 0; j < KNOWN_AP_COUNT; j ++) {
                if (!strcasecmp((char *)list[i].ssid, known_aps[j].ssid)) {
                    match = 1;
                    break;
                }
            }
            if (!match) continue;

            wifi_config_t wifi_config;
            strncpy((char *)wifi_config.sta.ssid, (char *)list[i].ssid, 32);
            strncpy((char *)wifi_config.sta.password, known_aps[j].passwd, 64);
            ESP_LOGI(__func__, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
            esp_wifi_stop();
            esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
            esp_wifi_start();
            ESP_LOGI(__func__, "Waiting for IP address...");
            connected = xEventGroupWaitBits(evg, DHCP_BIT , pdFALSE, pdTRUE, MS(5000)) & DHCP_BIT;
            if (connected) break;
        }
    }
    return ESP_OK;
}

