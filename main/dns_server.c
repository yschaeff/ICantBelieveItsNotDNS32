#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event_loop.h"

#include "nvs_flash.h"

#include "driver/gpio.h"
#include "sdkconfig.h"

#include "lwip/err.h"
#include "lwip/sockets.h"

#include "query.h"
#include "passwords.h"
#define EXAMPLE_WIFI_SSID "honeypot"
#define EXAMPLE_WIFI_PASS HONEYPOT_PASSWORD

#define BUF_SIZE 2048

const int DHCP_BIT = BIT0;

#define BLINK_GPIO CONFIG_BLINK_GPIO

#define MS(ms) ((ms) / portTICK_RATE_MS)

void blink_task(void *pvParameter)
{
    gpio_pad_select_gpio(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
    while(1) {
        gpio_set_level(BLINK_GPIO, 1);
        vTaskDelay(MS(100));
        gpio_set_level(BLINK_GPIO, 0);
        vTaskDelay(MS(100));
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    EventGroupHandle_t evg = (EventGroupHandle_t)ctx;
    printf("rcvd wifi event %d\n", event->event_id);
    switch(event->event_id) {
        case SYSTEM_EVENT_STA_START:
            printf("rcvd wifi event start\n");
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            printf("rcvd wifi event dhcp\n");
            xEventGroupSetBits(evg, DHCP_BIT);
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            printf("rcvd wifi event disconnect\n");
            esp_wifi_connect();
            xEventGroupClearBits(evg, DHCP_BIT);
            break;
        case SYSTEM_EVENT_STA_CONNECTED:
            printf("rcvd wifi event connected\n");
            break;
        default:
            printf("rcvd wifi event UNKNOWN\n");
            break;
    }
    return ESP_OK;
}

void wifiinit(EventGroupHandle_t evg)
{
    tcpip_adapter_init();

    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, evg) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI("XXX", "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
}


/*Context that passes client and client message to task*/
struct c_info {
    int sock;
    char *buf;
    size_t buflen;
    struct sockaddr_storage addr;
    socklen_t addr_size;
};

void process_msg(void *pvParameter)
{
    QueueHandle_t *peerqueue = (QueueHandle_t *)pvParameter;
    struct c_info peerinfo;
    ssize_t b_sent;
    char reply[BUF_SIZE];
    ssize_t reply_size;

    /*char *host = ipaddr_ntoa(((struct sockaddr_in6)peerinfo->addr).sin_addr);*/
    /*char *port = lwip_ntohs(peerinfo->addr.sin_port);*/
    /*printf("peer %s, port %s\n", host, port);*/

    while (1) {
        if (!xQueueReceive(*peerqueue, &peerinfo, MS(10000))) {
            continue;
        }
        reply_size = dns_reply(peerinfo.buf, peerinfo.buflen, reply, sizeof reply);
        if (reply_size) {
            b_sent = sendto(peerinfo.sock, reply, reply_size, 0,
                   (struct sockaddr *)&peerinfo.addr, peerinfo.addr_size);
            if (b_sent == -1) {
                perror("sendto");
            }
        }
        free(peerinfo.buf);
    }
}

void serve()
{
    int sock;
    size_t n;
    char buf[BUF_SIZE];
    struct sockaddr_in serverAddr;
    /*struct sockaddr_in6 serverAddr;*/
    struct sockaddr_storage peer_addr;
    socklen_t addr_size;
    struct c_info peerinfo;
    QueueHandle_t peerqueue;

    peerqueue =  xQueueCreate( 10, sizeof (peerinfo));
    xTaskCreate(process_msg, "msg1", 4096, &peerqueue, 5, NULL);
    // maybe also send socket here

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    /*sock = socket(PF_INET6, SOCK_DGRAM, 0);*/

    memset(&serverAddr, 0, sizeof serverAddr);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(53);
    /*serverAddr.sin_addr.s_addr = inet_addr("10.0.0.16");*/
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    /*serverAddr.sin6_family = AF_INET6;*/
    /*serverAddr.sin6_port = htons(53);*/
    /*serverAddr.sin6_addr= in6addr_any;*/

    bind(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    addr_size = sizeof peer_addr;

    while (1) {
        n = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&peer_addr,
             &addr_size);
        if (n == -1) {
            perror("recvfrom");
            continue;
        }
        /*printf("rcvd %d bytes\n", n);*/
        memset(&peerinfo, 0, sizeof (struct c_info));
        peerinfo.sock = sock;
        peerinfo.buf = malloc(n);
        memcpy(peerinfo.buf, buf, n);
        peerinfo.buflen = n;
        peerinfo.addr = peer_addr;
        peerinfo.addr_size = addr_size;
        if (!xQueueSend(peerqueue, &peerinfo, 100)) {
                puts("Queue full, dropping packet\n");
        }
    }
}

void app_main()
{
    EventGroupHandle_t *evg;
    nvs_flash_init();
    xTaskCreate(&blink_task, "blink_task", 512, NULL, 5, NULL);

    evg = xEventGroupCreate();
    wifiinit(evg);
    printf("Waiting for IP address...\n");
    while (!(xEventGroupWaitBits(evg, DHCP_BIT , pdFALSE, pdTRUE, MS(100)) & DHCP_BIT));
    serve();
}
