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

#include "namedb.h"
#include "query.h"
#include "axfr.h"
#include "wifi.h"

#define BUF_SIZE 2048

#define BLINK_GPIO      CONFIG_BLINK_GPIO
#define DNS_SERVER_PORT CONFIG_DNS_SERVER_PORT
#define ZONE            CONFIG_DNS_SERVER_AXFR_ZONE
#define MASTER          CONFIG_DNS_SERVER_AXFR_MASTER

#define MS(ms) ((ms) / portTICK_RATE_MS)

static void
blink_task(void *pvParameter)
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

/*Context that passes client and client message to task*/
struct c_info {
    char *buf;
    size_t buflen;
    struct sockaddr_storage addr;
    socklen_t addr_size;
};

struct thread_context {
    int sock;
    QueueHandle_t *peerqueue;
    struct namedb *namedb;
};

static void
process_msg(void *pvParameter)
{

    QueueHandle_t *peerqueue = ((struct thread_context *)pvParameter)->peerqueue;
    struct namedb *namedb = ((struct thread_context *)pvParameter)->namedb;
    int sock = ((struct thread_context *)pvParameter)->sock;
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
        if (peerinfo.buflen < sizeof(struct dns_header)) {
            ESP_LOGE(__func__, "packet doesn't fit header. Dropping.");
            free(peerinfo.buf);
            continue;
        }
        if (query_pkt_qr_count(peerinfo.buf) < 1) {
            ESP_LOGE(__func__, "no question?");
            query_to_formerr(peerinfo.buf);
            (void) sendto(sock, peerinfo.buf, peerinfo.buflen, 0,
               (struct sockaddr *)&peerinfo.addr, peerinfo.addr_size);
            free(peerinfo.buf);
            continue;
        }
        char *owner = peerinfo.buf + sizeof(struct dns_header);
        char *payload;
        if (query_find_owner_uncompressed(owner, &payload, peerinfo.buf + peerinfo.buflen)) {
            ESP_LOGE(__func__, "Could not parse owner name");
            query_to_formerr(peerinfo.buf);
            (void) sendto(sock, peerinfo.buf, peerinfo.buflen, 0,
               (struct sockaddr *)&peerinfo.addr, peerinfo.addr_size);
            free(peerinfo.buf);
            continue;
        }

        struct rrset *rrset = namedb_lookup(namedb, owner, payload);
        if (!rrset) {
            ESP_LOGE(__func__, "not is DB");
            /*TODO: NOERROR no data*/
            query_to_nxdomain(peerinfo.buf);
            (void) sendto(sock, peerinfo.buf, peerinfo.buflen, 0,
               (struct sockaddr *)&peerinfo.addr, peerinfo.addr_size);
            free(peerinfo.buf);
            continue;
        }
        ESP_LOGI(__func__, "Yes! found in DB! rrsetsize: %d", rrset->num);
        /*rrset contains: payload, rrsig*/
        reply_size = query_reply_from_rrset(peerinfo.buf, peerinfo.buflen,
            payload, reply, sizeof reply, rrset->payload, rrset->num,
            rrset->rrsig);
        if (reply_size) {
            b_sent = sendto(sock, reply, reply_size, 0,
               (struct sockaddr *)&peerinfo.addr, peerinfo.addr_size);
            if (b_sent == -1) {
                perror("sendto");
            }
        }
        free(peerinfo.buf);
        vTaskDelay(0);//allow for GC TODO: is this needed?
    }
}

static void serve(struct namedb *namedb)
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
    struct thread_context thread_context;

    ESP_LOGE(__func__, "start serving");

    peerqueue = xQueueCreate( 10, sizeof (peerinfo));

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    /*sock = socket(PF_INET6, SOCK_DGRAM, 0);*/

    thread_context.peerqueue = &peerqueue;
    thread_context.namedb = namedb;
    thread_context.sock = sock;
    xTaskCreate(process_msg, "msg1", 8192, &thread_context, 5, NULL);
    xTaskCreate(process_msg, "msg2", 8192, &thread_context, 5, NULL);

    memset(&serverAddr, 0, sizeof serverAddr);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_SERVER_PORT);
    /*serverAddr.sin_addr.s_addr = inet_addr("10.0.0.16");*/
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    /*serverAddr.sin6_family = AF_INET6;*/
    /*serverAddr.sin6_port = htons(53);*/
    /*serverAddr.sin6_addr= in6addr_any;*/

    ESP_LOGE(__func__, "start serving");
    bind(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    addr_size = sizeof peer_addr;

    ESP_LOGE(__func__, "loop");
    while (1) {
        n = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&peer_addr,
             &addr_size);
        if (n == -1) {
            perror("recvfrom");
            continue;
        }
        /*printf("rcvd %d bytes\n", n);*/
        memset(&peerinfo, 0, sizeof (struct c_info));
        peerinfo.buf = malloc(n);
        memcpy(peerinfo.buf, buf, n);
        peerinfo.buflen = n;
        peerinfo.addr = peer_addr;
        peerinfo.addr_size = addr_size;
        if (!xQueueSend(peerqueue, &peerinfo, 100)) {
            ESP_LOGW(__func__, "Queue full, dropping packet");
        }
    }
}

void app_main()
{
    esp_err_t error;
    nvs_flash_init();

    error = wifi_network_up();
    if (error) {
        ESP_LOGE("MAIN", "Unable to bring up network");
        //Reboot
    }
    struct namedb *namedb = namedb_init();
    if (!namedb) {
        ESP_LOGE(__func__, "namedb init error");
        return; //TODO some soft of panic
    }
    axfr(MASTER, ZONE, namedb);
    xTaskCreate(&blink_task, "blink_task", 512, NULL, 5, NULL);
    serve(namedb);
}
