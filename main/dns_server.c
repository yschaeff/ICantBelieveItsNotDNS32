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

struct thread_context {
    int sock;
    struct namedb *namedb;
};

static int
process_msg(struct namedb *namedb, char *recvbuf, size_t recvlen,
    char *sendbuf, size_t sendlen)
{
    if (recvlen < sizeof(struct dns_header)) {
        ESP_LOGE(__func__, "packet doesn't fit header. Dropping.");
        return 0;
    }
    if (query_pkt_qr_count(recvbuf) < 1) {
        ESP_LOGE(__func__, "no question?");
        memcpy(sendbuf, recvbuf, recvlen);
        query_to_formerr(sendbuf);
        return recvlen;
    }
    char *owner = recvbuf + sizeof(struct dns_header);
    char *payload;
    if (query_find_owner_uncompressed(owner, &payload, recvbuf + recvlen)) {
        ESP_LOGE(__func__, "Could not parse owner name");
        memcpy(sendbuf, recvbuf, recvlen);
        query_to_formerr(sendbuf);
        return recvlen;
    }

    int owner_found = 0; /* if owner name is found but the RR can't be found
                            we shouldn't return NXDOMAIN */
    struct rrset *rrset = namedb_lookup(namedb, owner, payload, &owner_found);
    if (!rrset && !owner_found) {
        ESP_LOGE(__func__, "not is DB");
        memcpy(sendbuf, recvbuf, recvlen);
        query_to_nxdomain(sendbuf);
        return recvlen;
    }
    /*rrset contains: payload, rrsig*/
    if (rrset) {
        ESP_LOGD(__func__, "Yes! found in DB! rrsetsize: %d", rrset->num);
        sendlen = query_reply_from_rrset(recvbuf, recvlen,
            payload, sendbuf, sizeof sendbuf, rrset->payload, rrset->num,
            rrset->rrsig);
    } else { //NOERROR NODATA
        sendlen = query_reply_from_rrset(recvbuf, recvlen,
            payload, sendbuf, sizeof sendbuf, NULL, 0, NULL);
    }
    return sendlen;
}

static void
handle_udp(void *pvParameter)
{
    struct namedb *namedb = ((struct thread_context *)pvParameter)->namedb;
    int sock = ((struct thread_context *)pvParameter)->sock;
    ssize_t b_sent;
    char recvbuf[BUF_SIZE];
    char sendbuf[BUF_SIZE];
    ssize_t recvlen, sendlen;
    struct sockaddr_storage peer_addr;
    socklen_t addr_size = sizeof (struct sockaddr_storage);

    while (1) {
        recvlen = recvfrom(sock, recvbuf, BUF_SIZE, 0,
            (struct sockaddr *)&peer_addr, &addr_size);
        if (recvlen == -1) {
            perror("recvfrom");
            continue;
        }
        sendlen = process_msg(namedb, recvbuf, recvlen, sendbuf, BUF_SIZE);
        if (!sendlen) continue;
        while (sendlen > 0) {
            b_sent = sendto(sock, sendbuf, sendlen, 0,
               (struct sockaddr *)&peer_addr, addr_size);
            if (b_sent == -1) {
                perror("sendto");
                break;
            }
            sendlen -= b_sent;
        }
    }
}

static void
handle_tcp(void *pvParameter)
{
    struct namedb *namedb = ((struct thread_context *)pvParameter)->namedb;
    int sock = ((struct thread_context *)pvParameter)->sock;
    ssize_t b_sent;
    char recvbuf[BUF_SIZE];
    char sendbuf[BUF_SIZE];
    ssize_t recvlen, sendlen;
    struct sockaddr_storage peer_addr;
    socklen_t addr_size = sizeof (struct sockaddr_storage);

    while (1) {
        int fd = accept(sock, (struct sockaddr *)&peer_addr, &addr_size);
        ESP_LOGV(__func__, "accept");
        recvlen = recv(fd, recvbuf, BUF_SIZE, 0);
        if (recvlen == -1) {
            perror("recvfrom");
            continue;
        }
        sendlen = process_msg(namedb, recvbuf+2, recvlen-2, sendbuf+2, BUF_SIZE-2);
        if (!sendlen) continue;
        *(uint16_t *)sendbuf = htons((uint16_t)sendlen);
        while (sendlen > 0) {
            b_sent = send(fd, sendbuf, sendlen+2, 0);
            if (b_sent == -1) {
                perror("sendto");
                break;
            }
            sendlen -= b_sent;
        }
        close(fd);
    }
}

static void serve(struct namedb *namedb)
{
    int udpsock, tcpsock;
    struct sockaddr_in serverAddr;
    struct thread_context udp_ctx;
    struct thread_context tcp_ctx;

    memset(&serverAddr, 0, sizeof serverAddr);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DNS_SERVER_PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    udpsock = socket(PF_INET, SOCK_DGRAM, 0);
    tcpsock = socket(PF_INET, SOCK_STREAM, 0);
    bind(udpsock, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    bind(tcpsock, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    listen(tcpsock, 10);

    udp_ctx.namedb = namedb;
    udp_ctx.sock = udpsock;
    tcp_ctx.namedb = namedb;
    tcp_ctx.sock = tcpsock;

    ESP_LOGI(__func__, "start serving");
    xTaskCreate(handle_udp, "msg1", 8192, &udp_ctx, 5, NULL);
    xTaskCreate(handle_tcp, "msg2", 8192, &tcp_ctx, 5, NULL);
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
    xTaskCreate(&blink_task, "blink_task", 512, NULL, 0, NULL);
    serve(namedb);
}
