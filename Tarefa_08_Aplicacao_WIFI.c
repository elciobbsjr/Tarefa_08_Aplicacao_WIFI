#include <string.h>
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "dhcpserver.h"
#include "dnsserver.h"

#define TCP_PORT 80
#define HTTP_GET "GET"
#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"

// LED GPIOs
#define LED_R 13
#define LED_B 12

// Buzzer GPIOs
#define BUZZER_A 21
#define BUZZER_B 10

static int modo_alerta = 0;

static int generate_html_content(const char *params, char *result, size_t max_len) {
    if (params) {
        if (strcmp(params, "acao=ligar") == 0) {
            gpio_put(LED_R, 1); 
            gpio_put(LED_B, 0);
            gpio_put(BUZZER_A, 0); 
            gpio_put(BUZZER_B, 0);
            modo_alerta = 0;
            printf("[HTTP] LIGAR\n");
        } else if (strcmp(params, "acao=desligar") == 0) {
            gpio_put(LED_R, 0); 
            gpio_put(LED_B, 0);
            gpio_put(BUZZER_A, 0); 
            gpio_put(BUZZER_B, 0);
            modo_alerta = 0;
            printf("[HTTP] DESLIGAR\n");
        } else if (strcmp(params, "acao=alerta") == 0) {
            modo_alerta = 1;
            printf("[HTTP] ALERTA ATIVADO\n");
        }
    }

    return snprintf(result, max_len,
        "<html><head><title>Controle de LED</title></head><body>"
        "<h1>Controle de Alerta</h1>"
        "<p><a href=\"?acao=ligar\"><button>Ligar</button></a></p>"
        "<p><a href=\"?acao=desligar\"><button>Desligar</button></a></p>"
        "<p><a href=\"?acao=alerta\"><button>Alerta</button></a></p>"
        "</body></html>");
}

err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (!p) {
        printf("[HTTP] Conexão encerrada.\n");
        tcp_close(pcb);
        return ERR_OK;
    }

    char headers[512] = {0};
    char response[1024] = {0};

    pbuf_copy_partial(p, headers, p->tot_len < sizeof(headers) ? p->tot_len : sizeof(headers) - 1, 0);

    if (strncmp(headers, HTTP_GET, strlen(HTTP_GET)) == 0) {
        char *uri = strchr(headers, ' ');
        if (uri) uri++; else uri = "";
        char *params = strchr(uri, '?');
        if (params) {
            *params++ = 0;
            char *space = strchr(params, ' ');
            if (space) *space = 0;
        }

        int body_len = generate_html_content(params, response, sizeof(response));

        char header_response[256];
        snprintf(header_response, sizeof(header_response), HTTP_RESPONSE_HEADERS, 200, body_len);

        tcp_write(pcb, header_response, strlen(header_response), 0);
        tcp_write(pcb, response, body_len, 0);
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

err_t tcp_server_accept(void *arg, struct tcp_pcb *new_pcb, err_t err) {
    printf("[HTTP] Nova conexão aceita.\n");
    tcp_recv(new_pcb, tcp_server_recv);
    return ERR_OK;
}

int main() {
    stdio_init_all();

    gpio_init(LED_R); gpio_set_dir(LED_R, GPIO_OUT);
    gpio_init(LED_B); gpio_set_dir(LED_B, GPIO_OUT);
    gpio_init(BUZZER_A); gpio_set_dir(BUZZER_A, GPIO_OUT);
    gpio_init(BUZZER_B); gpio_set_dir(BUZZER_B, GPIO_OUT);

    if (cyw43_arch_init()) return 1;

    const char *ap_name = "Controle de Acesso - ALARME";
    const char *password = "1234567@";

    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_WPA2_AES_PSK);

    ip4_addr_t ip, mask;
    IP4_ADDR(&ip, 192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);

    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &ip, &mask);

    dns_server_t dns_server;
    dns_server_init(&dns_server, &ip);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb || tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT) != ERR_OK) {
        printf("[ERRO] Falha ao iniciar servidor.\n");
        return 1;
    }

    pcb = tcp_listen_with_backlog(pcb, 1);
    tcp_accept(pcb, tcp_server_accept);

    printf("[INFO] AP '%s' ativo. Acesse: http://192.168.4.1\n", ap_name);

    while (true) {
        static bool led_on = false;
        static bool buzzer_toggle = false;

        if (modo_alerta) {
            gpio_put(LED_R, led_on);
            gpio_put(BUZZER_A, buzzer_toggle);
            gpio_put(BUZZER_B, !buzzer_toggle);

            led_on = !led_on;
            buzzer_toggle = !buzzer_toggle;
        } else {
            gpio_put(BUZZER_A, 0);
            gpio_put(BUZZER_B, 0);
        }

        sleep_ms(500);
    }

    return 0;
}
