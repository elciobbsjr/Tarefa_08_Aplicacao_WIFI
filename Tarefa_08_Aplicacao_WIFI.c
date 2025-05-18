/*
 * ============================================================================
 * ATIVIDADE CAP 08 - APLICAÇÃO WIFI
 * 
 * ALUNO: ÉLCIO BERILO BARBOSA DOS SANTOS JÚNIOR
 * MATRÍCULA: 20251RSE.MTC0024
 * 
 * DESCRIÇÃO:
 * Este projeto implementa um sistema de controle de alarme via Wi-Fi 
 * utilizando o Raspberry Pi Pico W. A aplicação cria um ponto de acesso (AP), 
 * um servidor HTTP para controle remoto de LEDs, buzzers e exibição de mensagens 
 * em um display OLED via interface web.
 * 
 * FUNCIONALIDADES:
 * - Criação de Access Point Wi-Fi com autenticação WPA2
 * - Servidor Web HTTP para controle remoto
 * - Controle de LEDs e Buzzers via interface Web
 * - Exibição de mensagens no display OLED (I2C)
 * - Modo Alerta com sinais sonoros e visuais
 * 
 * INSTRUÇÕES DE USO:
 * 1. Ligue o dispositivo Raspberry Pi Pico W com o firmware carregado.
 * 2. No seu dispositivo (celular, tablet ou computador), conecte-se à rede Wi-Fi:
 *      - Nome da Rede (SSID): Controle de Acesso - ALARME
 *      - Senha: 1234567@
 * 3. Após conectar-se à rede, abra o navegador de internet e acesse o seguinte endereço IP:
 *      → http://192.168.4.1
 * 4. Utilize a interface web para:
 *      - Ligar o sistema (LED Vermelho aceso)
 *      - Desligar o sistema (modo repouso)
 *      - Ativar o modo Alerta (LEDs piscando e buzzers alternando sons)
 * 
 * OBSERVAÇÃO:
 * - O display OLED exibe o estado atual do sistema.
 * - Em Modo Alerta, o sistema sinaliza visual e sonoramente.
 * 
 * ============================================================================
 */

#include <string.h>
#include "pico/cyw43_arch.h"      // Biblioteca para controle da interface Wi-Fi do Raspberry Pi Pico W
#include "pico/stdlib.h"          // Funções básicas de I/O, delays, etc.
#include "hardware/i2c.h"         // Biblioteca para comunicação I2C (usada no display OLED)
#include "inc/ssd1306.h"          // Biblioteca para controle do display OLED SSD1306
#include "lwip/pbuf.h"            // Manipulação de buffers de pacotes TCP/IP
#include "lwip/tcp.h"             // Biblioteca para criar servidor TCP
#include "dhcpserver.h"           // Servidor DHCP para atribuir IPs aos clientes Wi-Fi
#include "dnsserver.h"            // Servidor DNS para redirecionamento

// Definições de I2C e Display OLED
#define I2C_PORT i2c1
#define SDA_PIN 14
#define SCL_PIN 15
#define OLED_WIDTH 128
#define OLED_HEIGHT 64

// Configurações da Porta do Servidor TCP e cabeçalhos HTTP
#define TCP_PORT 80
#define HTTP_GET "GET"
#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"

// GPIOs dos LEDs e Buzzers
#define LED_R 13         // LED Vermelho
#define LED_B 12         // LED Azul
#define BUZZER_A 21      // Buzzer A
#define BUZZER_B 10      // Buzzer B

// Variável de controle para o modo de alerta
static int modo_alerta = 0;
ssd1306_t oled; // Estrutura que armazena o contexto do display OLED

// Função para atualizar o conteúdo do display OLED
void atualizar_display(const char *mensagem) {
    // Limpa o buffer do display
    memset(oled.ram_buffer + 1, 0, oled.bufsize - 1);

    // Verifica se a mensagem é "Sistema em repouso" e exibe de forma estilizada
    if (strcmp(mensagem, "Sistema em repouso") == 0) {
        ssd1306_draw_string(oled.ram_buffer + 1, 30, 10, (char *)"Sistema");
        ssd1306_draw_string(oled.ram_buffer + 1, 50, 25, (char *)"em");
        ssd1306_draw_string(oled.ram_buffer + 1, 25, 40, (char *)"Repouso");
    } else {
        // Caso contrário, exibe a mensagem diretamente
        ssd1306_draw_string(oled.ram_buffer + 1, 10, 25, (char *)mensagem);
    }

    // Atualiza o display fisicamente
    ssd1306_command(&oled, ssd1306_set_column_address);
    ssd1306_command(&oled, 0);
    ssd1306_command(&oled, OLED_WIDTH - 1);
    ssd1306_command(&oled, ssd1306_set_page_address);
    ssd1306_command(&oled, 0);
    ssd1306_command(&oled, (OLED_HEIGHT / 8) - 1);
    ssd1306_send_data(&oled);
}

// Gera o conteúdo HTML da página web baseada nos parâmetros recebidos
static int generate_html_content(const char *params, char *result, size_t max_len) {
    if (params) {
        // Controle das ações via parâmetros GET
        if (strcmp(params, "acao=ligar") == 0) {
            gpio_put(LED_R, 1); // Liga LED Vermelho
            gpio_put(LED_B, 0);
            gpio_put(BUZZER_A, 0);
            gpio_put(BUZZER_B, 0);
            modo_alerta = 0;    // Desativa modo alerta
            atualizar_display("Sistema ativo");
            printf("[HTTP] LIGAR\n");
        } else if (strcmp(params, "acao=desligar") == 0) {
            gpio_put(LED_R, 0);
            gpio_put(LED_B, 0);
            gpio_put(BUZZER_A, 0);
            gpio_put(BUZZER_B, 0);
            modo_alerta = 0;
            atualizar_display("Sistema em repouso");
            printf("[HTTP] DESLIGAR\n");
        } else if (strcmp(params, "acao=alerta") == 0) {
            modo_alerta = 1;    // Ativa o modo de alerta
            atualizar_display("Evacuar");
            printf("[HTTP] ALERTA ATIVADO\n");
        }
    }

    // Monta a página HTML da interface de controle
    return snprintf(result, max_len,
        "<!DOCTYPE html>"
        "<html lang=\"pt-br\">"
        "<head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Controle de Alarme</title>"
        "<style>"
        "body { font-family: Arial; background-color: #f0f0f0; text-align: center; padding: 50px; }"
        "h1 { color: #333; }"
        ".button { padding: 15px 25px; font-size: 16px; color: #fff; background-color: #4CAF50; border: none; border-radius: 15px; cursor: pointer; }"
        ".button:hover { background-color: #45a049; }"
        ".alerta { background-color: #f44336; }"
        "</style>"
        "</head>"
        "<body>"
        "<h1>Controle de Alarme</h1>"
        "<a href=\"?acao=ligar\"><button class=\"button\">Ligar</button></a><br><br>"
        "<a href=\"?acao=desligar\"><button class=\"button\">Desligar</button></a><br><br>"
        "<a href=\"?acao=alerta\"><button class=\"button alerta\">Alerta</button></a>"
        "</body>"
        "</html>"
    );
}

// Callback que lida com as requisições HTTP recebidas
err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (!p) {
        printf("[HTTP] Conexão encerrada.\n");
        tcp_close(pcb);
        return ERR_OK;
    }

    char headers[512] = {0};
    char response[2048] = {0};  // Buffer maior para suportar a página HTML

    // Copia os headers da requisição HTTP
    pbuf_copy_partial(p, headers, p->tot_len < sizeof(headers) ? p->tot_len : sizeof(headers) - 1, 0);

    // Verifica se é uma requisição GET
    if (strncmp(headers, HTTP_GET, strlen(HTTP_GET)) == 0) {
        char *uri = strchr(headers, ' ');
        if (uri) uri++; else uri = "";
        char *params = strchr(uri, '?');
        if (params) {
            *params++ = 0;
            char *space = strchr(params, ' ');
            if (space) *space = 0;
        }

        // Gera a resposta HTML baseada nos parâmetros
        int body_len = generate_html_content(params, response, sizeof(response));
        char header_response[256];
        snprintf(header_response, sizeof(header_response), HTTP_RESPONSE_HEADERS, 200, body_len);

        // Envia o cabeçalho HTTP e o corpo da resposta (página HTML)
        tcp_write(pcb, header_response, strlen(header_response), 0);
        tcp_write(pcb, response, body_len, 0);
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

// Callback chamado quando uma nova conexão TCP é aceita
err_t tcp_server_accept(void *arg, struct tcp_pcb *new_pcb, err_t err) {
    printf("[HTTP] Nova conexão aceita.\n");
    tcp_recv(new_pcb, tcp_server_recv); // Define a função de callback para receber dados
    return ERR_OK;
}

// Função principal
int main() {
    stdio_init_all(); // Inicializa UART para debug

    // Configuração dos GPIOs
    gpio_init(LED_R); gpio_set_dir(LED_R, GPIO_OUT);
    gpio_init(LED_B); gpio_set_dir(LED_B, GPIO_OUT);
    gpio_init(BUZZER_A); gpio_set_dir(BUZZER_A, GPIO_OUT);
    gpio_init(BUZZER_B); gpio_set_dir(BUZZER_B, GPIO_OUT);

    // Inicializa o barramento I2C para o display OLED
    i2c_init(I2C_PORT, 400 * 1000); // 400kHz
    gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SDA_PIN);
    gpio_pull_up(SCL_PIN);

    // Inicializa e configura o display OLED
    ssd1306_init_bm(&oled, OLED_WIDTH, OLED_HEIGHT, false, ssd1306_i2c_address, I2C_PORT);
    ssd1306_config(&oled);
    ssd1306_init();
    atualizar_display("Sistema em repouso");

    // Inicializa a interface Wi-Fi como Access Point (AP)
    if (cyw43_arch_init()) return 1;
    const char *ap_name = "Controle de Acesso - ALARME";
    const char *password = "1234567@";
    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_WPA2_AES_PSK);

    // Configuração de IP estático
    ip4_addr_t ip, mask;
    IP4_ADDR(&ip, 192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);

    // Inicializa servidores DHCP e DNS
    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &ip, &mask);

    dns_server_t dns_server;
    dns_server_init(&dns_server, &ip);

    // Cria e configura o servidor TCP (porta 80 para HTTP)
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb || tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT) != ERR_OK) {
        printf("[ERRO] Falha ao iniciar servidor.\n");
        return 1;
    }

    pcb = tcp_listen_with_backlog(pcb, 1);
    tcp_accept(pcb, tcp_server_accept);

    printf("[INFO] AP '%s' ativo. Acesse: http://192.168.4.1\n", ap_name);

    // Loop principal do programa
    while (true) {
        static bool led_on = false;
        static bool buzzer_toggle = false;

        if (modo_alerta) {
            // Modo Alerta: Pisca LEDs e alterna buzzers
            gpio_put(LED_R, led_on);
            gpio_put(BUZZER_A, buzzer_toggle);
            gpio_put(BUZZER_B, !buzzer_toggle);
            led_on = !led_on;
            buzzer_toggle = !buzzer_toggle;
        } else {
            // Desliga buzzers quando não está em alerta
            gpio_put(BUZZER_A, 0);
            gpio_put(BUZZER_B, 0);
        }

        sleep_ms(500); // Aguarda meio segundo entre os ciclos
    }

    return 0;
}
