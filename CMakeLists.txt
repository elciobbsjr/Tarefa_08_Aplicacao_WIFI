# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.1.1)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.1.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# === Configuração da Placa ===
set(PICO_BOARD pico_w CACHE STRING "Board type")

# Importa o SDK Pico
include(pico_sdk_import.cmake)

# Define o nome do projeto
project(Tarefa_08_Aplicacao_WIFI C CXX ASM)

# Inicializa o SDK Pico
pico_sdk_init()

# Adiciona o executável com os arquivos fonte
add_executable(Tarefa_08_Aplicacao_WIFI 
    Tarefa_08_Aplicacao_WIFI.c
    dhcpserver/dhcpserver.c
    dnsserver/dnsserver.c
    inc/ssd1306_i2c.c  # Adiciona o driver do display OLED
)

# Inclui diretórios de cabeçalhos
target_include_directories(Tarefa_08_Aplicacao_WIFI PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/dhcpserver
    ${CMAKE_CURRENT_LIST_DIR}/dnsserver
    ${CMAKE_CURRENT_LIST_DIR}/inc  # Inclui as bibliotecas do display OLED
)

# Linka as bibliotecas necessárias
target_link_libraries(Tarefa_08_Aplicacao_WIFI
    pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background
    pico_stdio_usb  # Ativa saída USB CDC para monitor serial
    hardware_i2c    # Necessário para o uso do I2C com o display
)

# Configura IP fixo para o Access Point
pico_configure_ip4_address(Tarefa_08_Aplicacao_WIFI PRIVATE
    CYW43_DEFAULT_IP_AP_ADDRESS 192.168.4.1
)

# Geração de arquivos de saída (UF2, bin, etc.)
pico_add_extra_outputs(Tarefa_08_Aplicacao_WIFI)
