#!/bin/bash
# =================================================================
#	OpenVPN Installer & Manager
#	Baseado no script original do SSH-PRO @TMYCOMNECTVPN
#	Versão Revisada, Refatorada e Aprimorada
# =================================================================

# --- Variáveis de Cor (usando ANSI-C Quoting para robustez) ---
# Usadas para formatar a saída do terminal, tornando-a mais legível.
readonly RED=$'\e[1;31m'
readonly GREEN=$'\e[1;32m'
readonly YELLOW=$'\e[1;33m'
readonly BLUE=$'\e[1;34m'
readonly CYAN=$'\e[1;36m'
readonly WHITE=$'\e[1;37m'
readonly SCOLOR=$'\e[0m'

# --- Funções de Utilidade ---

# Exibe uma mensagem de erro e sai do script.
# Parâmetro 1: Mensagem de erro.
# Parâmetro 2: Código de saída (opcional).
die() {
    echo -e "${RED}[ERRO] $1${SCOLOR}" >&2
    exit "${2:-1}"
}

# Exibe uma mensagem de aviso.
# Parâmetro 1: Mensagem de aviso.
warn() {
    echo -e "${YELLOW}[AVISO] $1${SCOLOR}"
}

# Exibe uma mensagem de sucesso.
# Parâmetro 1: Mensagem de sucesso.
success() {
    echo -e "${GREEN}[SUCESSO] $1${SCOLOR}"
}

# Exibe uma barra de progresso para comandos demorados.
# Parâmetro 1: Comando a ser executado em segundo plano.
fun_bar() {
    local cmd="$1"
    local progress_char="#"
    local spinner="/-\\|"
    local i=0
    
    # Executa o comando em segundo plano, redirecionando a saída
    eval "$cmd" >/dev/null 2>&1 &
    local pid=$!
    
    tput civis # Oculta o cursor
    echo -ne "${YELLOW}Aguarde... [${SCOLOR}"
    
    while ps -p $pid > /dev/null; do
        i=$(( (i+1) %4 ))
        echo -ne "${CYAN}${spinner:$i:1}${SCOLOR}"
        sleep 0.2
        echo -ne "\b"
    done
    
    echo -e "${YELLOW}]${SCOLOR} - ${GREEN}Concluído!${SCOLOR}"
    tput cnorm # Exibe o cursor novamente
}

# --- Verificações Iniciais ---

# Verifica se o script está a ser executado como root.
check_root() {
    [[ "$EUID" -ne 0 ]] && die "Este script precisa ser executado como utilizador ROOT."
}

# Verifica se o script está a ser executado com bash, não sh.
check_bash() {
    readlink /proc/$$/exe | grep -q "bash" || die "Execute este script com bash, não com sh (ex: bash ./script.sh)."
}

# Verifica se o TUN/TAP está disponível.
check_tun() {
    [[ ! -e /dev/net/tun ]] && die "O dispositivo TUN/TAP não está disponível."
}

# Verifica se os comandos necessários estão instalados.
check_dependencies() {
    local missing_deps=()
    for cmd in wget openvpn lsof easy-rsa; do
        command -v "$cmd" &>/dev/null || missing_deps+=("$cmd")
    done
    [[ ${#missing_deps[@]} -gt 0 ]] && die "Dependências em falta: ${missing_deps[*]}. Por favor, instale-as."
}

# --- Detecção de Sistema Operacional ---
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="$ID"
    else
        die "Não foi possível detectar o sistema operacional."
    fi

    case "$OS_ID" in
        ubuntu|debian)
            OS="debian"
            GROUPNAME="nogroup"
            ;;
        centos|fedora|rhel)
            OS="centos"
            GROUPNAME="nobody"
            ;;
        *)
            die "Sistema operacional '$OS_ID' não suportado."
            ;;
    esac
}

# --- Funções Principais do OpenVPN ---

# Instala o OpenVPN e as suas dependências.
install_openvpn() {
    clear
    echo -e "${BLUE}--- Instalador OpenVPN ---${SCOLOR}"
    
    # Instalar dependências
    echo -e "${CYAN}A instalar dependências...${SCOLOR}"
    if [[ "$OS" = "debian" ]]; then
        fun_bar "apt-get update && apt-get install -y openvpn easy-rsa lsof iptables-persistent"
    elif [[ "$OS" = "centos" ]]; then
        fun_bar "yum install -y epel-release && yum install -y openvpn easy-rsa lsof firewalld"
    fi

    # Configurar EasyRSA
    echo -e "${CYAN}A configurar o EasyRSA...${SCOLOR}"
    mkdir -p /etc/openvpn/easy-rsa
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    chmod +x /etc/openvpn/easy-rsa/easyrsa
    cd /etc/openvpn/easy-rsa/ || die "Não foi possível aceder ao diretório easy-rsa."

    # Inicializar PKI e construir CA, certificados de servidor e DH
    ./easyrsa init-pki
    echo "Easy-RSA CA" | ./easyrsa build-ca nopass
    echo "server" | ./easyrsa build-server-full server nopass
    ./easyrsa gen-dh
    openvpn --genkey --secret pki/ta.key
    
    # Copiar ficheiros para o diretório do OpenVPN
    cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem pki/ta.key /etc/openvpn/
    
    # Configurar o servidor
    configure_server
    
    # Configurar o firewall
    configure_firewall

    # Iniciar e habilitar o serviço OpenVPN
    echo -e "${CYAN}A iniciar o serviço OpenVPN...${SCOLOR}"
    systemctl enable openvpn@server
    systemctl start openvpn@server || {
        warn "O serviço OpenVPN falhou ao iniciar."
        echo -e "${YELLOW}Verifique os logs com: ${WHITE}journalctl -xeu openvpn@server.service${SCOLOR}"
        exit 1
    }
    
    success "OpenVPN instalado e iniciado com sucesso!"
    
    # Criar o primeiro cliente
    echo -e "${CYAN}A criar o primeiro cliente...${SCOLOR}"
    create_client "cliente1"
    
    echo -e "\n${CYAN}Pressione ENTER para voltar ao menu...${SCOLOR}"
    read -r
}

# Coleta as configurações do servidor do utilizador.
configure_server() {
    echo -e "${CYAN}A configurar o servidor OpenVPN...${SCOLOR}"
    
    # Obter IP público
    local IP
    IP=$(wget -4qO- "http://whatismyip.akamai.com/") || IP=$(hostname -I | awk '{print $1}')
    
    echo -ne "${WHITE}Porta para o OpenVPN [padrão: 1194]: ${SCOLOR}"
    read -r PORT
    [[ -z "$PORT" ]] && PORT="1194"
    
    echo -ne "${WHITE}Protocolo [1] UDP (padrão) [2] TCP: ${SCOLOR}"
    read -r PROTOCOL_CHOICE
    case $PROTOCOL_CHOICE in
        2) PROTOCOL="tcp" ;;
        *) PROTOCOL="udp" ;;
    esac

    echo -ne "${WHITE}DNS [1] Google (padrão) [2] Cloudflare [3] OpenDNS: ${SCOLOR}"
    read -r DNS_CHOICE
    case $DNS_CHOICE in
        2) DNS1="1.1.1.1"; DNS2="1.0.0.1" ;;
        3) DNS1="208.67.222.222"; DNS2="208.67.220.220" ;;
        *) DNS1="8.8.8.8"; DNS2="8.8.4.4" ;;
    esac
    
    # Criar o ficheiro de configuração do servidor
    cat > /etc/openvpn/server.conf << EOF
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
key-direction 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
keepalive 10 120
cipher AES-256-CBC
user nobody
group $GROUPNAME
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
crl-verify crl.pem
EOF
    # Criar diretórios de log
    mkdir -p /var/log/openvpn
    # Gerar CRL inicial
    cd /etc/openvpn/easy-rsa/ || exit
    ./easyrsa gen-crl
    cp pki/crl.pem /etc/openvpn/crl.pem
}

# Configura as regras de firewall.
configure_firewall() {
    echo -e "${CYAN}A configurar o firewall...${SCOLOR}"
    # Ativar encaminhamento de IP
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p

    if [[ "$OS" = "debian" ]]; then
        local IFACE
        IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
        iptables -A INPUT -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i "$IFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
        netfilter-persistent save
    elif [[ "$OS" = "centos" ]]; then
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --add-service=openvpn --permanent
        firewall-cmd --add-masquerade --permanent
        firewall-cmd --reload
    fi
}


# Cria um novo cliente OpenVPN.
# Parâmetro 1: Nome do cliente.
create_client() {
    local CLIENT_NAME="$1"
    
    if [[ -z "$CLIENT_NAME" ]]; then
        echo -ne "${WHITE}Nome do cliente: ${SCOLOR}"
        read -r CLIENT_NAME
        [[ -z "$CLIENT_NAME" ]] && warn "Nome inválido." && return
    fi
    
    # Verificar se o cliente já existe
    [[ -f "/etc/openvpn/easy-rsa/pki/issued/${CLIENT_NAME}.crt" ]] && warn "Cliente '$CLIENT_NAME' já existe." && return
    
    cd /etc/openvpn/easy-rsa/ || die "Diretório easy-rsa não encontrado."
    
    echo -e "${CYAN}A gerar o certificado para o cliente '$CLIENT_NAME'...${SCOLOR}"
    fun_bar "./easyrsa build-client-full '$CLIENT_NAME' nopass"
    
    # Gerar ficheiro de configuração .ovpn
    local IP PROTOCOL PORT
    IP=$(wget -4qO- "http://whatismyip.akamai.com/") || IP=$(hostname -I | awk '{print $1}')
    PROTOCOL=$(grep '^proto' /etc/openvpn/server.conf | cut -d " " -f 2)
    PORT=$(grep '^port' /etc/openvpn/server.conf | cut -d " " -f 2)
    
    local OVPN_DIR=~/ovpn-clients
    mkdir -p "$OVPN_DIR"
    
    cat > "${OVPN_DIR}/${CLIENT_NAME}.ovpn" << EOF
client
dev tun
proto ${PROTOCOL}
remote ${IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
key-direction 1
verb 3

<ca>
$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat "/etc/openvpn/easy-rsa/pki/issued/${CLIENT_NAME}.crt")
</cert>
<key>
$(cat "/etc/openvpn/easy-rsa/pki/private/${CLIENT_NAME}.key")
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF
    success "Configuração do cliente guardada em: ${OVPN_DIR}/${CLIENT_NAME}.ovpn"
}

# Revoga um cliente OpenVPN existente.
revoke_client() {
    cd /etc/openvpn/easy-rsa/ || die "Diretório easy-rsa não encontrado."
    
    # Listar clientes para seleção
    local clients
    mapfile -t clients < <(./easyrsa list-clients | awk 'NR>1 {print $2}')
    
    [[ ${#clients[@]} -eq 0 ]] && warn "Nenhum cliente para revogar." && return
    
    echo -e "${YELLOW}Selecione o cliente a revogar:${SCOLOR}"
    for i in "${!clients[@]}"; do
        echo "  $((i+1))) ${clients[$i]}"
    done
    
    echo -ne "${WHITE}Número do cliente: ${SCOLOR}"
    read -r choice
    
    # Validar escolha
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#clients[@]} )); then
        warn "Seleção inválida."
        return
    fi
    
    local CLIENT_TO_REVOKE="${clients[$((choice-1))]}"
    
    echo -ne "${YELLOW}Tem a certeza que deseja revogar '$CLIENT_TO_REVOKE'? [s/N]: ${SCOLOR}"
    read -r confirmation
    
    if [[ "$confirmation" =~ ^[sS]$ ]]; then
        echo -e "${CYAN}A revogar o cliente...${SCOLOR}"
        echo "yes" | ./easyrsa revoke "$CLIENT_TO_REVOKE"
        ./easyrsa gen-crl
        cp pki/crl.pem /etc/openvpn/crl.pem
        systemctl restart openvpn@server
        rm -f ~/ovpn-clients/"$CLIENT_TO_REVOKE".ovpn
        success "Cliente '$CLIENT_TO_REVOKE' revogado."
    else
        warn "Operação cancelada."
    fi
}

# Remove completamente a instalação do OpenVPN.
uninstall_openvpn() {
    echo -ne "${RED}Tem a CERTEZA que deseja remover o OpenVPN? Esta ação é irreversível. [s/N]: ${SCOLOR}"
    read -r confirmation
    
    if [[ "$confirmation" =~ ^[sS]$ ]]; then
        echo -e "${RED}A remover o OpenVPN...${SCOLOR}"
        
        systemctl stop openvpn@server
        systemctl disable openvpn@server
        
        if [[ "$OS" = "debian" ]]; then
            fun_bar "apt-get remove --purge -y openvpn easy-rsa && apt-get autoremove -y"
            # Limpar regras de firewall
            iptables -F
            iptables -X
            iptables -t nat -F
            netfilter-persistent save
        elif [[ "$OS" = "centos" ]]; then
            fun_bar "yum remove -y openvpn easy-rsa"
            # Limpar regras de firewall
            firewall-cmd --remove-service=openvpn --permanent
            firewall-cmd --remove-masquerade --permanent
            firewall-cmd --reload
        fi
        
        rm -rf /etc/openvpn ~/ovpn-clients
        
        success "OpenVPN removido com sucesso."
    else
        warn "Remoção cancelada."
    fi
}

# --- Menus de Gestão ---

# Menu principal do script.
main_menu() {
    while true; do
        clear
        echo -e "${BLUE}--- OpenVPN Installer & Manager ---${SCOLOR}"
        echo -e "${CYAN}Versão Funcional Revisada${SCOLOR}\n"
        
        if systemctl is-active --quiet openvpn@server; then
            local port proto
            port=$(grep '^port' /etc/openvpn/server.conf | awk '{print $2}')
            proto=$(grep '^proto' /etc/openvpn/server.conf | awk '{print $2}')
            echo -e "${GREEN}STATUS: Ativo${SCOLOR} | ${WHITE}Porta: $port ($proto)${SCOLOR}\n"
            echo -e "${YELLOW}1)${SCOLOR} Criar um novo cliente"
            echo -e "${YELLOW}2)${SCOLOR} Revogar um cliente existente"
            echo -e "${YELLOW}3)${SCOLOR} Desinstalar o OpenVPN"
            echo -e "${YELLOW}0)${SCOLOR} Sair"
        else
            echo -e "${RED}STATUS: Não Instalado${SCOLOR}\n"
            echo -e "${YELLOW}1)${SCOLOR} Instalar OpenVPN"
            echo -e "${YELLOW}0)${SCOLOR} Sair"
        fi
        
        echo -ne "\n${WHITE}Escolha uma opção: ${SCOLOR}"
        read -r choice
        
        if systemctl is-active --quiet openvpn@server; then
            case "$choice" in
                1) create_client ;;
                2) revoke_client ;;
                3) uninstall_openvpn; main_menu ;;
                0) exit 0 ;;
                *) warn "Opção inválida." ;;
            esac
        else
            case "$choice" in
                1) install_openvpn ;;
                0) exit 0 ;;
                *) warn "Opção inválida." ;;
            esac
        fi
        [[ -n "$choice" && "$choice" != "0" ]] && echo -e "\n${CYAN}Pressione ENTER para continuar...${SCOLOR}" && read -r
    done
}

# --- Ponto de Entrada do Script ---
main() {
    clear
    check_root
    check_bash
    check_tun
    detect_os
    # A verificação de dependências é feita antes da instalação.
    main_menu
}

# Executa a função principal
main