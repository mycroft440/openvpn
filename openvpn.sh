#!/bin/bash
# =================================================================
#	OpenVPN Installer & Manager
#	Baseado no script original do SSH-PRO @TMYCOMNECTVPN
#	Versão Revisada, Refatorada e Aprimorada
# =================================================================

# --- Variáveis de Cor ---
readonly RED=$'\e[1;31m'
readonly GREEN=$'\e[1;32m'
readonly YELLOW=$'\e[1;33m'
readonly BLUE=$'\e[1;34m'
readonly CYAN=$'\e[1;36m'
readonly WHITE=$'\e[1;37m'
readonly SCOLOR=$'\e[0m'

# --- Funções de Utilidade ---

die() {
    echo -e "${RED}[ERRO] $1${SCOLOR}" >&2
    exit "${2:-1}"
}

warn() {
    echo -e "${YELLOW}[AVISO] $1${SCOLOR}"
}

success() {
    echo -e "${GREEN}[SUCESSO] $1${SCOLOR}"
}

fun_bar() {
    local cmd="$1"
    local spinner="/-\\|"
    local i=0
    
    eval "$cmd" >/dev/null 2>&1 &
    local pid=$!
    
    tput civis
    echo -ne "${YELLOW}Aguarde... [${SCOLOR}"
    
    while ps -p $pid > /dev/null; do
        i=$(( (i+1) % 4 ))
        echo -ne "${CYAN}${spinner:$i:1}${SCOLOR}"
        sleep 0.2
        echo -ne "\b"
    done
    
    echo -e "${YELLOW}]${SCOLOR} - ${GREEN}Concluído!${SCOLOR}"
    tput cnorm
    wait $pid || die "Comando falhou: $cmd"
}

# --- Verificações Iniciais ---

check_root() {
    [[ "$EUID" -ne 0 ]] && die "Este script precisa ser executado como ROOT."
}

check_bash() {
    readlink /proc/$$/exe | grep -q "bash" || die "Execute este script com bash, não com sh."
}

check_tun() {
    [[ ! -e /dev/net/tun ]] && die "O dispositivo TUN/TAP não está disponível."
}

check_dependencies() {
    local missing_deps=()
    for cmd in wget openvpn lsof easy-rsa iptables ip; do
        command -v "$cmd" >/dev/null 2>&1 || missing_deps+=("$cmd")
    done
    [[ ${#missing_deps[@]} -gt 0 ]] && die "Dependências em falta: ${missing_deps[*]}."
}

# --- Detecção de Sistema Operacional ---

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="$ID"
    else
        die "Não foi possível detectar o sistema operacional."
    fi

    case "$OS_ID" in
        ubuntu|debian) OS="debian"; GROUPNAME="nogroup" ;;
        centos|fedora|rhel) OS="centos"; GROUPNAME="nobody" ;;
        *) die "Sistema operacional '$OS_ID' não suportado." ;;
    esac
}

# --- Funções Principais do OpenVPN ---

install_openvpn() {
    clear
    echo -e "${BLUE}--- Instalador OpenVPN ---${SCOLOR}"
    
    echo -e "${CYAN}A instalar dependências...${SCOLOR}"
    if [[ "$OS" = "debian" ]]; then
        fun_bar "apt update && apt install -y openvpn easy-rsa lsof iptables-persistent"
    elif [[ "$OS" = "centos" ]]; then
        fun_bar "yum install -y epel-release && yum install -y openvpn easy-rsa lsof firewalld"
    fi

    local EASY_RSA_DIR="/etc/openvpn/easy-rsa"
    mkdir -p "$EASY_RSA_DIR" || die "Falha ao criar diretório $EASY_RSA_DIR."
    cp -r /usr/share/easy-rsa/* "$EASY_RSA_DIR/" || die "EasyRSA não encontrado em /usr/share/easy-rsa."
    chmod +x "$EASY_RSA_DIR/easyrsa"
    cd "$EASY_RSA_DIR" || die "Não foi possível acessar $EASY_RSA_DIR."

    echo -e "${CYAN}A configurar EasyRSA...${SCOLOR}"
    ./easyrsa init-pki || die "Falha ao inicializar PKI."
    echo "Easy-RSA CA" | ./easyrsa build-ca nopass || die "Falha ao criar CA."
    echo "server" | ./easyrsa build-server-full server nopass || die "Falha ao criar certificado do servidor."
    ./easyrsa gen-dh || die "Falha ao gerar DH."
    openvpn --genkey --secret pki/ta.key || die "Falha ao gerar chave TA."
    
    cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem pki/ta.key /etc/openvpn/ || die "Falha ao copiar arquivos."
    chown root:root /etc/openvpn/*.{key,crt,pem} || die " falha ao ajustar propriedade."
    chmod 600 /etc/openvpn/*.{key,crt,pem} || die "Falha ao ajustar permissões."
    
    configure_server
    configure_firewall

    echo -e "${CYAN}A iniciar o serviço OpenVPN...${SCOLOR}"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable openvpn@server || die "Falha ao habilitar o serviço."
        systemctl start openvpn@server || die "Falha ao iniciar o serviço."
    else
        service openvpn@server start || die "Falha ao iniciar o serviço sem systemd."
    fi
    
    success "OpenVPN instalado e iniciado com sucesso!"
    
    echo -e "${CYAN}A criar o primeiro cliente...${SCOLOR}"
    create_client "cliente1"
    
    echo -e "\n${CYAN}Pressione ENTER para voltar ao menu...${SCOLOR}"
    read -r
}

configure_server() {
    echo -e "${CYAN}A configurar o servidor OpenVPN...${SCOLOR}"
    
    local IP
    IP=$(wget -4qO- "http://whatismyip.akamai.com/") || IP=$(hostname -I | awk '{print $1}')
    [[ -z "$IP" ]] && die "Não foi possível determinar o IP público."
    
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
    
    mkdir -p /var/log/openvpn || die "Falha ao criar diretório de logs."
    chown nobody:$GROUPNAME /var/log/openvpn || die "Falha ao ajustar permissões de logs."
    
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
    cd /etc/openvpn/easy-rsa/ || die "Diretório easy-rsa não encontrado."
    ./easyrsa gen-crl || die "Falha ao gerar CRL."
    cp pki/crl.pem /etc/openvpn/crl.pem || die "Falha ao copiar CRL."
    chown root:root /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
}

configure_firewall() {
    echo -e "${CYAN}A configurar o firewall...${SCOLOR}"
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p >/dev/null || die "Falha ao ativar encaminhamento de IP."

    if [[ "$OS" = "debian" ]]; then
        local IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
        [[ -z "$IFACE" ]] && die "Não foi possível determinar a interface de rede."
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
        iptables -A INPUT -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i "$IFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables-save > /etc/iptables/rules.v4 || die "Falha ao salvar regras iptables."
    elif [[ "$OS" = "centos" ]]; then
        systemctl start firewalld || die "Falha ao iniciar firewalld."
        systemctl enable firewalld || die "Falha ao habilitar firewalld."
        firewall-cmd --add-service=openvpn --permanent || die "Falha ao adicionar serviço OpenVPN."
        firewall-cmd --add-masquerade --permanent || die "Falha ao adicionar masquerade."
        firewall-cmd --reload || die "Falha ao recarregar firewalld."
    fi
}

create_client() {
    local CLIENT_NAME="$1"
    
    if [[ -z "$CLIENT_NAME" ]]; then
        echo -ne "${WHITE}Nome do cliente: ${SCOLOR}"
        read -r CLIENT_NAME
        [[ -z "$CLIENT_NAME" ]] && warn "Nome inválido." && return
    fi
    
    cd /etc/openvpn/easy-rsa/ || die "Diretório easy-rsa não encontrado."
    [[ -f "pki/issued/${CLIENT_NAME}.crt" ]] && warn "Cliente '$CLIENT_NAME' já existe." && return
    
    echo -e "${CYAN}A gerar certificado para '$CLIENT_NAME'...${SCOLOR}"
    fun_bar "./easyrsa build-client-full '$CLIENT_NAME' nopass"
    
    local IP PROTOCOL PORT
    IP=$(wget -4qO- "http://whatismyip.akamai.com/") || IP=$(hostname -I | awk '{print $1}')
    PROTOCOL=$(grep '^proto' /etc/openvpn/server.conf | cut -d " " -f 2)
    PORT=$(grep '^port' /etc/openvpn/server.conf | cut -d " " -f 2)
    
    local OVPN_DIR=~/ovpn-clients
    mkdir -p "$OVPN_DIR" || die "Falha ao criar diretório $OVPN_DIR."
    
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
    success "Configuração do cliente salva em: ${OVPN_DIR}/${CLIENT_NAME}.ovpn"
}

revoke_client() {
    cd /etc/openvpn/easy-rsa/ || die "Diretório easy-rsa não encontrado."
    
    local clients=()
    while IFS= read -r file; do
        clients+=("$(basename "$file" .crt)")
    done < <(ls -1 pki/issued/*.crt 2>/dev/null)
    
    [[ ${#clients[@]} -eq 0 ]] && warn "Nenhum cliente para revogar." && return
    
    echo -e "${YELLOW}Selecione o cliente a revogar:${SCOLOR}"
    for i in "${!clients[@]}"; do
        echo "  $((i+1))) ${clients[$i]}"
    done
    
    echo -ne "${WHITE}Número do cliente: ${SCOLOR}"
    read -r choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#clients[@]} )); then
        warn "Seleção inválida."
        return
    fi
    
    local CLIENT_TO_REVOKE="${clients[$((choice-1))]}"
    
    echo -ne "${YELLOW}Tem certeza que deseja revogar '$CLIENT_TO_REVOKE'? [s/N]: ${SCOLOR}"
    read -r confirmation
    
    if [[ "$confirmation" =~ ^[sS]$ ]]; then
        echo -e "${CYAN}A revogar o cliente...${SCOLOR}"
        echo "yes" | ./easyrsa revoke "$CLIENT_TO_REVOKE" || die "Falha ao revogar cliente."
        ./easyrsa gen-crl || die "Falha ao gerar CRL."
        cp pki/crl.pem /etc/openvpn/crl.pem || die "Falha ao atualizar CRL."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart openvpn@server || die "Falha ao reiniciar serviço."
        else
            service openvpn@server restart || die "Falha ao reiniciar serviço sem systemd."
        fi
        rm -f ~/ovpn-clients/"$CLIENT_TO_REVOKE".ovpn
        success "Cliente '$CLIENT_TO_REVOKE' revogado."
    else
        warn "Operação cancelada."
    fi
}

uninstall_openvpn() {
    echo -ne "${RED}Tem CERTEZA que deseja remover o OpenVPN? [s/N]: ${SCOLOR}"
    read -r confirmation
    
    if [[ "$confirmation" =~ ^[sS]$ ]]; then
        echo -e "${RED}A remover o OpenVPN...${SCOLOR}"
        
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop openvpn@server 2>/dev/null
            systemctl disable openvpn@server 2>/dev/null
        else
            service openvpn@server stop 2>/dev/null
        fi
        
        if [[ "$OS" = "debian" ]]; then
            fun_bar "apt remove --purge -y openvpn easy-rsa && apt autoremove -y"
            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE 2>/dev/null
            iptables -D INPUT -i tun+ -j ACCEPT 2>/dev/null
            iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null
            iptables -D FORWARD -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
            iptables-save > /etc/iptables/rules.v4
        elif [[ "$OS" = "centos" ]]; then
            fun_bar "yum remove -y openvpn easy-rsa"
            firewall-cmd --remove-service=openvpn --permanent 2>/dev/null
            firewall-cmd --remove-masquerade --permanent 2>/dev/null
            firewall-cmd --reload 2>/dev/null
        fi
        
        rm -rf /etc/openvpn ~/ovpn-clients
        success "OpenVPN removido com sucesso."
    else
        warn "Remoção cancelada."
    fi
}

# --- Menus de Gestão ---

main_menu() {
    while true; do
        clear
        echo -e "${BLUE}--- OpenVPN Installer & Manager ---${SCOLOR}"
        echo -e "${CYAN}Versão Funcional Revisada${SCOLOR}\n"
        
        if systemctl is-active --quiet openvpn@server 2>/dev/null || service openvpn@server status >/dev/null 2>&1; then
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
        
        if systemctl is-active --quiet openvpn@server 2>/dev/null || service openvpn@server status >/dev/null 2>&1; then
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

# --- Ponto de Entrada ---

main() {
    clear
    check_root
    check_bash
    check_tun
    detect_os
    check_dependencies
    main_menu
}

main