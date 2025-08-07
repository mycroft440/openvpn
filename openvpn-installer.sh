#!/bin/bash
#====================================================
#	OpenVPN Installer & Manager
#	Baseado no script original do SSH-PRO @TMYCOMNECTVPN
#	Versão Revisada e Funcional
#====================================================

# Cores
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
SCOLOR='\033[0m'

# Verificações iniciais
[[ "$EUID" -ne 0 ]] && {
    echo -e "${RED}[x] VOCÊ PRECISA EXECUTAR COMO USUÁRIO ROOT!${SCOLOR}"
    exit 1
}

# Verificar se é bash
if readlink /proc/$$/exe | grep -qs "dash"; then
    echo -e "${RED}Este script precisa ser executado com bash, não sh${SCOLOR}"
    exit 1
fi

# Verificar TUN/TAP
[[ ! -e /dev/net/tun ]] && {
    echo -e "${RED}TUN TAP NÃO DISPONÍVEL${SCOLOR}"
    exit 3
}

# Detectar OS
if [[ -e /etc/debian_version ]]; then
    OS=debian
    GROUPNAME=nogroup
    RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
    OS=centos
    GROUPNAME=nobody
    RCLOCAL='/etc/rc.d/rc.local'
else
    echo -e "${RED}SISTEMA NÃO SUPORTADO${SCOLOR}"
    exit 5
fi

# Função de barra de progresso (mantida para feedback visual)
fun_bar() {
    comando[0]="$1"
    comando[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${comando[0]} >/dev/null 2>&1
        ${comando[1]} >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "${YELLOW}AGUARDE ${WHITE}- ${YELLOW}["
    while true; do
        for ((i = 0; i < 18; i++)); do
            echo -ne "${RED}#"
            sleep 0.1s
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -e "${YELLOW}]"
        sleep 1s
        tput cuu1
        tput dl1
        echo -ne "${YELLOW}AGUARDE ${WHITE}- ${YELLOW}["
    done
    echo -e "${YELLOW}]${WHITE} -${GREEN} OK !${WHITE}"
    tput cnorm
}

# Função para verificar portas em uso
verif_ptrs() {
    porta=$1
    PT=$(lsof -V -i tcp -P -n 2>/dev/null | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    for pton in $(echo -e "$PT" | cut -d: -f2 | cut -d' ' -f1 | uniq); do
        svcs=$(echo -e "$PT" | grep -w "$pton" | awk '{print $1}' | uniq)
        [[ "$porta" = "$pton" ]] && {
            echo -e "\n${RED}PORTA ${YELLOW}$porta ${RED}EM USO PELO ${WHITE}$svcs${SCOLOR}"
            sleep 3
            menu_principal
        }
    done
}

# Função para criar novo cliente
newclient() {
    CLIENT_NAME=$1
    cd /etc/openvpn/easy-rsa/
    ./easyrsa build-client-full $CLIENT_NAME nopass
    
    # Gerar arquivo .ovpn
    mkdir -p ~/ovpn_clients
    cat > ~/ovpn_clients/$CLIENT_NAME.ovpn << EOF
client
dev tun
proto $PROTOCOL
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server

<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(cat pki/issued/$CLIENT_NAME.crt)
</cert>
<key>
$(cat pki/private/$CLIENT_NAME.key)
</key>
<tls-auth>
$(cat pki/ta.key)
</tls-auth>
EOF
    echo -e "${GREEN}Arquivo de cliente gerado: ~/ovpn_clients/$CLIENT_NAME.ovpn${SCOLOR}"
}

# Função principal do OpenVPN
fun_openvpn() {
    # Detectar IP
    IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    [[ "$IP" = "" ]] && {
        IP=$(hostname -I | cut -d' ' -f1)
    }

    # Verificar se OpenVPN já está instalado
    if systemctl is-active --quiet openvpn@server;
    then
        gerenciar_openvpn
        return
    fi

    # Instalação do OpenVPN
    clear
    echo -e "\E[44;1;37m          INSTALADOR OPENVPN           \E[0m"
    echo ""
    echo -e "${GREEN}Iniciando instalação do OpenVPN...${SCOLOR}"
    echo ""

    # Instalar dependências
    echo -e "${YELLOW}Instalando dependências...${SCOLOR}"
    if [[ "$OS" = "debian" ]]; then
        fun_bar 'apt-get update' 'apt-get install -y openvpn easy-rsa lsof'
    elif [[ "$OS" = "centos" ]]; then
        fun_bar 'yum update -y' 'yum install -y openvpn easy-rsa lsof'
    fi

    # Configurar EasyRSA
    echo -e "${YELLOW}Configurando EasyRSA...${SCOLOR}"
    mkdir -p /etc/openvpn/easy-rsa
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    chmod +x /etc/openvpn/easy-rsa/easyrsa
    cd /etc/openvpn/easy-rsa/
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-dh
    openvpn --genkey --secret pki/ta.key
    
    # Copiar arquivos para o diretório do OpenVPN
    cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem pki/ta.key /etc/openvpn/

    # Configurar servidor
    echo -e "${YELLOW}Configurando servidor OpenVPN...${SCOLOR}"
    echo -ne "${GREEN}Qual porta deseja usar para o OpenVPN? ${YELLOW}[1194]: ${WHITE}"
    read -e -i 1194 PORT
    echo -ne "${GREEN}Qual protocolo deseja usar? ${YELLOW}[1] UDP [2] TCP: ${WHITE}"
    read -e -i 1 PROTOCOL_CHOICE
    case $PROTOCOL_CHOICE in
        1) PROTOCOL=udp ;;
        2) PROTOCOL=tcp ;;
        *) PROTOCOL=udp ;;
    esac

    echo -ne "${GREEN}Qual DNS deseja usar? ${YELLOW}[1] Google [2] Cloudflare [3] OpenDNS: ${WHITE}"
    read -e -i 1 DNS_CHOICE
    case $DNS_CHOICE in
        1) DNS1=8.8.8.8; DNS2=8.8.4.4 ;;
        2) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
        3) DNS1=208.67.222.222; DNS2=208.67.220.220 ;;
        *) DNS1=8.8.8.8; DNS2=8.8.4.4 ;;
    esac

    # Criar configuração do servidor
    cat > /etc/openvpn/server.conf << EOF
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
key-direction 0
cipher AES-256-CBC
auth SHA256
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
keepalive 10 120
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem
explicit-exit-notify 1
EOF

    # Habilitar encaminhamento IP
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p

    # Configurar firewall
    echo -e "${YELLOW}Configurando firewall...${SCOLOR}"
    if [[ "$OS" = "debian" ]]; then
        apt-get install -y iptables-persistent
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
        iptables -A INPUT -i tun0 -j ACCEPT
        iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
        netfilter-persistent save
        netfilter-persistent reload
    elif [[ "$OS" = "centos" ]]; then
        yum install -y firewalld
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL --permanent
        firewall-cmd --zone=public --add-masquerade --permanent
        firewall-cmd --set-default-zone=trusted
        firewall-cmd --reload
    fi

    # Iniciar e habilitar OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server

    echo ""
    echo -e "${GREEN}OpenVPN instalado com sucesso!${SCOLOR}"
    echo -e "${YELLOW}Criando primeiro cliente...${SCOLOR}"
    
    echo -ne "${GREEN}Nome do primeiro cliente: ${WHITE}"
    read -e CLIENT
    newclient $CLIENT
    
    echo ""
    echo -e "${GREEN}Cliente criado! Arquivo: ~/ovpn_clients/$CLIENT.ovpn${SCOLOR}"
    echo ""
    echo -e "${GREEN}Pressione ENTER para continuar...${SCOLOR}"
    read
}

# Função para gerenciar OpenVPN
gerenciar_openvpn() {
    while :; do
        clear
        
        opnp=$(grep "^port" /etc/openvpn/server.conf | awk '{print $2}')
        mult=$(grep -q "duplicate-cn" /etc/openvpn/server.conf && echo -e "${GREEN}◉ " || echo -e "${RED}○ ")
        
        echo -e "\E[44;1;37m          GERENCIAR OPENVPN           \E[0m"
        echo ""
        echo -e "${YELLOW}PORTA${WHITE}: ${GREEN}$opnp${SCOLOR}"
        echo ""
        echo -e "${RED}[${CYAN}1${RED}] ${WHITE}• ${YELLOW}ALTERAR PORTA"
        echo -e "${RED}[${CYAN}2${RED}] ${WHITE}• ${YELLOW}CRIAR CLIENTE"
        echo -e "${RED}[${CYAN}3${RED}] ${WHITE}• ${YELLOW}REMOVER CLIENTE"
        echo -e "${RED}[${CYAN}4${RED}] ${WHITE}• ${YELLOW}REMOVER OPENVPN"
        echo -e "${RED}[${CYAN}5${RED}] ${WHITE}• ${YELLOW}MULTILOGIN OVPN $mult"
        echo -e "${RED}[${CYAN}6${RED}] ${WHITE}• ${YELLOW}ALTERAR HOST DNS"
        echo -e "${RED}[${CYAN}7${RED}] ${WHITE}• ${YELLOW}LISTAR CLIENTES"
        echo -e "${RED}[${CYAN}0${RED}] ${WHITE}• ${YELLOW}VOLTAR"
        echo ""
        echo -ne "${GREEN}O QUE DESEJA FAZER ${YELLOW}?${RED}?${WHITE} "
        read option
        
        case $option in
            1) alterar_porta ;;
            2) criar_cliente ;;
            3) remover_cliente ;;
            4) remover_openvpn ;;
            5) toggle_multilogin ;;
            6) alterar_dns ;;
            7) listar_clientes ;;
            0) menu_principal ;;
            *) echo -e "${RED}Opção inválida!${SCOLOR}"; sleep 2 ;;
        esac
    done
}

# Função para alterar porta
alterar_porta() {
    clear
    echo -e "\E[44;1;37m         ALTERAR PORTA OPENVPN         \E[0m"
    echo ""
    opnp=$(grep "^port" /etc/openvpn/server.conf | awk '{print $2}')
    echo -e "${YELLOW}PORTA EM USO: ${GREEN}$opnp${SCOLOR}"
    echo ""
    echo -ne "${GREEN}QUAL PORTA DESEJA UTILIZAR ${YELLOW}?${WHITE} "
    read porta
    [[ -z "$porta" ]] && {
        echo ""
        echo -e "${RED}Porta inválida!${SCOLOR}"
        sleep 3
        return
    }
    verif_ptrs $porta
    
    # Atualizar porta no server.conf
    sed -i "s/^port .*/port $porta/" /etc/openvpn/server.conf
    
    # Atualizar firewall
    if [[ "$OS" = "debian" ]]; then
        iptables -D INPUT -p $PROTOCOL --dport $opnp -j ACCEPT
        iptables -A INPUT -p $PROTOCOL --dport $porta -j ACCEPT
        netfilter-persistent save
        netfilter-persistent reload
    elif [[ "$OS" = "centos" ]]; then
        firewall-cmd --zone=public --remove-port=$opnp/$PROTOCOL --permanent
        firewall-cmd --zone=public --add-port=$porta/$PROTOCOL --permanent
        firewall-cmd --reload
    fi
    
    systemctl restart openvpn@server
    echo ""
    echo -e "${GREEN}PORTA ALTERADA COM SUCESSO!${SCOLOR}"
    sleep 2
}

# Função para criar cliente
criar_cliente() {
    clear
    echo -e "\E[44;1;37m           CRIAR CLIENTE            \E[0m"
    echo ""
    echo -ne "${GREEN}Nome do cliente: ${WHITE}"
    read CLIENT
    [[ -z "$CLIENT" ]] && {
        echo -e "${RED}Nome inválido!${SnCOLOR}"
        sleep 2
        return
    }
    
    # Verificar se cliente já existe
    if [[ -f /etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt ]]; then
        echo -e "${RED}Cliente já existe!${SCOLOR}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${GREEN}Criando cliente...${SCOLOR}"
    newclient $CLIENT
    
    echo ""
    echo -e "${GREEN}Cliente criado! Arquivo: ~/ovpn_clients/$CLIENT.ovpn${SCOLOR}"
    echo ""
    echo -e "${GREEN}Pressione ENTER para continuar...${SCOLOR}"
    read
}

# Função para remover cliente
remover_cliente() {
    clear
    echo -e "\E[44;1;37m          REMOVER CLIENTE           \E[0m"
    echo ""
    
    cd /etc/openvpn/easy-rsa/
    CLIENT_LIST=$(./easyrsa list-clients | grep -v 'Name' | grep -v '----')
    if [[ -z "$CLIENT_LIST" ]]; then
        echo -e "${RED}Nenhum cliente encontrado!${SCOLOR}"
        sleep 2
        return
    fi
    
    echo -e "${YELLOW}Clientes disponíveis:${SCOLOR}"
    echo "$CLIENT_LIST" | nl -s ') '
    echo ""
    echo -ne "${GREEN}Selecione o número do cliente para remover: ${WHITE}"
    read CLIENT_NUMBER
    
    CLIENT=$(echo "$CLIENT_LIST" | sed -n "${CLIENT_NUMBER}p")
    [[ -z "$CLIENT" ]] && {
        echo -e "${RED}Seleção inválida!${SCOLOR}"
        sleep 2
        return
    }
    
    echo ""
    echo -ne "${GREEN}Confirma remoção do cliente ${YELLOW}$CLIENT${GREEN}? ${RED}[s/n]: ${WHITE}"
    read REMOVE
    [[ "$REMOVE" = 's' ]] && {
        ./easyrsa revoke $CLIENT
        ./easyrsa gen-crl
        cp pki/crl.pem /etc/openvpn/crl.pem
        rm -f ~/ovpn_clients/$CLIENT.ovpn
        systemctl restart openvpn@server
        echo ""
        echo -e "${GREEN}Cliente removido com sucesso!${SCOLOR}"
    } || {
        echo -e "${RED}Operação cancelada!${SCOLOR}"
    }
    sleep 2
}

# Função para remover OpenVPN
remover_openvpn() {
    clear
    echo -e "\E[44;1;37m          REMOVER OPENVPN           \E[0m"
    echo ""
    echo -ne "${GREEN}DESEJA REMOVER O OPENVPN ${RED}? ${YELLOW}[s/n]:${WHITE} "
    read REMOVE
    [[ "$REMOVE" = 's' ]] && {
        echo ""
        echo -e "${GREEN}REMOVENDO OPENVPN...${SCOLOR}"
        
        if [[ "$OS" = "debian" ]]; then
            apt-get remove --purge -y openvpn easy-rsa
            rm -rf /etc/openvpn
            rm -f /etc/sysctl.d/99-openvpn.conf
            sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
            sysctl -p
            apt-get autoremove -y
            apt-get clean
            # Remover regras do iptables
            iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
            iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
            iptables -D INPUT -i tun0 -j ACCEPT
            iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT
            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
            netfilter-persistent save
            netfilter-persistent reload
        elif [[ "$OS" = "centos" ]]; then
            yum remove -y openvpn easy-rsa
            rm -rf /etc/openvpn
            sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
            sysctl -p
            yum autoremove -y
            yum clean all
            firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL --permanent
            firewall-cmd --zone=public --remove-masquerade --permanent
            firewall-cmd --reload
        fi
        
        rm -rf ~/ovpn_clients
        
        echo ""
        echo -e "${GREEN}OPENVPN REMOVIDO COM SUCESSO!${SCOLOR}"
        sleep 3
        menu_principal
    } || {
        echo -e "${RED}Operação cancelada!${SCOLOR}"
        sleep 2
    }
}

# Função para toggle multilogin
toggle_multilogin() {
    if grep -q "duplicate-cn" /etc/openvpn/server.conf;
    then
        sed -i '/duplicate-cn/d' /etc/openvpn/server.conf
        echo -e "${YELLOW}Multilogin desabilitado!${SCOLOR}"
    else
        echo "duplicate-cn" >> /etc/openvpn/server.conf
        echo -e "${GREEN}Multilogin habilitado!${SCOLOR}"
    fi
    systemctl restart openvpn@server
    sleep 2
}

# Função para alterar DNS
alterar_dns() {
    clear
    echo -e "\E[44;1;37m           ALTERAR DNS             \E[0m"
    echo ""
    echo -e "${YELLOW}Selecione o DNS:${SCOLOR}"
    echo -e "${RED}[${CYAN}1${RED}] ${WHITE}Google (8.8.8.8)"
    echo -e "${RED}[${CYAN}2${RED}] ${WHITE}Cloudflare (1.1.1.1)"
    echo -e "${RED}[${CYAN}3${RED}] ${WHITE}OpenDNS (208.67.222.222)"
    echo -e "${RED}[${CYAN}4${RED}] ${WHITE}Personalizado"
    echo ""
    echo -ne "${GREEN}Opção: ${WHITE}"
    read DNS_CHOICE
    
    case $DNS_CHOICE in
        1) DNS1=8.8.8.8; DNS2=8.8.4.4 ;;
        2) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
        3) DNS1=208.67.222.222; DNS2=208.67.220.220 ;;
        4) 
            echo -ne "${GREEN}DNS Primário: ${WHITE}"
            read DNS1
            echo -ne "${GREEN}DNS Secundário: ${WHITE}"
            read DNS2
            ;;
        *) echo -e "${RED}Opção inválida!${SCOLOR}"; sleep 2; return ;;
    esac
    
    # Atualizar DNS no server.conf
    sed -i '/^push "dhcp-option DNS/d' /etc/openvpn/server.conf
    echo "push \"dhcp-option DNS $DNS1\"" >> /etc/openvpn/server.conf
    echo "push \"dhcp-option DNS $DNS2\"" >> /etc/openvpn/server.conf
    
    systemctl restart openvpn@server
    echo ""
    echo -e "${GREEN}DNS alterado com sucesso!${SCOLOR}"
    echo -e "${YELLOW}DNS1: $DNS1 | DNS2: $DNS2${SCOLOR}"
    sleep 2
}

# Função para listar clientes
listar_clientes() {
    clear
    echo -e "\E[44;1;37m          CLIENTES OPENVPN          \E[0m"
    echo ""
    
    cd /etc/openvpn/easy-rsa/
    CLIENT_LIST=$(./easyrsa list-clients | grep -v 'Name' | grep -v '----')
    if [[ -z "$CLIENT_LIST" ]]; then
        echo -e "${RED}Nenhum cliente encontrado!${SCOLOR}"
    else
        echo -e "${GREEN}Clientes ativos:${SCOLOR}"
        echo "$CLIENT_LIST" | nl -s ') '
    fi
    
    echo ""
    echo -e "${GREEN}Pressione ENTER para continuar...${SCOLOR}"
    read
}

# Menu principal
menu_principal() {
    while :; do
        clear
        echo -e "\E[44;1;37m          OPENVPN MANAGER           \E[0m"
        echo ""
        
        # Verificar status do OpenVPN
        if systemctl is-active --quiet openvpn@server;
        then
            opnp=$(grep "^port" /etc/openvpn/server.conf | awk '{print $2}')
            echo -e "${GREEN}Status: ${WHITE}OpenVPN Ativo - Porta: ${GREEN}$opnp${SCOLOR}"
            echo ""
            echo -e "${RED}[${CYAN}1${RED}] ${WHITE}• ${YELLOW}GERENCIAR OPENVPN"
            echo -e "${RED}[${CYAN}2${RED}] ${WHITE}• ${YELLOW}CRIAR CLIENTE"
            echo -e "${RED}[${CYAN}3${RED}] ${WHITE}• ${YELLOW}REMOVER OPENVPN"
        else
            echo -e "${RED}Status: ${WHITE}OpenVPN Não Instalado${SCOLOR}"
            echo ""
            echo -e "${RED}[${CYAN}1${RED}] ${WHITE}• ${YELLOW}INSTALAR OPENVPN"
        fi
        
        echo -e "${RED}[${CYAN}0${RED}] ${WHITE}• ${YELLOW}SAIR"
        echo ""
        echo -ne "${GREEN}Selecione uma opção: ${WHITE}"
        read option
        
        case $option in
            1)
                if systemctl is-active --quiet openvpn@server;
                then
                    gerenciar_openvpn
                else
                    fun_openvpn
                fi
                ;;
            2)
                if systemctl is-active --quiet openvpn@server;
                then
                    criar_cliente
                else
                    echo -e "${RED}OpenVPN não está instalado!${SCOLOR}"
                    sleep 2
                fi
                ;;
            3)
                if systemctl is-active --quiet openvpn@server;
                then
                    remover_openvpn
                else
                    echo -e "${RED}OpenVPN não está instalado!${SCOLOR}"
                    sleep 2
                fi
                ;;
            0)
                clear
                echo -e "${GREEN}Saindo...${SCOLOR}"
                exit 0
                ;;
            *)
                echo -e "${RED}Opção inválida!${SCOLOR}"
                sleep 2
                ;;
        esac
    done
}

# Iniciar script
clear
menu_principal


