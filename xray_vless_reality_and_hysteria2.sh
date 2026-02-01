#!/bin/bash
set -e

# ==================== 配置区 ====================
VLESS_PORT=""
HY2_PORT=""
HY2_PASSWORD=""
MASQUERADE_SITE="www.bing.com"
REALITY_DEST="www.microsoft.com:443"  # Reality 伪装目标
REALITY_SERVER_NAMES="www.microsoft.com,microsoft.com"  # SNI 列表
# ================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# 检测是否需要 sudo 运行 docker
detect_docker_cmd() {
    if [ "$EUID" -eq 0 ]; then
        # 已经是 root 用户
        DOCKER="docker"
        return
    fi
    
    # 检查 sudo 权限
    sudo -v >/dev/null 2>&1 || true
    
    if command -v docker &>/dev/null; then
        # Docker 已安装，测试是否需要 sudo
        if docker info &>/dev/null 2>&1; then
            DOCKER="docker"
        elif sudo docker info &>/dev/null 2>&1; then
            DOCKER="sudo docker"
        else
            # 默认使用 sudo docker
            DOCKER="sudo docker"
        fi
    else
        # Docker 未安装，假设安装后需要 sudo（因为当前用户不在组里）
        DOCKER="sudo docker"
    fi
}

detect_docker_cmd

# 获取公网 IP
get_ip() {
    curl -s4 ip.sb || curl -s4 ifconfig.me || curl -s4 icanhazip.com
}

SERVER_IP=$(get_ip)

# ==================== 端口输入 ====================
input_port() {
    local prompt="$1"
    local default="$2"
    local port
    
    while true; do
        read -p "${prompt} [默认: ${default}]: " port
        port=${port:-$default}
        
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            echo "$port"
            return
        else
            echo -e "${RED}端口无效，请输入 1-65535 之间的数字${NC}"
        fi
    done
}

# ==================== 安装 Docker ====================
install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker 已安装"
        # 重新检测 docker 命令（确保权限正确）
        detect_docker_cmd
        return
    fi
    
    log "安装 Docker..."
    curl -fsSL get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo usermod -aG docker $USER
    
    # Docker 刚安装完，用户组权限需要重新登录才生效
    # 因此这里强制使用 sudo docker
    DOCKER="sudo docker"
    
    log "Docker 安装完成"
    info "注意: 用户组权限需重新登录后生效，本次运行将使用 sudo"
}

# ==================== 安装依赖包 ====================
install_packages() {
    local packages=("qrencode" "openssl" "curl")
    local missing=()
    
    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            missing+=("$pkg")
        fi
    done
    
    if [ ${#missing[@]} -eq 0 ]; then
        return
    fi
    
    log "安装依赖包: ${missing[*]}..."
    
    # 检测包管理器
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        sudo apt-get update -qq
        sudo apt-get install -y -qq "${missing[@]}"
    elif command -v dnf &>/dev/null; then
        # Fedora/RHEL 8+
        sudo dnf install -y -q "${missing[@]}"
    elif command -v yum &>/dev/null; then
        # CentOS/RHEL 7
        sudo yum install -y -q "${missing[@]}"
    elif command -v pacman &>/dev/null; then
        # Arch Linux
        sudo pacman -S --noconfirm "${missing[@]}"
    elif command -v apk &>/dev/null; then
        # Alpine
        sudo apk add --no-cache "${missing[@]}"
    else
        warn "未知的包管理器，请手动安装: ${missing[*]}"
    fi
}

# 兼容旧函数名
install_qrencode() {
    install_packages
}

# ==================== 系统内核优化 ====================
optimize_kernel() {
    log "优化系统内核参数..."
    
    # 检查是否已经优化过
    if grep -q "# Xray Optimization" /etc/sysctl.conf 2>/dev/null; then
        info "内核参数已优化，跳过"
        return
    fi
    
    # 获取内核版本
    local kernel_version=$(uname -r | cut -d'.' -f1-2)
    local kernel_major=$(echo $kernel_version | cut -d'.' -f1)
    local kernel_minor=$(echo $kernel_version | cut -d'.' -f2)
    info "检测到内核版本: $(uname -r)"
    
    # 备份原配置
    sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 追加优化参数
    sudo tee -a /etc/sysctl.conf > /dev/null << 'EOF'

# Xray Optimization - TCP/Network Performance
# ============================================

# TCP Fast Open (减少握手延迟)
net.ipv4.tcp_fastopen = 3

# TCP BBR 拥塞控制算法 (提升吞吐量)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 增大 TCP 缓冲区
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# 优化 TCP 连接
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# 增大连接队列
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# TIME_WAIT 优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 65535

# 本地端口范围
net.ipv4.ip_local_port_range = 1024 65535

EOF

    # 检查并启用 MPTCP (内核 5.6+)
    if [ "$kernel_major" -gt 5 ] || ([ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -ge 6 ]); then
        if [ -f /proc/sys/net/mptcp/enabled ]; then
            echo "" | sudo tee -a /etc/sysctl.conf > /dev/null
            echo "# MPTCP 多路径 TCP (内核 5.6+)" | sudo tee -a /etc/sysctl.conf > /dev/null
            echo "net.mptcp.enabled = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
            info "MPTCP 已启用 (内核 ${kernel_version} 支持)"
        fi
    fi

    # 应用配置
    sudo sysctl -p > /dev/null 2>&1 || true
    
    log "内核优化完成"
    
    # 检查 BBR 是否启用
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$current_cc" = "bbr" ]; then
        info "BBR 拥塞控制已启用 ✓"
    elif lsmod | grep -q bbr 2>/dev/null; then
        info "BBR 模块已加载"
    else
        warn "BBR 可能未启用，请检查内核版本 (需要 4.9+)"
    fi
    
    # 检查 TFO 状态
    local tfo_status=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)
    if [ "$tfo_status" = "3" ]; then
        info "TCP Fast Open 已启用 (客户端+服务端) ✓"
    fi
}

# ==================== 安装 VLESS Reality ====================
install_vless() {
    if $DOCKER ps -a --format '{{.Names}}' | grep -q '^xray_reality$'; then
        warn "VLESS Reality 容器已存在，跳过"
        return
    fi
    
    log "安装 VLESS Reality (端口: ${VLESS_PORT})..."
    mkdir -p ~/xray_config
    
    # 生成 UUID
    VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 生成 x25519 密钥对 (使用临时容器)
    log "生成 Reality 密钥对..."
    # 注意: ghcr.io/xtls/xray-core 镜像的 entrypoint 已经是 xray，所以只需传递子命令
    KEY_PAIR=$($DOCKER run --rm ghcr.io/xtls/xray-core:latest x25519 2>&1)
    
    # xray x25519 输出格式 (单行，空格分隔):
    # PrivateKey: xxx Password: yyy Hash32: zzz
    # 其中 Password 就是客户端需要的公钥 (PublicKey)
    
    # 使用 sed 直接提取，更可靠
    PRIVATE_KEY=$(echo "$KEY_PAIR" | sed -n 's/.*PrivateKey:[[:space:]]*\([^[:space:]]*\).*/\1/p')
    # Password 是新版的公钥字段名
    PUBLIC_KEY=$(echo "$KEY_PAIR" | sed -n 's/.*Password:[[:space:]]*\([^[:space:]]*\).*/\1/p')
    
    # 如果新格式解析失败，尝试旧格式 (Private key: / Public key:)
    if [ -z "$PRIVATE_KEY" ]; then
        PRIVATE_KEY=$(echo "$KEY_PAIR" | sed -n 's/.*Private[[:space:]]*key:[[:space:]]*\([^[:space:]]*\).*/\1/p')
    fi
    if [ -z "$PUBLIC_KEY" ]; then
        PUBLIC_KEY=$(echo "$KEY_PAIR" | sed -n 's/.*Public[[:space:]]*key:[[:space:]]*\([^[:space:]]*\).*/\1/p')
    fi
    
    # 验证密钥是否生成成功
    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
        warn "密钥对原始输出: $KEY_PAIR"
        warn "解析结果 - 私钥: [$PRIVATE_KEY] 公钥: [$PUBLIC_KEY]"
        err "密钥生成失败，请检查 Docker 是否正常运行"
    fi
    info "私钥: ${PRIVATE_KEY:0:10}..."
    info "公钥: ${PUBLIC_KEY:0:10}..."
    
    # 生成 shortId (8字节随机hex)
    SHORT_ID=$(openssl rand -hex 8)
    
    # 保存密钥信息 (使用等号分隔，方便解析)
    cat > ~/xray_config/keys.txt << EOF
UUID=${VLESS_UUID}
PrivateKey=${PRIVATE_KEY}
PublicKey=${PUBLIC_KEY}
ShortId=${SHORT_ID}
EOF
    
    # 生成 Xray 配置文件 (优化版)
    cat > ~/xray_config/config.json << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "dns": {
        "servers": [
            "1.1.1.1",
            "8.8.8.8"
        ],
        "queryStrategy": "UseIPv4",
        "disableCache": false,
        "disableFallback": true
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${VLESS_UUID}",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "${REALITY_DEST}",
                    "serverNames": [
                        $(echo "$REALITY_SERVER_NAMES" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')
                    ],
                    "privateKey": "${PRIVATE_KEY}",
                    "shortIds": [
                        "${SHORT_ID}"
                    ]
                },
                "tcpSettings": {
                    "acceptProxyProtocol": false,
                    "header": {
                        "type": "none"
                    }
                },
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpNoDelay": true,
                    "tcpKeepAliveInterval": 15,
                    "tcpKeepAliveIdle": 30,
                    "tcpMptcp": true
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct",
            "settings": {
                "domainStrategy": "UseIPv4"
            },
            "streamSettings": {
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpNoDelay": true,
                    "tcpMptcp": true
                }
            }
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        },
        {
            "protocol": "dns",
            "tag": "dns-out"
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["dns-in"],
                "outboundTag": "dns-out"
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "block"
            }
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 2,
                "connIdle": 120,
                "uplinkOnly": 1,
                "downlinkOnly": 1,
                "bufferSize": 64
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }
    }
}
EOF

    # 启动容器
    # 注意: 必须显式指定 run -c 来使用挂载的配置文件，否则会使用默认配置目录
    $DOCKER run -d \
        --name xray_reality \
        --restart=always \
        --log-opt max-size=50m \
        -p ${VLESS_PORT}:443 \
        -v ~/xray_config/config.json:/etc/xray/config.json:ro \
        ghcr.io/xtls/xray-core:latest \
        run -c /etc/xray/config.json
    
    sleep 3
    
    # 验证容器是否正常运行
    if ! $DOCKER ps | grep -q xray_reality; then
        err "Xray 容器启动失败，请检查日志: docker logs xray_reality"
    fi
    
    log "VLESS Reality 安装完成"
}

# ==================== 安装 Hysteria2 ====================
install_hysteria() {
    if $DOCKER ps -a --format '{{.Names}}' | grep -q '^hysteria2$'; then
        warn "Hysteria2 容器已存在，跳过"
        return
    fi
    
    HY2_PASSWORD=$(openssl rand -base64 16)
    
    log "安装 Hysteria2 (端口: ${HY2_PORT})..."
    mkdir -p ~/hysteria2 && cd ~/hysteria2
    
    # 生成自签证书
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout server.key -out server.crt \
        -subj "/CN=${MASQUERADE_SITE}" -days 36500 2>/dev/null
    
    # 保存密码到文件
    echo "${HY2_PASSWORD}" > ~/hysteria2/password.txt
    
    # 生成配置
    cat > config.yaml << EOF
listen: :${HY2_PORT}

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: ${HY2_PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: https://${MASQUERADE_SITE}
    rewriteHost: true
EOF

    $DOCKER run -d \
        --name hysteria2 \
        --restart=always \
        --log-opt max-size=50m \
        -p ${HY2_PORT}:${HY2_PORT}/udp \
        -v ~/hysteria2:/etc/hysteria \
        tobyxdd/hysteria:v2 server -c /etc/hysteria/config.yaml
    
    log "Hysteria2 安装完成"
}

# ==================== 保存 VLESS 信息 ====================
save_vless_info() {
    mkdir -p ~/proxy_info
    
    # 读取保存的密钥信息 (keys.txt 格式: KEY=VALUE)
    if [ ! -f ~/xray_config/keys.txt ]; then
        warn "密钥文件不存在"
        return
    fi
    
    # 使用 source 或 grep+cut 解析 KEY=VALUE 格式
    local uuid=$(grep '^UUID=' ~/xray_config/keys.txt | cut -d'=' -f2)
    local public_key=$(grep '^PublicKey=' ~/xray_config/keys.txt | cut -d'=' -f2)
    local short_id=$(grep '^ShortId=' ~/xray_config/keys.txt | cut -d'=' -f2)
    local server_name=$(echo "$REALITY_SERVER_NAMES" | cut -d',' -f1)
    
    # 如果变量为空，尝试从配置文件读取
    if [ -z "$server_name" ]; then
        server_name=$(grep -o '"serverNames":\s*\[\s*"[^"]*"' ~/xray_config/config.json | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    fi
    
    # 生成分享链接
    # 格式: vless://uuid@server:port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=xxx&fp=chrome&pbk=xxx&sid=xxx&type=tcp#name
    local vless_uri="vless://${uuid}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${server_name}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#VLESS-Reality-${SERVER_IP}"
    
    echo "${vless_uri}" > ~/proxy_info/vless_uri.txt
    
    # 保存详细信息
    cat > ~/proxy_info/vless_info.txt << EOF
================== VLESS Reality 配置 ==================
地址 (Address): ${SERVER_IP}
端口 (Port): ${VLESS_PORT}
UUID: ${uuid}
流控 (Flow): xtls-rprx-vision
加密 (Encryption): none
传输协议 (Network): tcp
伪装类型 (Type): none
安全 (Security): reality
SNI: ${server_name}
指纹 (Fingerprint): chrome
公钥 (Public Key): ${public_key}
Short ID: ${short_id}

分享链接:
${vless_uri}
=========================================================
EOF

    # 生成二维码
    qrencode -t UTF8 -o ~/proxy_info/vless_qr.txt "${vless_uri}"
    
    log "VLESS 信息已保存"
}

# ==================== 保存 Hysteria2 信息 ====================
save_hy2_info() {
    mkdir -p ~/proxy_info
    
    # 读取密码（可能是从之前保存的文件）
    if [ -z "$HY2_PASSWORD" ] && [ -f ~/hysteria2/password.txt ]; then
        HY2_PASSWORD=$(cat ~/hysteria2/password.txt)
    fi
    
    # 读取端口
    local port=$HY2_PORT
    if [ -z "$port" ] && [ -f ~/hysteria2/config.yaml ]; then
        port=$(grep -E "^listen:" ~/hysteria2/config.yaml | sed 's/listen: ://')
    fi
    
    if [ -n "$HY2_PASSWORD" ] && [ -n "$port" ]; then
        local hy2_uri="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${port}?insecure=1&sni=${MASQUERADE_SITE}#Hy2-${SERVER_IP}"
        
        echo "${hy2_uri}" > ~/proxy_info/hy2_uri.txt
        qrencode -t UTF8 -o ~/proxy_info/hy2_qr.txt "${hy2_uri}"
        
        # 保存详细信息
        cat > ~/proxy_info/hy2_info.txt << EOF
地址: ${SERVER_IP}
端口: ${port}
密码: ${HY2_PASSWORD}
SNI: ${MASQUERADE_SITE}

分享链接:
${hy2_uri}
EOF
        log "Hysteria2 信息已保存"
    fi
}

# ==================== 输出连接信息 ====================
print_info() {
    local show_vless=$1
    local show_hy2=$2
    
    echo ""
    echo "============================================================"
    echo -e "${GREEN}              安装完成！连接信息如下${NC}"
    echo "============================================================"
    echo ""
    
    # VLESS Reality 信息
    if [ "$show_vless" = "true" ]; then
        echo -e "${YELLOW}【VLESS Reality】${NC}"
        if [ -f ~/proxy_info/vless_info.txt ]; then
            cat ~/proxy_info/vless_info.txt
            echo ""
            echo "二维码:"
            [ -f ~/proxy_info/vless_qr.txt ] && cat ~/proxy_info/vless_qr.txt
        else
            warn "VLESS 配置信息暂未生成"
        fi
        echo ""
    fi
    
    # Hysteria2 信息
    if [ "$show_hy2" = "true" ]; then
        echo -e "${YELLOW}【Hysteria2】${NC}"
        if [ -f ~/proxy_info/hy2_info.txt ]; then
            cat ~/proxy_info/hy2_info.txt
        fi
        echo ""
        echo "二维码:"
        if [ -f ~/proxy_info/hy2_qr.txt ]; then
            cat ~/proxy_info/hy2_qr.txt
        else
            local hy2_uri=$(cat ~/proxy_info/hy2_uri.txt 2>/dev/null)
            [ -n "$hy2_uri" ] && qrencode -t ANSIUTF8 "${hy2_uri}"
        fi
        echo ""
    fi
    
    echo "============================================================"
    echo "连接信息已保存到 ~/proxy_info/"
    ls -1 ~/proxy_info/ 2>/dev/null | sed 's/^/  - /'
    echo "============================================================"
}

# ==================== 查看状态 ====================
show_status() {
    echo ""
    echo "============================================================"
    echo -e "${CYAN}              服务运行状态${NC}"
    echo "============================================================"
    echo ""
    
    echo -e "${YELLOW}【Docker 容器状态】${NC}"
    $DOCKER ps -a --filter "name=xray_reality" --filter "name=hysteria2" \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || warn "无法获取容器状态"
    echo ""
    
    echo -e "${YELLOW}【VLESS Reality】${NC}"
    if $DOCKER ps --format '{{.Names}}' | grep -q '^xray_reality$'; then
        echo -e "状态: ${GREEN}运行中${NC}"
        $DOCKER logs --tail 5 xray_reality 2>&1 | head -5
    else
        echo -e "状态: ${RED}未运行${NC}"
    fi
    echo ""
    
    echo -e "${YELLOW}【Hysteria2】${NC}"
    if $DOCKER ps --format '{{.Names}}' | grep -q '^hysteria2$'; then
        echo -e "状态: ${GREEN}运行中${NC}"
        $DOCKER logs --tail 5 hysteria2 2>&1 | head -5
    else
        echo -e "状态: ${RED}未运行${NC}"
    fi
    echo ""
}

# ==================== 查看配置信息 ====================
show_info() {
    [ -z "$SERVER_IP" ] && SERVER_IP=$(get_ip)
    
    echo ""
    echo "============================================================"
    echo -e "${CYAN}              连接配置信息${NC}"
    echo "============================================================"
    echo ""
    
    # VLESS Reality 信息
    echo -e "${YELLOW}【VLESS Reality】${NC}"
    if [ -f ~/proxy_info/vless_info.txt ]; then
        cat ~/proxy_info/vless_info.txt
        echo ""
        echo "二维码:"
        [ -f ~/proxy_info/vless_qr.txt ] && cat ~/proxy_info/vless_qr.txt
    elif [ -f ~/xray_config/keys.txt ]; then
        # 重新生成信息 (keys.txt 格式: KEY=VALUE)
        local uuid=$(grep '^UUID=' ~/xray_config/keys.txt | cut -d'=' -f2)
        local public_key=$(grep '^PublicKey=' ~/xray_config/keys.txt | cut -d'=' -f2)
        local short_id=$(grep '^ShortId=' ~/xray_config/keys.txt | cut -d'=' -f2)
        local port=$(grep -o '"port":[[:space:]]*[0-9]*' ~/xray_config/config.json | head -1 | grep -o '[0-9]*')
        echo "地址: ${SERVER_IP}"
        echo "端口: ${port}"
        echo "UUID: ${uuid}"
        echo "公钥: ${public_key}"
        echo "Short ID: ${short_id}"
    else
        warn "VLESS Reality 未安装"
    fi
    echo ""
    
    # Hysteria2 信息
    echo -e "${YELLOW}【Hysteria2】${NC}"
    if [ -f ~/proxy_info/hy2_info.txt ]; then
        cat ~/proxy_info/hy2_info.txt
        echo ""
        echo "二维码:"
        [ -f ~/proxy_info/hy2_qr.txt ] && cat ~/proxy_info/hy2_qr.txt
    elif [ -f ~/hysteria2/config.yaml ]; then
        local password=$(cat ~/hysteria2/password.txt 2>/dev/null)
        local port=$(grep -E "^listen:" ~/hysteria2/config.yaml | sed 's/listen: ://')
        echo "地址: ${SERVER_IP}"
        echo "端口: ${port}"
        echo "密码: ${password}"
    else
        warn "Hysteria2 未安装"
    fi
    echo ""
}

# ==================== 查看日志 ====================
show_logs() {
    local service=$1
    local lines=${2:-50}
    
    case "$service" in
        vless)
            echo -e "${YELLOW}【VLESS Reality 日志】${NC}"
            $DOCKER logs --tail $lines xray_reality 2>&1
            ;;
        hy2|hysteria)
            echo -e "${YELLOW}【Hysteria2 日志】${NC}"
            $DOCKER logs --tail $lines hysteria2 2>&1
            ;;
        *)
            echo -e "${YELLOW}【VLESS Reality 日志】${NC}"
            $DOCKER logs --tail $lines xray_reality 2>&1
            echo ""
            echo -e "${YELLOW}【Hysteria2 日志】${NC}"
            $DOCKER logs --tail $lines hysteria2 2>&1
            ;;
    esac
}

# ==================== 重启服务 ====================
restart_service() {
    local service=$1
    
    case "$service" in
        vless)
            log "重启 VLESS Reality..."
            $DOCKER restart xray_reality
            ;;
        hy2|hysteria)
            log "重启 Hysteria2..."
            $DOCKER restart hysteria2
            ;;
        *)
            log "重启所有服务..."
            $DOCKER restart xray_reality hysteria2 2>/dev/null || true
            ;;
    esac
    log "重启完成"
}

# ==================== 卸载服务 ====================
uninstall() {
    local service=$1
    
    echo ""
    
    case "$service" in
        vless)
            echo -e "${RED}警告: 此操作将删除 VLESS Reality 服务和配置！${NC}"
            read -p "确认卸载 VLESS Reality? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                log "停止并删除 VLESS Reality 容器..."
                $DOCKER stop xray_reality 2>/dev/null || true
                $DOCKER rm xray_reality 2>/dev/null || true
                log "删除 VLESS 配置文件..."
                rm -rf ~/xray_config
                rm -f ~/proxy_info/vless_*.txt
                log "VLESS Reality 卸载完成"
            else
                info "已取消"
            fi
            ;;
        hy2|hysteria)
            echo -e "${RED}警告: 此操作将删除 Hysteria2 服务和配置！${NC}"
            read -p "确认卸载 Hysteria2? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                log "停止并删除 Hysteria2 容器..."
                $DOCKER stop hysteria2 2>/dev/null || true
                $DOCKER rm hysteria2 2>/dev/null || true
                log "删除 Hysteria2 配置文件..."
                rm -rf ~/hysteria2
                rm -f ~/proxy_info/hy2_*.txt
                log "Hysteria2 卸载完成"
            else
                info "已取消"
            fi
            ;;
        *)
            echo -e "${RED}警告: 此操作将删除所有代理服务和配置！${NC}"
            echo ""
            echo "  1) 仅卸载 VLESS Reality"
            echo "  2) 仅卸载 Hysteria2"
            echo "  3) 卸载全部"
            echo "  0) 取消"
            echo ""
            read -p "请选择 [0-3]: " choice
            
            case "$choice" in
                1)
                    uninstall "vless"
                    ;;
                2)
                    uninstall "hy2"
                    ;;
                3)
                    read -p "确认卸载全部服务? (y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        log "停止并删除所有容器..."
                        $DOCKER stop xray_reality hysteria2 2>/dev/null || true
                        $DOCKER rm xray_reality hysteria2 2>/dev/null || true
                        log "删除所有配置文件..."
                        rm -rf ~/xray_config ~/hysteria2 ~/proxy_info
                        log "全部卸载完成"
                    else
                        info "已取消"
                    fi
                    ;;
                *)
                    info "已取消"
                    ;;
            esac
            ;;
    esac
}

# ==================== 显示菜单 ====================
show_menu() {
    echo ""
    echo "============================================================"
    echo "     VLESS Reality + Hysteria2 一键管理脚本"
    echo "============================================================"
    echo ""
    echo "  1) 安装 VLESS Reality"
    echo "  2) 安装 Hysteria2"
    echo "  3) 安装全部 (VLESS + Hysteria2)"
    echo ""
    echo "  4) 查看服务状态"
    echo "  5) 查看连接信息"
    echo "  6) 查看日志"
    echo "  7) 重启服务"
    echo "  8) 卸载"
    echo ""
    echo "  9) 优化系统内核 (BBR/TCP)"
    echo ""
    echo "  0) 退出"
    echo ""
    echo "============================================================"
}

# ==================== 安装流程 ====================
do_install() {
    local install_vless_flag=$1
    local install_hy2_flag=$2
    
    [ -z "$SERVER_IP" ] && err "无法获取公网 IP"
    log "服务器 IP: $SERVER_IP"
    
    install_docker
    install_qrencode
    optimize_kernel
    
    if [ "$install_vless_flag" = "true" ]; then
        VLESS_PORT=$(input_port "请输入 VLESS Reality 端口" "443")
        install_vless
        save_vless_info
    fi
    
    if [ "$install_hy2_flag" = "true" ]; then
        HY2_PORT=$(input_port "请输入 Hysteria2 端口" "8443")
        install_hysteria
        save_hy2_info
    fi
    
    print_info "$install_vless_flag" "$install_hy2_flag"
}

# ==================== 主流程 ====================
main() {
    # 命令行参数处理
    case "$1" in
        status)
            show_status
            exit 0
            ;;
        info)
            show_info
            exit 0
            ;;
        logs)
            show_logs "$2" "$3"
            exit 0
            ;;
        restart)
            restart_service "$2"
            exit 0
            ;;
        uninstall)
            uninstall "$2"
            exit 0
            ;;
        help|--help|-h)
            echo "用法: $0 [命令]"
            echo ""
            echo "命令:"
            echo "  (无参数)     交互式菜单"
            echo "  status       查看服务运行状态"
            echo "  info         查看连接配置信息"
            echo "  logs [服务] [行数]  查看日志 (vless/hy2/all)"
            echo "  restart [服务]      重启服务 (vless/hy2/all)"
            echo "  uninstall [服务]    卸载服务 (vless/hy2/all)"
            echo "  help         显示此帮助"
            exit 0
            ;;
    esac
    
    # 交互式菜单
    while true; do
        show_menu
        read -p "请选择 [0-9]: " choice
        
        case "$choice" in
            1)
                do_install "true" "false"
                ;;
            2)
                do_install "false" "true"
                ;;
            3)
                do_install "true" "true"
                ;;
            4)
                show_status
                ;;
            5)
                show_info
                ;;
            6)
                read -p "查看哪个服务日志? (vless/hy2/all) [all]: " log_svc
                read -p "显示多少行? [50]: " log_lines
                show_logs "${log_svc:-all}" "${log_lines:-50}"
                ;;
            7)
                read -p "重启哪个服务? (vless/hy2/all) [all]: " restart_svc
                restart_service "${restart_svc:-all}"
                ;;
            8)
                uninstall
                ;;
            9)
                optimize_kernel
                ;;
            0)
                echo "Bye!"
                exit 0
                ;;
            *)
                warn "无效选择"
                ;;
        esac
        
        echo ""
        read -p "按 Enter 继续..."
    done
}

main "$@"
