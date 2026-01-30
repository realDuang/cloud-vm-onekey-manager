#!/bin/bash
set -e

# ==================== 配置区 ====================
PORT=11443                                    # 端口
HY2_PASSWORD=$(openssl rand -base64 16)       # 自动生成密码
MASQUERADE_SITE="www.bing.com"                # 伪装站点
# ================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# 获取公网 IP
get_ip() {
    curl -s4 ip.sb || curl -s4 ifconfig.me || curl -s4 icanhazip.com
}

SERVER_IP=$(get_ip)
[ -z "$SERVER_IP" ] && err "无法获取公网 IP"

log "服务器 IP: $SERVER_IP"
log "端口: $PORT"

# ==================== 安装 Docker ====================
install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker 已安装"
        return
    fi
    
    log "安装 Docker..."
    curl -fsSL get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo usermod -aG docker $USER
    log "Docker 安装完成"
}

# ==================== 安装 VLESS Reality ====================
install_vless() {
    if docker ps -a --format '{{.Names}}' | grep -q '^xray_reality$'; then
        warn "VLESS Reality 容器已存在，跳过"
        return
    fi
    
    log "安装 VLESS Reality..."
    mkdir -p ~/xray_config
    
    docker run -d \
        --name xray_reality \
        --restart=always \
        --log-opt max-size=50m \
        -p ${PORT}:443 \
        -e EXTERNAL_PORT=${PORT} \
        -v ~/xray_config:/data \
        wulabing/xray_docker_reality:latest
    
    sleep 3
    log "VLESS Reality 安装完成"
}

# ==================== 安装 Hysteria2 ====================
install_hysteria() {
    if docker ps -a --format '{{.Names}}' | grep -q '^hysteria2$'; then
        warn "Hysteria2 容器已存在，跳过"
        return
    fi
    
    log "安装 Hysteria2..."
    mkdir -p ~/hysteria2 && cd ~/hysteria2
    
    # 生成自签证书
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout server.key -out server.crt \
        -subj "/CN=${MASQUERADE_SITE}" -days 36500 2>/dev/null
    
    # 生成配置
    cat > config.yaml << EOF
listen: :${PORT}

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

    docker run -d \
        --name hysteria2 \
        --restart=always \
        --log-opt max-size=50m \
        -p ${PORT}:${PORT}/udp \
        -v ~/hysteria2:/etc/hysteria \
        tobyxdd/hysteria:v2 server -c /etc/hysteria/config.yaml
    
    log "Hysteria2 安装完成"
}

# ==================== 安装 qrencode ====================
install_qrencode() {
    if ! command -v qrencode &>/dev/null; then
        log "安装 qrencode..."
        sudo apt-get update -qq && sudo apt-get install -y -qq qrencode
    fi
}

# ==================== 输出连接信息 ====================
print_info() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}              安装完成！连接信息如下${NC}"
    echo "============================================================"
    echo ""
    
    # VLESS Reality 信息
    echo -e "${YELLOW}【VLESS Reality】${NC}"
    if [ -f ~/xray_config/config_info.txt ]; then
        cat ~/xray_config/config_info.txt 2>/dev/null || docker exec xray_reality cat /config_info.txt 2>/dev/null
    else
        docker exec xray_reality cat /config_info.txt 2>/dev/null || warn "VLESS 配置信息暂未生成"
    fi
    echo ""
    
    # Hysteria2 信息
    HY2_URI="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=${MASQUERADE_SITE}#Hy2-${SERVER_IP}"
    
    echo -e "${YELLOW}【Hysteria2】${NC}"
    echo "地址: ${SERVER_IP}"
    echo "端口: ${PORT}"
    echo "密码: ${HY2_PASSWORD}"
    echo "SNI: ${MASQUERADE_SITE}"
    echo ""
    echo "分享链接:"
    echo "${HY2_URI}"
    echo ""
    echo "二维码:"
    qrencode -t ANSIUTF8 "${HY2_URI}"
    
    # 保存信息到文件
    mkdir -p ~/proxy_info
    echo "${HY2_URI}" > ~/proxy_info/hy2_uri.txt
    qrencode -t UTF8 -o ~/proxy_info/hy2_qr.txt "${HY2_URI}"
    qrencode -o ~/proxy_info/hy2_qr.png -s 10 "${HY2_URI}"
    
    echo ""
    echo "============================================================"
    echo "连接信息已保存到 ~/proxy_info/"
    echo "  - hy2_uri.txt   (分享链接)"
    echo "  - hy2_qr.txt    (文本二维码)"
    echo "  - hy2_qr.png    (图片二维码)"
    echo "============================================================"
}

# ==================== 主流程 ====================
main() {
    echo ""
    echo "============================================================"
    echo "     VLESS Reality + Hysteria2 一键安装脚本"
    echo "============================================================"
    echo ""
    
    install_docker
    install_qrencode
    install_vless
    install_hysteria
    print_info
}

main
SCRIPT
