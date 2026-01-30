#!/bin/bash
set -e

# ==================== 配置区 ====================
VLESS_PORT=""
HY2_PORT=""
HY2_PASSWORD=""
MASQUERADE_SITE="www.bing.com"
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
DOCKER="docker"
if ! docker info &>/dev/null; then
    if sudo docker info &>/dev/null; then
        DOCKER="sudo docker"
    fi
fi

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
        return
    fi
    
    log "安装 Docker..."
    curl -fsSL get.docker.com -o /tmp/get-docker.sh
    sudo sh /tmp/get-docker.sh
    sudo usermod -aG docker $USER
    log "Docker 安装完成"
}

# ==================== 安装 qrencode ====================
install_qrencode() {
    if ! command -v qrencode &>/dev/null; then
        log "安装 qrencode..."
        sudo apt-get update -qq && sudo apt-get install -y -qq qrencode
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
    
    $DOCKER run -d \
        --name xray_reality \
        --restart=always \
        --log-opt max-size=50m \
        -p ${VLESS_PORT}:443 \
        -e EXTERNAL_PORT=${VLESS_PORT} \
        -v ~/xray_config:/data \
        wulabing/xray_docker_reality:latest
    
    sleep 3
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
    
    # 等待容器生成配置信息
    local max_wait=30
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        if $DOCKER exec xray_reality cat /config_info.txt &>/dev/null; then
            # 保存完整配置信息
            $DOCKER exec xray_reality cat /config_info.txt > ~/proxy_info/vless_info.txt
            
            # 提取分享链接
            $DOCKER exec xray_reality cat /config_info.txt | grep -E "^vless://" > ~/proxy_info/vless_uri.txt 2>/dev/null || true
            
            # 生成二维码
            local vless_uri=$(cat ~/proxy_info/vless_uri.txt 2>/dev/null)
            if [ -n "$vless_uri" ]; then
                qrencode -t UTF8 -o ~/proxy_info/vless_qr.txt "$vless_uri"
            fi
            
            log "VLESS 信息已保存"
            return
        fi
        sleep 1
        ((waited++))
    done
    
    warn "VLESS 配置信息暂未生成，稍后可使用 '$0 info' 查看"
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
        elif [ -f ~/xray_config/config_info.txt ]; then
            cat ~/xray_config/config_info.txt
        else
            $DOCKER exec xray_reality cat /config_info.txt 2>/dev/null || warn "VLESS 配置信息暂未生成"
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
    elif $DOCKER ps --format '{{.Names}}' | grep -q '^xray_reality$'; then
        $DOCKER exec xray_reality cat /config_info.txt 2>/dev/null || warn "配置信息不可用"
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
    echo ""
    echo -e "${RED}警告: 此操作将删除所有代理服务和配置！${NC}"
    read -p "确认卸载? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log "停止并删除容器..."
        $DOCKER stop xray_reality hysteria2 2>/dev/null || true
        $DOCKER rm xray_reality hysteria2 2>/dev/null || true
        
        log "删除配置文件..."
        rm -rf ~/xray_config ~/hysteria2 ~/proxy_info
        
        log "卸载完成"
    else
        info "已取消"
    fi
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
            uninstall
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
            echo "  uninstall    卸载所有服务"
            echo "  help         显示此帮助"
            exit 0
            ;;
    esac
    
    # 交互式菜单
    while true; do
        show_menu
        read -p "请选择 [0-8]: " choice
        
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
