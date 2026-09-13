#!/bin/bash

# ==================== 配置区域（修改这里） ====================
# GFWList 数据源（二选一，留空一个）
GFW_LIST_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/master/list.txt"
# LOCAL_GFW_FILE="gfwlist.txt"  # 使用本地文件时取消注释

# AdGuard Home 上游 DNS（空格分隔）
# 未匹配规则时使用的默认上游 DNS
DEFAULT_UPSTREAM_DNS="223.5.5.5 2400:3200::1 223.6.6.6 2400:3200:baba::1 119.29.29.29 2402:4e00:: 2402:4e00:1:: 119.28.28.28"

# 匹配 GFWList 规则时使用的 DNS
MATCHED_RULE_DNS="tcp://127.0.0.2:5533 tls://1.1.1.1 tls://1dot1dot1dot1.cloudflare-dns.com"

# 输出文件
# domain-list-community 使用的纯域名列表
DOMAIN_LIST_OUTPUT="data/all"

# AdGuard Home upstream_dns_file 使用的配置文件
AGH_UPSTREAM_OUTPUT="upstream.conf"

# 其他配置
AUTHOR="yandujun363"
DISTRIBUTION="https://github.com/yangdujun/gfwlist-adh-dns"
DEBUG=false

# ===========================================================

# ==================== 颜色输出 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ==================== 域名验证 ====================
is_valid_domain() {
    local domain="$1"
    # 排除 IP 地址
    if [[ "$domain" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    # 域名格式：字母数字和连字符，至少包含一个点
    if [[ "$domain" =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$ ]]; then
        return 0
    fi
    return 1
}

# ==================== 提取域名 ====================
extract_domain() {
    local line="$1"
    local domain="$line"

    # 去除开头空格
    domain="$(echo "$domain" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$domain" ]] && return 1

    # 处理白名单标记 @@||
    domain="${domain#@@||}"
    # 处理前缀 || 或 .
    domain="${domain#||}"
    domain="${domain#.}"

    # 验证域名
    if is_valid_domain "$domain"; then
        echo "$domain"
        return 0
    fi
    return 1
}

# ==================== 数据获取 ====================
fetch_data() {
    local data=""

    if [[ -n "$LOCAL_GFW_FILE" ]]; then
        log_info "从本地文件读取: $LOCAL_GFW_FILE"
        if [[ -f "$LOCAL_GFW_FILE" ]]; then
            data=$(cat "$LOCAL_GFW_FILE")
        else
            log_error "本地文件不存在: $LOCAL_GFW_FILE"
            exit 1
        fi
    elif [[ -n "$GFW_LIST_URL" ]]; then
        log_info "从远程获取: $GFW_LIST_URL"
        data=$(curl -s -L --connect-timeout 30 --max-time 60 "$GFW_LIST_URL" 2>/dev/null)
        if [[ $? -ne 0 ]] || [[ -z "$data" ]]; then
            log_error "下载失败: $GFW_LIST_URL"
            exit 1
        fi
    else
        log_error "未配置数据源（请设置 GFW_LIST_URL 或 LOCAL_GFW_FILE）"
        exit 1
    fi

    echo "$data"
}

# ==================== 处理域名 ====================
process_domains() {
    local data="$1"
    local default_upstream_dns="$DEFAULT_UPSTREAM_DNS"
    local matched_rule_dns="$MATCHED_RULE_DNS"

    # 使用 awk 批量处理
    local result=$(echo "$data" | awk -v up="$default_upstream_dns" -v wl="$matched_rule_dns" '
    BEGIN {
        # 初始化关联数组用于去重
        split("", seen_domains)
        split("", seen_dns)
        domain_count = 0
        dns_count = 0
    }
    {
        # 跳过空行和注释
        if ($0 ~ /^[[:space:]]*(#|!)/ || $0 ~ /^[[:space:]]*$/) next

        line = $0
        # 去除前后空格
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        # 提取域名
        domain = line
        is_whitelist = 0

        # 处理白名单标记
        if (index(line, "@@||") == 1) {
            is_whitelist = 1
            domain = substr(line, 5)  # 去掉 @@||
        }

        # 去掉 || 或 . 前缀
        if (substr(domain, 1, 2) == "||") {
            domain = substr(domain, 3)
        } else if (substr(domain, 1, 1) == ".") {
            domain = substr(domain, 2)
        }

        # 验证域名（简单检查，避免正则性能开销）
        if (domain !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ &&
            domain ~ /^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/) {

            # 域名去重
            if (!(domain in seen_domains)) {
                seen_domains[domain] = 1
                domain_list[domain_count++] = "domain:" domain
            }

            # DNS 条目去重
            # 白名单域名（@@||）走默认上游，普通规则域名走匹配规则 DNS
            dns_entry = "[/" domain "/]"
            dns_entry = (is_whitelist ? dns_entry up : dns_entry wl)

            if (!(dns_entry in seen_dns)) {
                seen_dns[dns_entry] = 1
                dns_list[dns_count++] = dns_entry
            }
        }
    }
    END {
        # 输出域名列表（换行分隔）
        for (i = 0; i < domain_count; i++) {
            print domain_list[i]
        }
        # 使用特殊分隔符输出 DNS 列表
        print "---DNS_SEPARATOR---"
        for (i = 0; i < dns_count; i++) {
            print dns_list[i]
        }
    }')

    # 分离结果
    local domains_part=$(echo "$result" | sed -n '/---DNS_SEPARATOR---/q;p')
    local dns_part=$(echo "$result" | sed -n '/---DNS_SEPARATOR---/,$p' | tail -n +2)

    # 转换为数组
    IFS=$'\n' read -r -d '' -a DOMAINS < <(echo "$domains_part" && printf '\0')
    IFS=$'\n' read -r -d '' -a DNS_ENTRIES < <(echo "$dns_part" && printf '\0')

    log_info "处理完成: ${#DOMAINS[@]} 个域名, ${#DNS_ENTRIES[@]} 个 DNS 条目"
}

# ==================== 保存域名列表 ====================
save_domains() {
    local output_dir=$(dirname "$DOMAIN_LIST_OUTPUT")
    [[ -n "$output_dir" ]] && mkdir -p "$output_dir"

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local count=${#DOMAINS[@]}

    local sorted_domains=""
    if [[ ${#DOMAINS[@]} -gt 0 ]]; then
        sorted_domains=$(
            printf '%s\n' "${DOMAINS[@]}" \
            | sed 's/^domain://' \
            | LC_ALL=C sort \
            | sed 's/^/domain:/'
        )
    fi

    if [[ -n "$sorted_domains" ]]; then
        printf '%s\n' "$sorted_domains" > "$DOMAIN_LIST_OUTPUT"
    else
        : > "$DOMAIN_LIST_OUTPUT"
    fi

    log_info "domain-list-community 域名列表保存: $DOMAIN_LIST_OUTPUT ($count 个)"
}

# ==================== 保存 AdGuard Home 上游配置 ====================
save_agh_upstream() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local count=${#DNS_ENTRIES[@]}

    local sorted_entries=""
    if [[ ${#DNS_ENTRIES[@]} -gt 0 ]]; then
        sorted_entries=$(
            printf '%s\n' "${DNS_ENTRIES[@]}" \
            | awk '{
                line = $0
                if (match(line, /^\[\/[^\/]+\/\]/)) {
                    prefix = substr(line, 1, RLENGTH)
                    domain = prefix
                    sub(/^\[\//, "", domain)
                    sub(/\/\]$/, "", domain)
                    rest = substr(line, RLENGTH + 1)
                    print domain "\t" prefix rest
                } else {
                    print $0 "\t" $0
                }
            }' \
            | LC_ALL=C sort -k1,1 \
            | cut -f2-
        )
    fi

    {
        echo "# Generated at: $timestamp"
        echo "# Author: $AUTHOR"
        echo "# Distribution: $DISTRIBUTION"
        echo "# Type: AdGuard Home upstream_dns_file"
        echo "# Total Domains: $count"
        echo "# ------------------------------------------"
        echo ""
        # 默认上游（未匹配规则时使用）
        for dns in $DEFAULT_UPSTREAM_DNS; do
            echo "$dns"
        done
        echo ""
        # 匹配规则时的域名级上游
        if [[ -n "$sorted_entries" ]]; then
            printf '%s\n' "$sorted_entries"
        fi
    } > "$AGH_UPSTREAM_OUTPUT"

    log_info "AdGuard Home 上游配置保存: $AGH_UPSTREAM_OUTPUT ($count 个条目)"
}

# ==================== 主程序 ====================
main() {
    echo "DNS 配置生成器 (Bash 版)"
    echo "================================"
    echo ""

    # 显示配置
    log_info "当前配置:"
    echo "  数据源: ${GFW_LIST_URL:-$LOCAL_GFW_FILE}"
    echo "  默认上游 DNS (未匹配规则): $DEFAULT_UPSTREAM_DNS"
    echo "  匹配规则 DNS: $MATCHED_RULE_DNS"
    echo ""

    # 获取数据
    local data=$(fetch_data)
    if [[ -z "$data" ]]; then
        log_error "数据为空，请检查网络或文件"
        exit 1
    fi

    log_info "数据行数: $(echo "$data" | wc -l)"
    echo ""

    # 处理域名
    process_domains "$data"
    echo ""

    # 保存结果
    save_domains
    save_agh_upstream

    echo ""
    log_info "完成！"
    echo "   - domain-list-community 域名列表: $DOMAIN_LIST_OUTPUT (${#DOMAINS[@]} 个)"
    echo "   - AdGuard Home 上游配置: $AGH_UPSTREAM_OUTPUT (${#DNS_ENTRIES[@]} 个)"

    if [[ "$DEBUG" == "true" ]] && [[ ${#DOMAINS[@]} -gt 0 ]]; then
        echo ""
        echo "域名示例 (前 10 个):"
        printf '%s\n' "${DOMAINS[@]:0:10}" | sed 's/^/   /'
        echo ""
        echo "DNS 示例 (前 5 个):"
        printf '%s\n' "${DNS_ENTRIES[@]:0:5}" | sed 's/^/   /'
    fi

    # if systemctl is-active --quiet AdGuardHome.service; then
    #     log_info "重启 AdGuardHome.service ..."
    #     if systemctl restart AdGuardHome.service; then
    #         log_info "服务重启成功"
    #     else
    #         log_error "服务重启失败，请检查: journalctl -u AdGuardHome.service -n 50"
    #     fi
    # else
    #     log_warn "AdGuardHome.service 未运行，跳过重启"
    # fi
}

# ==================== 错误处理 ====================
trap 'log_error "脚本被中断"; exit 1' INT TERM

# ==================== 依赖检查 ====================
for cmd in curl grep sed awk; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "缺少依赖: $cmd"
        echo "   安装: apt-get install $cmd 或 yum install $cmd"
        exit 1
    fi
done

# ==================== 启动 ====================
main "$@"