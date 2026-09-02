import requests
import os
import re
import ipaddress

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID   = os.getenv("CF_PROFILE_ID", "")
MODE         = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

# Cloudflare Zero Trust Split Tunnels 官方单策略限制通常为 1000~2000 条
MAX_RULES       = int(os.getenv("MAX_RULES", "1000"))
TARGET_DOMAIN_N = 0  # 期望域名条数，剩余配额给 IP

# 合法域名正则：只保留标准域名格式，过滤脏数据
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# ============================================================
# 1. 本地私有网络 (必须使用 address 字段)
# ============================================================
LOCAL_EXCLUDE_IPS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# ============================================================
# 2. AI 服务域名 (必须使用 host 字段)
# ============================================================
AI_EXCLUDE_DOMAINS = [
    # Google AI / Gemini
    "gemini.google.com",
    "aistudio.google.com",
    "gstatic.com",
    "ai.google.dev",
    "googleapis.com",
    "clients6.google.com",
    "accounts.google.com",
    "googleusercontent.com",
    "ogs.google.com",
    "apis.google.com",
    
    # OpenAI / ChatGPT
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    
    # Anthropic / Claude
    "claude.ai",
    "anthropic.com",
    
    # Adobe
    "firefly.adobe.com",
]

# 域名：Loyalsoldier 精选直连域名
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"

# IP：GeoIP2-CN (聚合版)
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

def get_cn_cidrs():
    """从 GeoIP2-CN 拉取 CN CIDR 列表并进行智能聚合"""
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    raw_cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    
    # 转换为 ip_network 对象进行自动聚合
    nets = [ipaddress.ip_network(c) for c in raw_cidrs if '/' in c]
    collapsed = list(ipaddress.collapse_addresses(nets))
    
    # 如果依然超出 MAX_RULES，优先保留掩码较小的大骨干网段（前缀 <= 18）
    if len(collapsed) > (MAX_RULES - 50):
        collapsed = [net for net in collapsed if net.prefixlen <= 18]
        
    cidrs = [str(net) for net in collapsed]
    print(f"   IP 数据源获取并聚合为 {len(cidrs)} 条 CIDR")
    return cidrs

def get_cn_domains():
    """从 Loyalsoldier/surge-rules 拉取精选 CN 直连域名列表"""
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        line = line.lstrip('.')
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f"*.{line}")
    unique = list(set(domains))
    print(f"   域名数据源获取到 {len(unique)} 条域名（已过滤非法格式）")
    return unique

def update_split_tunnels(cidrs, domains):
    # 1. 本地 IP 规则 (使用 address)
    local_entries = [
        {"address": ip, "description": "Local LAN"}
        for ip in LOCAL_EXCLUDE_IPS
    ]

    # 2. AI 域名规则 (使用 host)
    ai_entries = [
        {"host": domain, "description": "AI Service"}
        for domain in AI_EXCLUDE_DOMAINS
    ]

    reserved_count = len(local_entries) + len(ai_entries)

    # 3. 动态分配配额
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips = min(MAX_RULES - reserved_count - max_domains, len(cidrs))

    domain_entries = [
        {"host": d, "description": "CN Domain"}
        for d in domains[:max_domains]
    ]

    ip_entries = [
        {"address": cidr, "description": "CN IP"}
        for cidr in cidrs[:max_ips]
    ]

    # 组合全部规则：本地 IP + AI 域名 + CN 域名 + CN IP
    routes = local_entries + ai_entries + domain_entries + ip_entries

    print(
        f"   本地 IP：{len(local_entries)} 条 | "
        f"AI 域名：{len(ai_entries)} 条 | "
        f"CN 域名：{len(domain_entries)} 条 | "
        f"CN IP：{len(ip_entries)} 条 | "
        f"合计：{len(routes)} 条"
    )

    if len(routes) > MAX_RULES:
        print(f"⚠️ 规则总数超出配额限制，已截断至 {MAX_RULES} 条")
        routes = routes[:MAX_RULES]
    
    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    resp = requests.put(url, json=routes, headers=HEADERS)

    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！共下发 {len(routes)} 条路由 | Mode: {MODE}")
    else:
        print(f"❌ 失败 {resp.status_code}: Cloudflare API 请求未成功")
        print(f"🔍 错误详情: {resp.text}")
        resp.raise_for_status()

if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs = get_cn_cidrs()
    domains = get_cn_domains()
    update_split_tunnels(cidrs, domains)
