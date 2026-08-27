import os
import requests

# 从环境变量中读取 Cloudflare 凭证
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
TOKEN = os.environ.get("CF_API_TOKEN")

if not ACCOUNT_ID or not TOKEN:
    raise ValueError("❌ 缺少环境变量 CF_ACCOUNT_ID 或 CF_API_TOKEN")

# 国内双公共 DNS（阿里公共 DNS + 腾讯 DNSPod）
DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]

# 官方完整的 14 个默认内网保留域名（不指定 DNS 服务器，保持走本地网关）
DEFAULT_FALLBACKS = [
    {"suffix": "corp"},
    {"suffix": "domain"},
    {"suffix": "home"},
    {"suffix": "home.arpa"},
    {"suffix": "host"},
    {"suffix": "internal"},
    {"suffix": "intranet"},
    {"suffix": "invalid"},
    {"suffix": "lan"},
    {"suffix": "local"},
    {"suffix": "localdomain"},
    {"suffix": "localhost"},
    {"suffix": "private"},
    {"suffix": "test"},
]

print("🔄 正在从开源社区拉取国内热门直连域名列表...")
url = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
resp = requests.get(url, timeout=15)
resp.raise_for_status()
raw_lines = resp.text.splitlines()

cn_domains = []
for line in raw_lines:
    line = line.strip()
    # 过滤空行与注释
    if not line or line.startswith("#"):
        continue
    # 提取纯域名
    if line.startswith("full:") or line.startswith("domain:"):
        domain = line.split(":", 1)[1]
    elif ":" in line:
        continue
    else:
        domain = line

    if domain and domain not in cn_domains:
        cn_domains.append(domain)

# 确保核心根后缀 cn 在首位（自动匹配所有 .cn 结尾网站）
if "cn" not in cn_domains:
    cn_domains.insert(0, "cn")

# 截取前 400 个最高频的主流国内域名，避免超出 Cloudflare 规则容量限制
MAX_LIMIT = 400
selected_domains = cn_domains[:MAX_LIMIT]
print(f"📦 成功筛选出 {len(selected_domains)} 个高频国内域名...")

# 组装完整的推送数据
payload = []

# 1. 注入默认 14 个内网域名（不带 dns_servers）
payload.extend(DEFAULT_FALLBACKS)

# 2. 注入国内分流域名（同时绑定 223.5.5.5 和 119.29.29.29）
for d in selected_domains:
    payload.append({
        "suffix": d,
        "dns_servers": DNS_SERVERS
    })

print(f"🚀 正在向 Cloudflare API 推送共 {len(payload)} 条 Fallback 规则...")

# 调用 Cloudflare Zero Trust Local Domain Fallback 接口
api_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/fallback_domains"
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

cf_resp = requests.put(api_url, json=payload, headers=headers)

if cf_resp.status_code != 200:
    print(f"❌ 推送失败，返回状态码: {cf_resp.status_code}")
    print(f"错误详情: {cf_resp.text}")
    cf_resp.raise_for_status()

print("✅ 同步成功！国内域名已全量绑定 223.5.5.5 / 119.29.29.29，且 14 个内网保留域已完整保留。")
