import requests
import os
import re
import ipaddress

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID   = os.getenv("CF_PROFILE_ID", "")
MODE         = os.getenv("MODE", "exclude")  # exclude=CN直连 (YouTube跑满) | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

if MODE not in ALLOWED_MODES:
    raise ValueError(f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

# Cloudflare Zero Trust Split Tunnels 限制为 1000 条
MAX_RULES = int(os.getenv("MAX_RULES", "1000"))

# ============================================================
# 1. 本地私有网络 (使用 address 字段)
# ============================================================
LOCAL_EXCLUDE_IPS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# ============================================================
# 2. AI 服务域名 (使用 host 字段，排除后走本地代理专线)
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

# ============================================================
# 3. 国内核心大厂域名 (精准排除，绝不绕道海外)
# ============================================================
CN_CORE_DOMAINS = [
    *.cn,
    # Bilibili (特别包含视频核心 CDN bilivideo.com)
    "*.bilibili.com", "*.bilivideo.com", "*.hdslb.com", "*.biliapi.net",
    # 百度
    "*.baidu.com", "*.bdimg.com", "*.bdstatic.com", "*.baidupcs.com", "*.shifen.com", "*.bcebos.com",
    # 腾讯 / 微信全家桶 (含小程序与微信支付)
    "*.wechat.com", "*.weixin.qq.com", "*.wx.qq.com", "*.servicewechat.com", "*.tenpay.com",
    "*.qq.com", "*.tencent.com", "*.gtimg.com", "*.myqcloud.com",
    # 阿里 / 支付
    "*.taobao.com", "*.tmall.com", "*.alipay.com", "*.alicdn.com", "*.aliyun.com",
    # 京东 / 拼多多
    "*.jd.com", "*.360buyimg.com", "*.pinduoduo.com", "*.yangkeduo.com",
    # 字节 / 抖音
    "*.douyin.com", "*.douyincdn.com", "*.iesdouyin.com", "*.byteimg.com", "*.toutiao.com", "*.bytedance.com",
    # 快手 / 小红书
    "*.kuaishou.com", "*.kwimgs.com", "*.yximgs.com", "*.xiaohongshu.com", "*.xhscdn.com",
    # 知乎 / 网易 / 新浪微博
    "*.zhihu.com", "*.zhimg.com", "*.163.com", "*.126.net", "*.sina.com", "*.weibo.com", "*.weibocdn.com",
    # 美团 / 高德地图 / 央视
    "*.meituan.com", "*.dianping.com", "*.amap.com", "*.cctv.com", "*.cctvpic.com", "*.cntv.cn", "*.wscdns.com", "*.kcdnvip.com", "*.volcfcdn.com",
    # 影音视频 / 豆瓣
    "*.iqiyi.com", "*.qiyi.com", "*.youku.com", "*.sohu.com", "*.douban.com", "*.doubanio.com",
    # 手机大厂 / 开发者站
    "*.mi.com", "*.huawei.com", "*.csdn.net", "*.segmentfault.com", "*.oschina.net", "*.gitee.com"
]

# IP 数据源：GeoIP2-CN (聚合版)
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

def get_cn_cidrs(max_available_ips):
    """拉取 CN CIDR 并根据剩余可用配额进行最优聚合"""
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    raw_cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    
    nets = [ipaddress.ip_network(c) for c in raw_cidrs if '/' in c]
    collapsed = list(ipaddress.collapse_addresses(nets))
    
    # 如果超出配额，优先保留掩码较小的大骨干网段（<=18）
    if len(collapsed) > max_available_ips:
        collapsed = [net for net in collapsed if net.prefixlen <= 18]
        
    cidrs = [str(net) for net in collapsed]
    print(f"   IP 数据源获取并聚合为 {len(cidrs)} 条 CIDR (可用配额: {max_available_ips})")
    return cidrs

def update_split_tunnels():
    # 1. 本地 IP
    local_entries = [{"address": ip, "description": "Local LAN"} for ip in LOCAL_EXCLUDE_IPS]

    # 2. AI 域名
    ai_entries = [{"host": domain, "description": "AI Service"} for domain in AI_EXCLUDE_DOMAINS]

    # 3. 国内核心大厂域名
    cn_domain_entries = [{"host": domain, "description": "CN Core Domain"} for domain in CN_CORE_DOMAINS]

    reserved_count = len(local_entries) + len(ai_entries) + len(cn_domain_entries)
    max_available_ips = MAX_RULES - reserved_count

    # 4. 获取自适应配额的 CN IP
    cidrs = get_cn_cidrs(max_available_ips)
    ip_entries = [{"address": cidr, "description": "CN IP"} for cidr in cidrs[:max_available_ips]]

    # 组合全部规则
    routes = local_entries + ai_entries + cn_domain_entries + ip_entries

    print(
        f"   本地 IP：{len(local_entries)} 条 | "
        f"AI 域名：{len(ai_entries)} 条 | "
        f"CN 大厂域名：{len(cn_domain_entries)} 条 | "
        f"CN IP：{len(ip_entries)} 条 | "
        f"合计下发：{len(routes)} 条"
    )

    if len(routes) > MAX_RULES:
        routes = routes[:MAX_RULES]
    
    if PROFILE_ID:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
    else:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

    resp = requests.put(url, json=routes, headers=HEADERS)

    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！共下发 {len(routes)} 条规则 | Mode: {MODE}")
    else:
        print(f"❌ 失败 {resp.status_code}: Cloudflare API 请求未成功")
        print(f"🔍 错误详情: {resp.text}")
        resp.raise_for_status()

if __name__ == "__main__":
    print(f"🔄 开始执行 Cloudflare Split Tunnels 同步 (模式: {MODE})...")
    update_split_tunnels()
