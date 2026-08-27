import os
import requests

ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
TOKEN = os.environ.get("CF_API_TOKEN")
PROFILE_ID = os.environ.get("CF_PROFILE_ID")

if not ACCOUNT_ID or not TOKEN:
    raise ValueError("缺少环境变量 CF_ACCOUNT_ID 或 CF_API_TOKEN")

# 国内高速双公共 DNS
DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]

# 1. 官方 14 个系统保留默认内网域（保持内网/局域网/NAS 正常访问）
DEFAULT_FALLBACKS = [
    {"suffix": "corp", "dns_servers": []},
    {"suffix": "domain", "dns_servers": []},
    {"suffix": "home", "dns_servers": []},
    {"suffix": "home.arpa", "dns_servers": []},
    {"suffix": "host", "dns_servers": []},
    {"suffix": "internal", "dns_servers": []},
    {"suffix": "intranet", "dns_servers": []},
    {"suffix": "invalid", "dns_servers": []},
    {"suffix": "lan", "dns_servers": []},
    {"suffix": "local", "dns_servers": []},
    {"suffix": "localdomain", "dns_servers": []},
    {"suffix": "localhost", "dns_servers": []},
    {"suffix": "private", "dns_servers": []},
    {"suffix": "test", "dns_servers": []},
]

# 2. 精选国内最全核心服务、音视频 CDN、银行、政企主域名
CORE_DOMAINS = [
    # 顶级后缀（一条即可覆盖所有 .cn / .com.cn / .gov.cn / .edu.cn）
    "cn",

    # 央视 / 新闻 / 广播电视
    "cctv.com", "cctvpic.com", "cntv.com", "cgtn.com", "yangshipin.com",
    "xinhuanet.com", "people.com.cn", "cankaoxiaoxi.com", "thepaper.cn",

    # 腾讯系（微信、QQ、腾讯视频、腾讯云、游戏 CDN）
    "qq.com", "tencent.com", "gtimg.com", "qpic.cn", "qlogo.cn",
    "tencent-cloud.net", "myqcloud.com", "wechat.com", "tenpay.com",

    # 阿里系（淘宝、天猫、支付宝、阿里云、优酷、高德）
    "taobao.com", "tmall.com", "alipay.com", "alipayobjects.com",
    "aliyun.com", "aliyuncs.com", "alicdn.com", "ykimg.com",
    "youku.com", "amap.com", "autonavi.com", "dingtalk.com",

    # 百度系（搜索、网盘、贴吧、地图）
    "baidu.com", "bdimg.com", "bdstatic.com", "baidupcs.com",

    # 字节跳动系（抖音、今日头条、西瓜视频、飞书）
    "douyin.com", "bytegoofy.com", "bytedance.com", "toutiao.com",
    "feishu.cn", "feishucdn.com", "pstatp.com", "ixigua.com",

    # 哔哩哔哩（B站及全套播放与图片 CDN）
    "bilibili.com", "biliapi.net", "hdslb.com", "bilivideo.com",

    # 爱奇艺专项（含视频流分发与边缘 CDN）
    "iqiyi.com", "qiyi.com", "qy.net", "qiyipic.com", "71edge.com",

    # 芒果 TV / 快手 / 斗鱼 / 虎牙 / 喜马拉雅
    "mgtv.com", "hunantv.com", "kuaishou.com", "yximgs.com",
    "douyu.com", "douyucdn.cn", "huya.com", "ximalaya.com",

    # 网易系（邮箱、网易云音乐、游戏）
    "163.com", "126.net", "netease.com", "127.net", "music.163.com",

    # 电商 / 生活 / 出行（京东、美团、拼多多、小红书、携程、滴滴、12306）
    "jd.com", "360buyimg.com", "pinduoduo.com", "yangkeduo.com",
    "meituan.com", "dianping.com", "meituan.net", "xiaohongshu.com",
    "ctrip.com", "trip.com", "didiglobal.com", "udache.com", "12306.cn",

    # 社区 / 资讯 / 技术（知乎、微博、CSDN、掘金、Gitee、博客园）
    "zhihu.com", "zhimg.com", "weibo.com", "weibo.cn", "sinaimg.cn",
    "csdn.net", "gitee.com", "juejin.cn", "cnblogs.com", "segmentfault.com",

    # 手机终端 / 硬件生态（华为、小米、OPPO、vivo、荣耀、大疆）
    "huawei.com", "dbankcdn.com", "vmall.com", "mi.com", "xiaomi.com",
    "mi-img.com", "oppo.com", "vivo.com", "honor.com", "dji.com",

    # 金融 / 银行（招行、工行、建行、农行、中行、银联）
    "cmbchina.com", "icbc.com.cn", "ccb.com", "abchina.com",
    "boc.cn", "unionpay.com",

    # 工具 / 办公 / 安全（WPS 金山、夸克、360）
    "wps.cn", "wpscdn.cn", "kdocs.cn", "quark.cn", "360.cn", "so.com"
]

print("🔄 正在拉取扩展国内直连域名...")
try:
    url = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    raw_lines = resp.text.splitlines()

    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("full:") or line.startswith("domain:"):
            domain = line.split(":", 1)[1]
        elif ":" in line:
            continue
        else:
            domain = line

        # 过滤无效纯数字、杂乱单字域名
        if domain and len(domain) > 3 and not domain.startswith("0") and not domain.startswith("1"):
            if domain not in CORE_DOMAINS:
                CORE_DOMAINS.append(domain)
except Exception as e:
    print(f"⚠️ 拉取公网扩展列表异常，使用核心内置列表: {e}")

# 严格截取前 360 条（加上 14 条保留内网域，总数约 374 条，完美处于安全限制内）
selected_domains = CORE_DOMAINS[:360]
print(f"📦 筛选出 {len(selected_domains)} 个核心高频国内域名...")

payload = []
payload.extend(DEFAULT_FALLBACKS)

for d in selected_domains:
    payload.append({
        "suffix": d,
        "dns_servers": DNS_SERVERS,
        "description": "China Split DNS"
    })

if PROFILE_ID:
    api_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/fallback_domains"
else:
    api_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/fallback_domains"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

print(f"🚀 正在推送到 API: {api_url}")
cf_resp = requests.put(api_url, json=payload, headers=headers)

if cf_resp.status_code != 200:
    print(f"❌ 推送失败: {cf_resp.text}")
    cf_resp.raise_for_status()

print("✅ 同步完成！国内全业务域名与阿里/腾讯 DNS 已成功全量写入。")
