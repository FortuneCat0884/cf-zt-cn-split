import os
import requests
import re
import json
import sys

# ==========================================
# 0. 环境变量与全局配置
# ==========================================
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
TOKEN = os.environ.get("CF_API_TOKEN")
ENV_PROFILE_ID = os.environ.get("CF_PROFILE_ID")

if not ACCOUNT_ID or not TOKEN:
    print("❌ 致命错误: 缺少环境变量 CF_ACCOUNT_ID 或 CF_API_TOKEN")
    sys.exit(1)

DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]
AUTO_TAG = "China Split DNS"
MAX_TOTAL_RULES = 400  # Cloudflare 官方规则总量上限

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# ==========================================
# 1. 精准探测目标 Policy ID
# ==========================================
policy_id = ENV_PROFILE_ID.strip() if ENV_PROFILE_ID else None
if not policy_id or policy_id.lower() == "default":
    for endpoint in ["devices/policies", "devices/policy"]:
        url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/{endpoint}"
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                result = res.json().get("result", [])
                if isinstance(result, list) and len(result) > 0:
                    for p in result:
                        if p.get("default") is True:
                            policy_id = p.get("policy_id") or p.get("id")
                            break
                    if not policy_id:
                        policy_id = result[0].get("policy_id") or result[0].get("id")
                    break
                elif isinstance(result, dict):
                    policy_id = result.get("policy_id") or result.get("id")
                    break
        except Exception:
            continue

# 【重点修复修复区域】根据是否携带 ID 智能切换单复数路由
if policy_id and policy_id.lower() != "default":
    api_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policies/{policy_id}/fallback_domains"
else:
    api_url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/fallback_domains"

# ==========================================
# 2. 状态感知与数据隔离 (最高等级防御)
# ==========================================
DEFAULT_SUFFIXES = [
    "corp", "domain", "home", "home.arpa", "host", "internal", "intranet", 
    "invalid", "lan", "local", "localdomain", "localhost", "private", "test"
]

user_manual_domains = []
user_manual_suffixes = set()

print(f"🛡️ 正在感知云端现有配置 (Target: {policy_id or 'Global Default'})，建立私有数据保护隔离舱...")
try:
    get_resp = requests.get(api_url, headers=headers, timeout=15)
    get_resp.raise_for_status()
    for item in get_resp.json().get("result", []):
        s = item.get("suffix", "").lower().strip()
        desc = item.get("description", "")
        
        # 只要不是脚本自动生成的，全部视为用户的神圣不可侵犯财产
        if s and desc != AUTO_TAG:
            user_manual_domains.append({
                "suffix": s,
                "dns_server": item.get("dns_server") or [],  
                "description": desc
            })
            user_manual_suffixes.add(s)
except Exception as e:
    print(f"❌ 致命错误: 无法获取云端当前配置！为防止误覆盖私有数据，同步强行阻断中止！\n详情: {e}")
    sys.exit(1)

baseline_payload = list(user_manual_domains)
for suffix in DEFAULT_SUFFIXES:
    if suffix not in user_manual_suffixes:
        baseline_payload.append({
            "suffix": suffix,
            "dns_server": [],
            "description": "Default Local Domain"
        })
        user_manual_suffixes.add(suffix)  

dynamic_quota = MAX_TOTAL_RULES - len(baseline_payload)
print(f"📊 隔离舱建立完毕: 保护了 {len(user_manual_domains)} 条您的私有/修改规则。云端剩余可用自动配额: {dynamic_quota} 条")

# ==========================================
# 3. 全局拓扑联合查重函数
# ==========================================
def is_redundant(target: str, auto_domains: list) -> bool:
    if target.endswith(".cn") and target != "cn":
        return True  
    for parent in list(user_manual_suffixes) + auto_domains:
        if parent == "cn": 
            continue
        if target == parent or target.endswith("." + parent):
            return True
    return False

# ==========================================
# 4. 构建与清洗骨干大厂库
# ==========================================
INITIAL_CORE = [
    "cn", "cctv.com", "cctvpic.com", "cntv.com", "cgtn.com", "yangshipin.com",
    "qq.com", "tencent.com", "gtimg.com", "tencent-cloud.net", "myqcloud.com", "wechat.com",
    "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "aliyuncs.com", "alicdn.com", "ykimg.com", "youku.com", "amap.com", "dingtalk.com", "ele.me",
    "baidu.com", "bdimg.com", "bdstatic.com", "baidupcs.com", "baidubce.com",
    "douyin.com", "bytegoofy.com", "bytedance.com", "toutiao.com", "ixigua.com", "volccdn.com",
    "bilibili.com", "biliapi.net", "hdslb.com", "bilivideo.com",
    "iqiyi.com", "qiyi.com", "qy.net", "qiyipic.com", "71edge.com",
    "mgtv.com", "kuaishou.com", "yximgs.com", "douyu.com", "huya.com", "ximalaya.com",
    "163.com", "126.net", "netease.com", "127.net",
    "jd.com", "360buyimg.com", "pinduoduo.com", "meituan.com", "sankuai.com", "xiaohongshu.com",
    "ctrip.com", "didiglobal.com", "sf-express.com", "zhihu.com", "weibo.com", "csdn.net", "gitee.com",
    "qiniu.com", "upyun.com", "ksyun.com",
    "huawei.com", "dbankcdn.com", "vmall.com", "mi.com", "xiaomi.com", "oppo.com", "vivo.com", "dji.com",
    "cmbchina.com", "ccb.com", "abchina.com", "unionpay.com", "so.com"
]

INITIAL_CORE = sorted(list(set(INITIAL_CORE)), key=lambda x: (x.count('.'), len(x)))
auto_generated_domains = []

for d in INITIAL_CORE:
    if len(auto_generated_domains) >= dynamic_quota:
        break
    if not is_redundant(d, auto_generated_domains):
        auto_generated_domains.append(d)

print(f"⭐ 已安全分发大厂根域: {len(auto_generated_domains)} 条，剩余额度: {dynamic_quota - len(auto_generated_domains)} 条")

# ==========================================
# 5. 公网扩展库抓取与安全补充
# ==========================================
public_candidates = []
try:
    print("🔄 正在拉取并深度清洗公网扩展资源...")
    resp = requests.get("https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt", timeout=15)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith(("#", "keyword:", "regexp:", "geosite:")): 
            continue
        
        domain = line.split(":", 1)[1] if line.startswith(("domain:", "full:")) else line
        domain = domain.lstrip('*.').rstrip('.')  
        
        if (domain and len(domain) > 3 and not domain.endswith(".cn") 
            and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain)  
            and re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', domain)):
            public_candidates.append(domain)
except Exception as e:
    print(f"⚠️ 拉取扩展列表异常 (自动回退至纯骨干库): {e}")

public_candidates = sorted(list(set(public_candidates)), key=lambda x: (x.count('.'), len(x)))

for candidate in public_candidates:
    if len(auto_generated_domains) >= dynamic_quota:
        break
    if not is_redundant(candidate, auto_generated_domains):
        auto_generated_domains.append(candidate)

print(f"📦 公网补充完毕，本次共生成优质自动化直连规则: {len(auto_generated_domains)} 条")

# ==========================================
# 6. 安全无损合并装载与推送
# ==========================================
final_payload = list(baseline_payload)
for d in auto_generated_domains:
    final_payload.append({
        "suffix": d, 
        "dns_server": DNS_SERVERS, 
        "description": AUTO_TAG
    })

print(f"🚀 正在推送装载了 {len(final_payload)} 条规则的数据包至 Cloudflare 边缘端点...")
cf_resp = requests.put(api_url, json=final_payload, headers=headers)

if cf_resp.status_code not in (200, 201):
    print(f"⚠️ PUT 推送遇到阻塞 (Status: {cf_resp.status_code})，尝试降级使用 PATCH 协议...")
    cf_resp = requests.patch(api_url, json=final_payload, headers=headers)

if cf_resp.status_code not in (200, 201):
    try:
        err_info = json.dumps(cf_resp.json(), indent=2, ensure_ascii=False)
    except Exception:
        err_info = cf_resp.text
    print(f"❌ 最终推送失败，API 完整报错详情:\n{err_info}")
    sys.exit(1)

print("✅ 大满贯达成！规则闭环天衣无缝，私有数据毫发无伤，DNS 参数全面接管！")
