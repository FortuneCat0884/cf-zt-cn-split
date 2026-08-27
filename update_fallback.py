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
MAX_TOTAL_RULES = 400

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# ==========================================
# 1. 动态双向端点握手 (解决默认策略 404 暗坑)
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

# 构造候选端点列表（特定策略端点优先，全局默认端点兜底）
candidate_urls = []
if policy_id and policy_id.lower() != "default":
    candidate_urls.append(f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{policy_id}/fallback_domains")
candidate_urls.append(f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/fallback_domains")

api_url = None
raw_cloud_domains = []

print("🛡️ 正在与 Cloudflare API 进行自适应握手并拉取现有配置...")
for test_url in candidate_urls:
    try:
        resp = requests.get(test_url, headers=headers, timeout=15)
        if resp.status_code == 200:
            api_url = test_url
            raw_cloud_domains = resp.json().get("result", [])
            print(f"✅ 成功锁定通信端点: {api_url}")
            break
        elif resp.status_code == 404:
            print(f"ℹ️ 端点 {test_url} 返回 404（默认策略保护），自动切换备用端点...")
    except Exception as e:
        print(f"⚠️ 探测异常: {e}")

if not api_url:
    print("❌ 致命错误: 所有 API 端点均无法连通，为保护私有配置，任务中止！")
    sys.exit(1)

# ==========================================
# 2. 数据感知与私有规则保护
# ==========================================
DEFAULT_SUFFIXES = [
    "corp", "domain", "home", "home.arpa", "host", "internal", "intranet", 
    "invalid", "lan", "local", "localdomain", "localhost", "private", "test"
]

user_manual_domains = []
user_manual_suffixes = set()

for item in raw_cloud_domains:
    s = item.get("suffix", "").lower().strip()
    desc = item.get("description", "")
    if s and desc != AUTO_TAG:
        user_manual_domains.append({
            "suffix": s,
            "dns_server": item.get("dns_server") or [],
            "description": desc
        })
        user_manual_suffixes.add(s)

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
print(f"📊 保护了 {len(user_manual_domains)} 条您的私有规则，剩余自动配额: {dynamic_quota} 条")

# ==========================================
# 3. 全局联合去重
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
# 4. 骨干大厂库
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

print(f"⭐ 已分发大厂根域: {len(auto_generated_domains)} 条")

# ==========================================
# 5. 公网扩展库
# ==========================================
public_candidates = []
try:
    print("🔄 正在拉取公网扩展直连列表...")
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
    print(f"⚠️ 拉取扩展异常: {e}")

public_candidates = sorted(list(set(public_candidates)), key=lambda x: (x.count('.'), len(x)))

for candidate in public_candidates:
    if len(auto_generated_domains) >= dynamic_quota:
        break
    if not is_redundant(candidate, auto_generated_domains):
        auto_generated_domains.append(candidate)

print(f"📦 公网补充完毕，本次共生成规则: {len(auto_generated_domains)} 条")

# ==========================================
# 6. 推送更新
# ==========================================
final_payload = list(baseline_payload)
for d in auto_generated_domains:
    final_payload.append({
        "suffix": d, 
        "dns_server": DNS_SERVERS, 
        "description": AUTO_TAG
    })

print(f"🚀 正在推送到 Cloudflare: {api_url}")
cf_resp = requests.put(api_url, json=final_payload, headers=headers)

if cf_resp.status_code not in (200, 201):
    print(f"⚠️ PUT 推送未直接成功 (Status: {cf_resp.status_code})，尝试 PATCH...")
    cf_resp = requests.patch(api_url, json=final_payload, headers=headers)

if cf_resp.status_code not in (200, 201):
    try:
        err_info = json.dumps(cf_resp.json(), indent=2, ensure_ascii=False)
    except Exception:
        err_info = cf_resp.text
    print(f"❌ 最终推送失败:\n{err_info}")
    sys.exit(1)

print("✅ 同步圆满成功！默认策略自适应握手完成，DNS 参数已全量生效！")
