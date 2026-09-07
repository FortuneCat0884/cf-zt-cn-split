"""Shared planning and API code for Split Tunnels and Local Domain Fallback."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import ipaddress
import json
import os
import re
import sys
from urllib.parse import quote

import requests


# 这两台 DNS 的主机地址也会自动进入固定 IP 排除列表。
DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]
LOCAL_EXCLUDE_IPS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# 本机 argo 命令的全部自动优选候选段。公共网段可以直接维护在这里。
ARGO_EXCLUDE_IPS = [
    "104.18.10.0/24", "104.18.20.0/24", "104.19.30.0/24",
    "104.20.40.0/24", "104.21.50.0/24", "104.22.60.0/24",
    "104.24.70.0/24", "104.26.80.0/24", "104.27.90.0/24",
    "172.67.180.0/24", "172.67.190.0/24", "172.64.100.0/24",
    "162.159.192.0/24", "162.159.138.0/24",
    "198.41.132.0/24", "198.41.214.0/24", "141.101.120.0/24",
    "108.162.236.0/24", "104.16.1.0/24", "104.16.80.0/24",
    "104.16.160.0/24", "104.17.64.0/24", "104.17.128.0/24",
]

# 合并原来两个脚本的核心名单；父域名已覆盖的子域名无需重复填写。
CN_CORE_SUFFIXES = """
cn ele.me jd.com mi.com qq.com qy.net so.com 126.net 127.net 163.com
ccb.com dji.com amap.com cctv.com cgtn.com cntv.com csdn.net huya.com
mgtv.com oppo.com qiyi.com sina.com sohu.com vivo.com baidu.com bdimg.com
ctrip.com douyu.com gitee.com gtimg.com hdslb.com iqiyi.com ksyun.com
qiniu.com tmall.com upyun.com vmall.com weibo.com ykimg.com youku.com
zhihu.com zhimg.com 71edge.com alicdn.com alipay.com aliyun.com bcebos.com
douban.com douyin.com huawei.com ixigua.com kwimgs.com shifen.com
taobao.com tenpay.com wechat.com wscdns.com xhscdn.com xiaomi.com
yximgs.com abchina.com biliapi.net byteimg.com cctvpic.com kcdnvip.com
meituan.com netease.com oschina.net qiyipic.com sankuai.com tencent.com
toutiao.com volccdn.com aliyuncs.com baidubce.com baidupcs.com
bdstatic.com bilibili.com cmbchina.com dbankcdn.com dianping.com
dingtalk.com doubanio.com kuaishou.com myqcloud.com unionpay.com
volcfcdn.com weibocdn.com ximalaya.com 360buyimg.com bilivideo.com
bytedance.com bytegoofy.com douyincdn.com iesdouyin.com pinduoduo.com
yangkeduo.com didiglobal.com sf-express.com yangshipin.com xiaohongshu.com
segmentfault.com servicewechat.com tencent-cloud.net
""".split()

DEFAULT_SUFFIXES = [
    "corp", "domain", "home", "home.arpa", "host", "internal", "intranet",
    "invalid", "lan", "local", "localdomain", "localhost", "private", "test",
]
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
AUTO_DNS_TAG = "China Split DNS"
TAG_PREFIX = "CF-CN:"
LEGACY_SPLIT_TAGS = {"Local LAN", "AI Service", "CN Core Domain", "CN IP", "Private exclusion"}
TIMEOUT = (10, 30)


class SyncError(Exception):
    """Only messages safe for public Actions logs belong in this exception."""


def private_cidrs(raw: str) -> tuple[str, ...]:
    if not raw.strip():
        return ()
    values = [value for value in re.split(r"[\s,]+", raw.strip()) if value]
    if not values:
        raise SyncError("WARP_EXTRA_EXCLUDES 没有有效项目；不使用时请清空该 Secret。")
    result = []
    for index, value in enumerate(values, 1):
        try:
            cidr = str(ipaddress.ip_network(value, strict=True))
        except ValueError:
            raise SyncError(f"WARP_EXTRA_EXCLUDES 第 {index} 项不是有效 IP/CIDR；原值已隐藏。") from None
        if cidr not in result:
            result.append(cidr)
    return tuple(result)


@dataclass(frozen=True)
class Settings:
    account_id: str
    token: str = field(repr=False)
    profile_id: str = ""
    total_limit: int = 1000
    fallback_target: int = 200
    extra_excludes: tuple[str, ...] = field(default=(), repr=False)

    @classmethod
    def from_env(cls):
        account = os.getenv("CF_ACCOUNT_ID", "").strip()
        token = os.getenv("CF_API_TOKEN", "").strip()
        if not account or not token:
            raise SyncError("缺少 CF_ACCOUNT_ID 或 CF_API_TOKEN。")
        if os.getenv("MODE", "exclude").strip().lower() != "exclude":
            raise SyncError("本版本用于 CN/Argo 排除，请使用 MODE=exclude，避免反转线路。")
        profile = os.getenv("CF_PROFILE_ID", "").strip()
        if profile.lower() == "default":
            profile = ""
        try:
            limit = int(os.getenv("WARP_MAX_TOTAL_RULES", "1000"))
            target = int(os.getenv("WARP_FALLBACK_TARGET", "200"))
        except ValueError:
            raise SyncError("WARP_MAX_TOTAL_RULES 和 WARP_FALLBACK_TARGET 必须为正整数。") from None
        if limit < 1 or target < 1 or target > limit:
            raise SyncError("总配额和 DNS 目标数量必须为正数，DNS 目标不能超过总配额。")
        return cls(account, token, profile, limit, target, private_cidrs(os.getenv("WARP_EXTRA_EXCLUDES", "")))


def suffix_key(value):
    return value.count("."), len(value), value


def normalize_suffix(value, *, public=False):
    if not isinstance(value, str):
        raise ValueError("invalid suffix")
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    value = value.encode("idna").decode("ascii")
    labels = value.split(".")
    if not value or len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ):
        raise ValueError("invalid suffix")
    if public and (len(labels) < 2 or labels[-1].isdigit()):
        raise ValueError("invalid public suffix")
    return value


def covered_suffix(value, parents):
    labels = value.split(".")
    return any(".".join(labels[index:]) in parents for index in range(len(labels)))


def minimal_suffixes(values):
    result = []
    seen = set()
    for value in sorted(set(values), key=suffix_key):
        if not covered_suffix(value, seen):
            result.append(value)
            seen.add(value)
    return result


def normalize_split(rows):
    if not isinstance(rows, list):
        raise SyncError("Split Tunnel API 返回的列表结构无效；停止同步。")
    result = []
    seen = set()
    for index, row in enumerate(rows, 1):
        try:
            if not isinstance(row, dict) or bool(row.get("address")) == bool(row.get("host")):
                raise ValueError("invalid entry")
            desc = row.get("description") or ""
            if not isinstance(desc, str):
                raise ValueError("invalid description")
            if row.get("address"):
                entry = {"address": str(ipaddress.ip_network(row["address"], strict=True)), "description": desc}
            else:
                value = row["host"]
                suffix = normalize_suffix(value)
                entry = {"host": ("*." if value.startswith("*.") else "") + suffix, "description": desc}
            key = json.dumps(entry, sort_keys=True)
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise SyncError(f"现有分流规则第 {index} 项无法安全解析；未输出内容，停止同步。") from None
        if key not in seen:
            seen.add(key)
            result.append(entry)
    return result


def normalize_dns(rows):
    if not isinstance(rows, list):
        raise SyncError("Local Domain Fallback API 返回的列表结构无效；停止同步。")
    result = []
    seen = {}
    for index, row in enumerate(rows, 1):
        try:
            if not isinstance(row, dict):
                raise ValueError("invalid entry")
            suffix = normalize_suffix(row.get("suffix"))
            servers = row.get("dns_server") or []
            if not isinstance(servers, list):
                raise ValueError("invalid servers")
            servers = list(dict.fromkeys(str(ipaddress.ip_address(server)) for server in servers))
            desc = row.get("description") or ""
            if not isinstance(desc, str):
                raise ValueError("invalid description")
            entry = {"suffix": suffix, "dns_server": servers, "description": desc}
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise SyncError(f"现有 DNS 规则第 {index} 项无法安全解析；未输出内容，停止同步。") from None
        if suffix in seen and seen[suffix] != entry:
            raise SyncError("现有 DNS 列表含同后缀的冲突规则；停止同步，避免丢失手工配置。")
        if suffix not in seen:
            result.append(entry)
            seen[suffix] = entry
    return result


def canonical(rows):
    normalized = []
    for row in rows:
        item = dict(row)
        if "dns_server" in item:
            item["dns_server"] = sorted(item["dns_server"])
        normalized.append(json.dumps(item, sort_keys=True, separators=(",", ":")))
    return tuple(sorted(normalized))


@dataclass
class State:
    split: list
    dns: list

    def equivalent(self, other):
        return canonical(self.split) == canonical(other.split) and canonical(self.dns) == canonical(other.dns)


class CloudflareClient:
    def __init__(self, settings, session=None):
        self.session = session or requests.Session()
        base = f"https://api.cloudflare.com/client/v4/accounts/{quote(settings.account_id, safe='')}/devices/policy"
        if settings.profile_id:
            base += "/" + quote(settings.profile_id, safe="")
        self.urls = {"split": base + "/exclude", "dns": base + "/fallback_domains"}
        self.headers = {"Authorization": "Bearer " + settings.token, "Content-Type": "application/json"}

    def _request(self, method, kind, rows=None):
        kwargs = {"headers": self.headers, "timeout": TIMEOUT}
        if rows is not None:
            kwargs["json"] = rows
        try:
            response = self.session.request(method, self.urls[kind], **kwargs)
        except requests.RequestException:
            raise SyncError("Cloudflare 网络请求失败；请求和响应详情已隐藏。") from None
        if response.status_code not in (200, 201, 204):
            raise SyncError(f"Cloudflare 请求失败（HTTP {response.status_code}）；不切换策略、不输出响应正文。")
        if response.status_code == 204 and method == "PUT":
            return None
        try:
            data = response.json()
        except ValueError:
            raise SyncError("Cloudflare 返回了无效 JSON；停止同步，响应正文已隐藏。") from None
        if not isinstance(data, dict) or data.get("success") is not True:
            raise SyncError("Cloudflare 未确认请求成功；停止同步，响应正文已隐藏。")
        if method == "GET" and not isinstance(data.get("result"), list):
            raise SyncError("Cloudflare 未返回有效规则列表；不会将读取失败当作空配置。")
        return data.get("result")

    def read_state(self):
        return State(normalize_split(self._request("GET", "split")), normalize_dns(self._request("GET", "dns")))

    def write(self, kind, rows):
        self._request("PUT", kind, rows)


def download_source(name, url):
    # 公共数据下载不复用带 Cloudflare 令牌的请求头。
    try:
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException:
        raise SyncError(f"下载 {name} 数据失败；停止同步，保留现有配置。") from None
    if not response.text.strip():
        raise SyncError(f"{name} 数据源为空；停止同步，保留现有配置。")
    return response.text


def load_sources(scope):
    sources = {"domains": ("DNS 域名", DOMAIN_URL)}
    if scope == "all":
        sources["ips"] = ("CN IPv4", IP_URL)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {key: pool.submit(download_source, *value) for key, value in sources.items()}
        return {key: future.result() for key, future in futures.items()}


def parse_cn_source(text):
    networks = []
    for index, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=True)
            if network.version != 4 or "/" not in line:
                raise ValueError("expected IPv4 CIDR")
        except ValueError:
            raise SyncError(f"CN IPv4 数据第 {index} 行格式异常；停止同步。") from None
        networks.append(network)
    if not networks:
        raise SyncError("CN IPv4 数据没有有效网段；停止同步。")
    return list(ipaddress.collapse_addresses(networks))


def parse_domain_source(text):
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith(("#", "keyword:", "regexp:", "geosite:", "full:")):
            continue
        if line.startswith("domain:"):
            line = line[len("domain:"):]
        try:
            domains.add(normalize_suffix(line, public=True))
        except (ValueError, UnicodeError):
            continue
    if not domains:
        raise SyncError("公网 DNS 域名源没有有效后缀；停止同步。")
    return sorted(domains, key=suffix_key)


def append_split(rows, entry):
    key = "address" if "address" in entry else "host"
    if not any(row.get(key) == entry[key] for row in rows):
        rows.append(entry)


def required_split_rows(current, settings):
    rows = [dict(row) for row in current if row["description"] not in LEGACY_SPLIT_TAGS and not row["description"].startswith(TAG_PREFIX)]
    try:
        groups = [("local", LOCAL_EXCLUDE_IPS), ("argo", ARGO_EXCLUDE_IPS),
                  ("dns", DNS_SERVERS), ("private", settings.extra_excludes)]
        for tag, values in groups:
            for value in values:
                append_split(rows, {"address": str(ipaddress.ip_network(value, strict=True)), "description": TAG_PREFIX + tag})
    except ValueError:
        raise SyncError("固定 IP 配置包含无效网段；停止同步。") from None
    return rows


def domain_split_rows(required, suffixes):
    rows = [dict(row) for row in required]
    for suffix in minimal_suffixes(suffixes):
        if "." in suffix:
            append_split(rows, {"host": suffix, "description": TAG_PREFIX + "domain"})
        append_split(rows, {"host": "*." + suffix, "description": TAG_PREFIX + "domain"})
    return rows


def dns_baseline(current):
    rows = [dict(row) for row in current if row["description"] != AUTO_DNS_TAG]
    present = {row["suffix"] for row in rows}
    for suffix in DEFAULT_SUFFIXES:
        if not covered_suffix(suffix, present):
            rows.append({"suffix": suffix, "dns_server": [], "description": "Default Local Domain"})
            present.add(suffix)
    return rows


def dns_rows(baseline, automatic):
    return [dict(row) for row in baseline] + [
        {"suffix": suffix, "dns_server": list(DNS_SERVERS), "description": AUTO_DNS_TAG}
        for suffix in sorted(automatic, key=suffix_key)
    ]


@dataclass
class Plan:
    split: list
    dns: list
    required_split: list
    required_dns: list
    stats: dict = field(default_factory=dict)

    @property
    def state(self):
        return State(self.split, self.dns)


def build_plan(settings, current, cn_networks, public_domains, *, scope="all"):
    current = State(normalize_split(current.split), normalize_dns(current.dns))
    baseline = dns_baseline(current.dns)
    baseline_suffixes = {row["suffix"] for row in baseline}
    core = minimal_suffixes(normalize_suffix(value) for value in CN_CORE_SUFFIXES)
    automatic = [value for value in core if not covered_suffix(value, baseline_suffixes)]
    required = required_split_rows(current.split, settings) if scope == "all" else list(current.split)

    def fixed_rows(auto):
        return domain_split_rows(required, core + list(auto)) if scope == "all" else list(current.split)

    def cost(auto):
        return len(fixed_rows(auto)) + len(baseline) + len(auto)

    if cost(automatic) > settings.total_limit:
        raise SyncError("手工规则、核心域名和固定排除项已超过共同配额；未写入任何配置。")
    if scope == "fallback":
        fixed_networks = [ipaddress.ip_network(row["address"]) for row in current.split if "address" in row]
        if any(not any(ipaddress.ip_address(server) in net for net in fixed_networks) for server in DNS_SERVERS):
            raise SyncError("DNS 服务器尚未被 IP 规则排除；请先运行 cf-zt-cn-split.py 完整同步。")

    # 200 是补充自动项的目标；手工和核心项超过目标时仍保留，受共同总配额约束。
    target = max(settings.fallback_target, len(baseline) + len(automatic))
    present = baseline_suffixes | set(automatic)
    for candidate in sorted(set(public_domains), key=suffix_key):
        if len(baseline) + len(automatic) >= target:
            break
        if covered_suffix(candidate, present):
            continue
        proposed = automatic + [candidate]
        if cost(proposed) > settings.total_limit:
            continue
        automatic = proposed
        present.add(candidate)

    dns = dns_rows(baseline, automatic)
    split = fixed_rows(automatic)
    remaining = settings.total_limit - len(dns) - len(split)
    selected = []
    already_covered = 0
    if scope == "all":
        fixed_networks = [ipaddress.ip_network(row["address"]) for row in split if "address" in row]
        candidates = []
        for network in cn_networks:
            if any(network.version == parent.version and network.subnet_of(parent) for parent in fixed_networks):
                already_covered += 1
            else:
                candidates.append(network)
        # 仅选数据源原有的精确聚合网段；不扩大网段，不按地址从低到高截断。
        candidates.sort(key=lambda net: (-net.num_addresses, int(net.network_address), net.prefixlen))
        selected = candidates[:remaining]
        split += [{"address": str(net), "description": TAG_PREFIX + "cn-ip"} for net in selected]
    if len(split) + len(dns) > settings.total_limit:
        raise SyncError("计划超过共同配额；停止同步。")
    stats = {"split_rules": len(split), "dns_rules": len(dns), "total_rules": len(split) + len(dns),
             "cn_source": len(cn_networks), "cn_selected": len(selected), "cn_already_covered": already_covered}
    return Plan(split, dns, required, baseline, stats)


def update_steps(current, plan, limit, *, scope="all"):
    split_changed = canonical(current.split) != canonical(plan.split)
    dns_changed = canonical(current.dns) != canonical(plan.dns)
    if not split_changed and not dns_changed:
        return []
    if len(plan.split) + len(plan.dns) > limit:
        raise SyncError("计划超过共同配额；停止同步。")
    if scope == "fallback":
        if split_changed or len(current.split) + len(plan.dns) > limit:
            raise SyncError("单独 DNS 更新的剩余配额不足；请执行完整同步。")
        return [("dns", plan.dns)] if dns_changed else []
    if not dns_changed or len(plan.split) + len(current.dns) <= limit:
        return ([("split", plan.split)] if split_changed else []) + ([("dns", plan.dns)] if dns_changed else [])
    if not split_changed or len(current.split) + len(plan.dns) <= limit:
        return ([("dns", plan.dns)] if dns_changed else []) + ([("split", plan.split)] if split_changed else [])

    # 旧版本可能已经生成了 1000 + 400。先缩减自动项，保护手工、Argo、DNS 和 Secret。
    split_room = limit - len(current.dns)
    if split_room >= len(plan.required_split):
        bridge = plan.split[:split_room]
        return [("split", bridge), ("dns", plan.dns), ("split", plan.split)]
    dns_room = limit - len(current.split)
    if dns_room >= len(plan.required_dns):
        bridge = plan.required_dns + [row for row in plan.dns if row not in plan.required_dns]
        return [("dns", bridge[:dns_room]), ("split", plan.split), ("dns", plan.dns)]
    raise SyncError("旧配置超额，无法在保留手工项的前提下安全更新；未写入任何配置。")


def apply_plan(client, current, plan, limit, *, scope="all", dry_run=False):
    steps = update_steps(current, plan, limit, scope=scope)
    if dry_run:
        print(f"预检查通过：计划 {len(steps)} 次更新；dry-run 未执行写入。")
        return 0
    expected = current
    attempted = 0
    try:
        for kind, rows in steps:
            if not client.read_state().equivalent(expected):
                raise SyncError("云端配置在检查后发生变化；停止同步，避免覆盖同时进行的修改。")
            attempted += 1
            client.write(kind, rows)
            expected = State(rows, expected.dns) if kind == "split" else State(expected.split, rows)
            if not client.read_state().equivalent(expected):
                raise SyncError("写入后的回读结果不一致；停止后续更新。")
    except SyncError as exc:
        if attempted:
            raise SyncError(f"同步未全部完成，已发起 {attempted} 次写入。{exc} 重新运行会先读取当前配置。") from None
        raise
    if not steps:
        print("配置与计划一致，无需写入。")
    else:
        print(f"同步成功：{len(steps)} 次更新均已回读确认。")
    return len(steps)


def synchronize(settings, *, scope="all", dry_run=False, client=None, sources=None):
    # 两个源和所有配置都先完整验证；源失败不会触发任何 PUT。
    sources = load_sources(scope) if sources is None else sources
    domains = parse_domain_source(sources["domains"])
    networks = parse_cn_source(sources["ips"]) if scope == "all" else []
    client = client or CloudflareClient(settings)
    current = client.read_state()
    plan = build_plan(settings, current, networks, domains, scope=scope)
    print(f"计划：分流 {len(plan.split)} 条 + DNS {len(plan.dns)} 条 = {len(plan.split) + len(plan.dns)}/{settings.total_limit} 条。")
    if scope == "all":
        missing = plan.stats["cn_source"] - plan.stats["cn_selected"] - plan.stats["cn_already_covered"]
        print(f"CN 网段：选入 {plan.stats['cn_selected']} 条，固定项已覆盖 {plan.stats['cn_already_covered']} 条，未选入 {missing} 条。")
        if missing:
            print("配额内无法保证全部 CN IP 直连；已为自动 DNS 域名配置根域名和子域名分流。")
    apply_plan(client, current, plan, settings.total_limit, scope=scope, dry_run=dry_run)
    return plan


def main(scope="all"):
    parser = argparse.ArgumentParser(description="同步 Cloudflare CN/Argo 排除与国内 DNS 配置")
    parser.add_argument("--dry-run", action="store_true", help="读取并验证计划，只显示数量，不写入")
    args = parser.parse_args()
    try:
        synchronize(Settings.from_env(), scope=scope, dry_run=args.dry_run)
    except SyncError as exc:
        print(f"同步失败：{exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"同步遇到未预期错误（{type(exc).__name__}）；详情未输出，以保护私有配置。", file=sys.stderr)
        return 1
    return 0
