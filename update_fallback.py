"""单独更新 DNS，使用现有分流规则剩余的配额；日常建议执行完整同步。"""
from warp_common import main


if __name__ == "__main__":
    raise SystemExit(main(scope="fallback"))
