import contextlib
from copy import deepcopy
from dataclasses import replace
import io
import ipaddress
import os
import unittest
from unittest.mock import Mock, patch

import requests
import warp_common as w


PUBLIC = [f"site{i:04d}.example.net" for i in range(300)]
NETWORKS = [ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"
)]
SOURCES = {"domains": "\n".join(PUBLIC), "ips": "\n".join(map(str, NETWORKS))}


class FakeClient:
    def __init__(self, state, *, limit=1000):
        self.state = deepcopy(state)
        self.limit = limit
        self.writes = []
        self.reads = 0
        self.fail_write = None
        self.change_on_read = None
        self.ignore_writes = False

    def read_state(self):
        self.reads += 1
        if self.reads == self.change_on_read:
            self.state.split.append({"address": "203.0.113.199/32", "description": "Concurrent manual change"})
        return deepcopy(self.state)

    def write(self, kind, rows):
        self.writes.append((kind, deepcopy(rows)))
        if len(self.writes) == self.fail_write:
            raise w.SyncError("模拟写入失败")
        if self.ignore_writes:
            return
        next_state = w.State(rows, self.state.dns) if kind == "split" else w.State(self.state.split, rows)
        if len(next_state.split) + len(next_state.dns) > self.limit:
            raise AssertionError("Intermediate configuration exceeded shared limit")
        self.state = deepcopy(next_state)


def split_rows(count):
    base = int(ipaddress.ip_address("198.18.0.0"))
    return [{"address": str(ipaddress.ip_address(base + i)) + "/32", "description": w.TAG_PREFIX + "cn-ip"} for i in range(count)]


def dns_entries(count):
    return [{"suffix": f"n{i}.example.invalid", "dns_server": ["192.0.2.53"], "description": w.AUTO_DNS_TAG} for i in range(count)]


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.cfg = w.Settings("offline-account", "offline-token")
        self.empty = w.State([], [])
        blocker = patch.object(requests.sessions.Session, "request", side_effect=AssertionError("Live HTTP is forbidden in tests"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def quiet(self, function, *args, **kwargs):
        log = io.StringIO()
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            result = function(*args, **kwargs)
        return result, log.getvalue()

    def test_secret_is_optional_and_normalized(self):
        self.assertEqual(w.private_cidrs(""), ())
        self.assertEqual(w.private_cidrs("203.0.113.37,\n203.0.113.37/32 2001:db8::7"),
                         ("203.0.113.37/32", "2001:db8::7/128"))
        for invalid in (",,", "DO-NOT-LOG-THIS", "203.0.113.37/24"):
            with self.assertRaises(w.SyncError) as error:
                w.private_cidrs(invalid)
            self.assertNotIn(invalid, str(error.exception))

    def test_environment_uses_same_explicit_profile(self):
        env = {"CF_ACCOUNT_ID": "offline-account", "CF_API_TOKEN": "offline-token", "CF_PROFILE_ID": " selected-profile "}
        with patch.dict(os.environ, env, clear=True):
            cfg = w.Settings.from_env()
        client = w.CloudflareClient(cfg, session=Mock())
        self.assertTrue(all("/selected-profile/" in url for url in client.urls.values()))
        with patch.dict(os.environ, {**env, "CF_PROFILE_ID": "default"}, clear=True):
            default = w.CloudflareClient(w.Settings.from_env(), session=Mock())
        self.assertTrue(default.urls["dns"].endswith("/devices/policy/fallback_domains"))

    def test_include_mode_and_invalid_budget_stop(self):
        env = {"CF_ACCOUNT_ID": "offline-account", "CF_API_TOKEN": "offline-token"}
        for addition in ({"MODE": "include"}, {"WARP_MAX_TOTAL_RULES": "0"}, {"WARP_FALLBACK_TARGET": "bad"}):
            with patch.dict(os.environ, {**env, **addition}, clear=True), self.assertRaises(w.SyncError):
                w.Settings.from_env()

    def test_plan_preserves_argo_dns_and_root_domains(self):
        plan = w.build_plan(self.cfg, self.empty, NETWORKS, PUBLIC)
        addresses = {row["address"] for row in plan.split if "address" in row}
        hosts = {row["host"] for row in plan.split if "host" in row}
        self.assertTrue(set(w.ARGO_EXCLUDE_IPS).issubset(addresses))
        self.assertTrue({"223.5.5.5/32", "119.29.29.29/32"}.issubset(addresses))
        self.assertTrue({"baidu.com", "*.baidu.com", "*.cn"}.issubset(hosts))
        self.assertNotIn("cn", hosts)
        self.assertLessEqual(len(plan.split) + len(plan.dns), 1000)
        for row in plan.dns:
            if row["description"] == w.AUTO_DNS_TAG:
                suffix = row["suffix"]
                self.assertTrue(any(host == "*." + suffix or
                                    (host.startswith("*.") and suffix.endswith("." + host[2:])) for host in hosts))
                if "." in suffix:
                    self.assertTrue(suffix in hosts or any(host.startswith("*.") and suffix.endswith("." + host[2:]) for host in hosts))

    def test_manual_rules_and_dns_override_survive(self):
        manual_split = {"address": "203.0.113.27/32", "description": "Private manual route"}
        manual_dns = {"suffix": "qq.com", "dns_server": ["192.0.2.53"], "description": "Private manual resolver"}
        plan = w.build_plan(self.cfg, w.State([manual_split], [manual_dns]), NETWORKS, PUBLIC)
        self.assertIn(manual_split, plan.split)
        self.assertIn(manual_dns, plan.dns)
        self.assertEqual(sum(row["suffix"] == "qq.com" for row in plan.dns), 1)

    def test_removing_secret_removes_owned_old_entry_only(self):
        old = w.State([
            {"address": "203.0.113.37/32", "description": "Private exclusion"},
            {"address": "203.0.113.38/32", "description": "Manual"},
        ], [])
        plan = w.build_plan(self.cfg, old, [], PUBLIC)
        addresses = {row.get("address") for row in plan.split}
        self.assertNotIn("203.0.113.37/32", addresses)
        self.assertIn("203.0.113.38/32", addresses)

    def test_private_ipv4_and_ipv6_are_reserved(self):
        cfg = replace(self.cfg, extra_excludes=("203.0.113.37/32", "2001:db8::7/128"))
        plan = w.build_plan(cfg, self.empty, NETWORKS, PUBLIC)
        addresses = {row.get("address") for row in plan.required_split}
        self.assertTrue(set(cfg.extra_excludes).issubset(addresses))

    def test_impossible_required_rules_fail_without_truncating(self):
        with self.assertRaises(w.SyncError):
            w.build_plan(replace(self.cfg, total_limit=10, fallback_target=1), self.empty, NETWORKS, PUBLIC)

    def test_largest_cn_blocks_win_without_broadening(self):
        cfg = replace(self.cfg, fallback_target=1)
        fixed = w.build_plan(cfg, self.empty, [], [])
        cfg = replace(cfg, total_limit=len(fixed.split) + len(fixed.dns) + 1)
        plan = w.build_plan(cfg, self.empty, NETWORKS, [])
        chosen = [row["address"] for row in plan.split if row["description"] == w.TAG_PREFIX + "cn-ip"]
        self.assertEqual(chosen, ["198.18.0.0/15"])

    def test_deterministic_input_order(self):
        first = w.build_plan(self.cfg, self.empty, NETWORKS, PUBLIC)
        second = w.build_plan(self.cfg, self.empty, list(reversed(NETWORKS)), list(reversed(PUBLIC)))
        self.assertEqual(first.split, second.split)
        self.assertEqual(first.dns, second.dns)

    def test_empty_or_invalid_sources_abort_before_api(self):
        for sources in ({**SOURCES, "ips": ""}, {**SOURCES, "ips": "invalid"},
                        {**SOURCES, "domains": "# only comments\nfull:example.com\n"}):
            client = FakeClient(self.empty)
            with self.assertRaises(w.SyncError):
                w.synchronize(self.cfg, sources=sources, client=client)
            self.assertEqual(client.writes, [])
            self.assertEqual(client.reads, 0)

    def test_download_failure_prevents_any_write(self):
        client = FakeClient(self.empty)
        with patch.object(w, "load_sources", side_effect=w.SyncError("Source unavailable")), self.assertRaises(w.SyncError):
            w.synchronize(self.cfg, client=client)
        self.assertEqual(client.writes, [])

    def test_domain_parser_respects_full_match_semantics(self):
        parsed = w.parse_domain_source("full:exact.example.com\ndomain:whole.example.com\n*.other.example.com\n192.0.2.1\nregexp:.*\n")
        self.assertEqual(set(parsed), {"whole.example.com", "other.example.com"})

    def test_real_sync_is_idempotent_and_does_not_print_secrets(self):
        cfg = replace(self.cfg, extra_excludes=("203.0.113.37/32",))
        client = FakeClient(self.empty)
        _, first_log = self.quiet(w.synchronize, cfg, sources=SOURCES, client=client)
        writes = len(client.writes)
        _, second_log = self.quiet(w.synchronize, cfg, sources=SOURCES, client=client)
        self.assertEqual(len(client.writes), writes)
        self.assertNotIn("203.0.113.37", first_log + second_log)
        self.assertIn("无需写入", second_log)

    def test_dry_run_never_writes(self):
        client = FakeClient(self.empty)
        self.quiet(w.synchronize, self.cfg, sources=SOURCES, client=client, dry_run=True)
        self.assertEqual(client.writes, [])

    def test_migration_from_1400_uses_safe_bridge(self):
        current = w.State(split_rows(1000), dns_entries(400))
        new_split, new_dns = split_rows(800), dns_entries(200)
        plan = w.Plan(new_split, new_dns, new_split[:29], new_dns[:14])
        client = FakeClient(current)
        self.quiet(w.apply_plan, client, current, plan, 1000)
        self.assertEqual([(kind, len(rows)) for kind, rows in client.writes], [("split", 600), ("dns", 200), ("split", 800)])
        for kind, rows in client.writes:
            required = plan.required_split if kind == "split" else plan.required_dns
            self.assertTrue(all(item in rows for item in required))
        self.assertTrue(client.state.equivalent(plan.state))

    def test_update_order_reserves_space(self):
        current = w.State(split_rows(600), dns_entries(400))
        plan = w.Plan(split_rows(800), dns_entries(200), [], [])
        self.assertEqual([kind for kind, _ in w.update_steps(current, plan, 1000)], ["dns", "split"])
        reverse = w.Plan(current.split, current.dns, [], [])
        self.assertEqual([kind for kind, _ in w.update_steps(plan.state, reverse, 1000)], ["split", "dns"])

    def test_concurrent_change_stops_before_put(self):
        plan = w.build_plan(self.cfg, self.empty, NETWORKS, PUBLIC)
        client = FakeClient(self.empty)
        client.change_on_read = 1
        with self.assertRaises(w.SyncError):
            w.apply_plan(client, self.empty, plan, 1000)
        self.assertEqual(client.writes, [])

    def test_unconfirmed_write_stops_before_next_update(self):
        plan = w.build_plan(self.cfg, self.empty, NETWORKS, PUBLIC)
        client = FakeClient(self.empty)
        client.ignore_writes = True
        with self.assertRaises(w.SyncError) as error:
            w.apply_plan(client, self.empty, plan, 1000)
        self.assertEqual(len(client.writes), 1)
        self.assertIn("未全部完成", str(error.exception))

    def test_partial_failure_is_not_reported_as_success(self):
        current = w.State(split_rows(1000), dns_entries(400))
        plan = w.Plan(split_rows(800), dns_entries(200), split_rows(29), dns_entries(14))
        client = FakeClient(current)
        client.fail_write = 2
        with self.assertRaises(w.SyncError):
            w.apply_plan(client, current, plan, 1000)
        self.assertEqual(len(client.writes), 2)
        self.assertEqual(len(client.state.split), 600)

    def test_fallback_only_keeps_split_and_obeys_shared_budget(self):
        full = w.build_plan(self.cfg, self.empty, NETWORKS, PUBLIC)
        current = full.state
        plan = w.build_plan(self.cfg, current, [], list(reversed(PUBLIC)), scope="fallback")
        self.assertEqual(plan.split, current.split)
        self.assertLessEqual(len(plan.dns) + len(current.split), 1000)

    def test_fallback_only_requires_dns_ip_exclusion(self):
        with self.assertRaises(w.SyncError):
            w.build_plan(self.cfg, self.empty, [], PUBLIC, scope="fallback")

    def response(self, status=200, data=None):
        response = Mock(status_code=status)
        response.json.return_value = {"success": True, "result": []} if data is None else data
        return response

    def test_http_200_failure_and_bad_result_are_rejected(self):
        for data in ({"success": False, "errors": [{"message": "DO-NOT-LOG"}]},
                     {"success": True}, {"success": True, "result": {}}):
            session = Mock()
            session.request.return_value = self.response(data=data)
            client = w.CloudflareClient(self.cfg, session=session)
            with self.assertRaises(w.SyncError) as error:
                client.read_state()
            self.assertNotIn("DO-NOT-LOG", str(error.exception))

    def test_api_404_does_not_switch_profile(self):
        session = Mock()
        session.request.return_value = self.response(status=404)
        client = w.CloudflareClient(replace(self.cfg, profile_id="chosen-profile"), session=session)
        with self.assertRaises(w.SyncError):
            client.read_state()
        self.assertEqual(session.request.call_count, 1)
        self.assertIn("/chosen-profile/exclude", session.request.call_args.args[1])

    def test_writes_use_put_timeout_and_validate_success(self):
        session = Mock()
        session.request.return_value = self.response(data={"success": False, "errors": [{"message": "PRIVATE-DATA"}]})
        client = w.CloudflareClient(self.cfg, session=session)
        with self.assertRaises(w.SyncError) as error:
            client.write("dns", [])
        self.assertEqual(session.request.call_args.args[0], "PUT")
        self.assertEqual(session.request.call_args.kwargs["timeout"], w.TIMEOUT)
        self.assertEqual(session.request.call_count, 1)
        self.assertNotIn("PRIVATE-DATA", str(error.exception))

    def test_network_and_json_errors_do_not_echo_private_values(self):
        session = Mock()
        client = w.CloudflareClient(self.cfg, session=session)
        session.request.side_effect = requests.ConnectionError("PRIVATE-DATA")
        with self.assertRaises(w.SyncError) as error:
            client.write("dns", [])
        self.assertNotIn("PRIVATE-DATA", str(error.exception))
        session.request.side_effect = None
        response = self.response()
        response.json.side_effect = ValueError("PRIVATE-DATA")
        session.request.return_value = response
        with self.assertRaises(w.SyncError) as error:
            client.read_state()
        self.assertNotIn("PRIVATE-DATA", str(error.exception))

    def test_204_write_acknowledgement_is_supported(self):
        session = Mock()
        session.request.return_value = self.response(status=204)
        w.CloudflareClient(self.cfg, session=session).write("dns", [])

    def test_public_fetch_never_uses_api_authorization(self):
        response = self.response()
        response.text = "example.com"
        with patch.object(requests, "get", return_value=response) as get:
            self.assertEqual(w.download_source("test", "https://example.com/list"), "example.com")
        self.assertNotIn("headers", get.call_args.kwargs)

    def test_malformed_existing_config_aborts_safely(self):
        with self.assertRaises(w.SyncError):
            w.normalize_split([{"address": "192.0.2.1", "host": "example.com"}])
        with self.assertRaises(w.SyncError):
            w.normalize_dns([{"suffix": "private.example.invalid", "dns_server": "192.0.2.53"}])


if __name__ == "__main__":
    unittest.main()
