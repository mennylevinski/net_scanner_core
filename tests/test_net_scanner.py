"""Unit tests for Net Scanner Core (fully mocked, no live network required)."""

import csv
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import types
import unittest
from unittest import mock

import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import net_scanner as ns  # noqa: E402
from scanner import discovery, export, http_probe as http_mod, inspector, network, ports, smb  # noqa: E402


class TestConfigAndPortsSync(unittest.TestCase):
    def test_ports_md_matches_code(self):
        ports_md_path = os.path.join(REPO_ROOT, "PORTS.md")
        with open(ports_md_path, "r", encoding="utf-8") as f:
            content = f.read()

        doc_tcp = set()
        doc_udp = set()
        for line in content.splitlines():
            m = re.match(r"^\|\s*(\d+)\s*\|\s*([A-Z/]+)\s*\|", line)
            if not m:
                continue
            p = int(m.group(1))
            proto = m.group(2).upper()
            if "TCP" in proto:
                doc_tcp.add(p)
            if "UDP" in proto:
                doc_udp.add(p)

        self.assertEqual(set(ns.COMMON_PORTS_TCP), doc_tcp)
        self.assertEqual(set(ns.COMMON_PORTS_UDP), doc_udp)

    def test_risky_port_highlighting(self):
        out = ns._highlight_risky_ports(["22/tcp", "23/tcp", "445/tcp", "53/udp", 3389, 80])
        self.assertEqual(
            out,
            ["22/tcp", "23/tcp(Telnet)", "445/tcp(SMB)", "53/udp", "3389(RDP)", "80"],
        )


class TestNetworkUtilities(unittest.TestCase):
    def test_parse_target_ips_single_range_and_cidr(self):
        self.assertEqual(ns._parse_target_ips("192.168.1.5"), ["192.168.1.5"])
        self.assertEqual(
            ns._parse_target_ips("192.168.1.1-192.168.1.3"),
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        )
        self.assertEqual(
            ns._parse_target_ips("192.168.1.0/30"),
            ["192.168.1.1", "192.168.1.2"],
        )
        with self.assertRaises(ValueError):
            ns._parse_target_ips("192.168.1.10-192.168.1.5")
        with self.assertRaises(ValueError):
            ns._parse_target_ips("10.0.0.0/16")

    def test_clamp_subnet(self):
        big = ipaddress.ip_network("10.0.0.0/16")
        self.assertEqual(
            ns._clamp_subnet(big, local_ip="10.0.5.42"),
            ipaddress.ip_network("10.0.5.0/24"),
        )
        self.assertIsNone(ns._clamp_subnet(big, local_ip=None))
        small = ipaddress.ip_network("192.168.1.0/24")
        self.assertEqual(ns._clamp_subnet(small, local_ip="192.168.1.5"), small)

    def test_parse_arp_output_windows_and_linux(self):
        win_out = (
            "Interface: 192.168.1.10 --- 0x6\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           AA-BB-CC-DD-EE-FF     dynamic\n"
        )
        self.assertEqual(
            ns._parse_arp_output(win_out, is_windows=True),
            {"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
        )

        ip_neigh_out = (
            "192.168.1.1 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
            "192.168.1.2 dev eth0 FAILED\n"
        )
        self.assertEqual(
            ns._parse_arp_output(ip_neigh_out, is_windows=False),
            {"192.168.1.1": "11:22:33:44:55:66"},
        )

        arp_a_out = "? (192.168.1.5) at aa:bb:cc:11:22:33 [ether] on wlan0\n"
        self.assertEqual(
            ns._parse_arp_output(arp_a_out, is_windows=False),
            {"192.168.1.5": "aa:bb:cc:11:22:33"},
        )

    def test_offline_interface_fallback_and_primary_mac(self):
        af_link = getattr(network.psutil, "AF_LINK", -1)
        fake_addrs = {
            "lo": [types.SimpleNamespace(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0")],
            "eth0": [
                types.SimpleNamespace(family=socket.AF_INET, address="192.168.50.10", netmask="255.255.255.0"),
                types.SimpleNamespace(family=af_link, address="AA-BB-CC-11-22-33", netmask=None),
            ],
        }
        fake_stats = {
            "lo": types.SimpleNamespace(isup=True),
            "eth0": types.SimpleNamespace(isup=True),
        }
        with mock.patch("scanner.network.psutil.net_if_addrs", return_value=fake_addrs), \
             mock.patch("scanner.network.psutil.net_if_stats", return_value=fake_stats), \
             mock.patch("scanner.network.socket.socket") as mock_sock:
            mock_sock.return_value.__enter__.return_value.connect.side_effect = OSError("No route")
            iface, ip = network._get_default_interface_and_ip()
            self.assertEqual((iface, ip), ("eth0", "192.168.50.10"))
            self.assertEqual(network._primary_mac(iface), "aa:bb:cc:11:22:33")


class TestPortScanner(unittest.TestCase):
    def test_dual_protocol_scan_and_tags(self):
        with mock.patch("scanner.ports._probe_tcp", side_effect=lambda ip, p, t: p in (53, 80)), \
             mock.patch("scanner.ports._probe_udp", side_effect=lambda ip, p, t: p in (53, 1434)):
            res = ports._scan_ports("192.168.1.1", [53, 80, 1434], include_proto=True)
            self.assertEqual(res, ["53/tcp", "53/udp", "80/tcp", "1434/udp"])

            res_ints = ports._scan_ports("192.168.1.1", [53, 80, 1434], include_proto=False)
            self.assertEqual(res_ints, [53, 80, 1434])


class TestHttpAndSmb(unittest.TestCase):
    def test_http_probe_head_405_fallback_and_ssl_retry(self):
        head_resp = types.SimpleNamespace(status_code=405, headers={})
        get_resp = mock.MagicMock()
        get_resp.__enter__.return_value = types.SimpleNamespace(status_code=200, headers={"Server": "nginx"})

        with mock.patch("scanner.http_probe._port_open_fast", side_effect=lambda ip, p, timeout: p == 80), \
             mock.patch("scanner.http_probe.requests.head", return_value=head_resp), \
             mock.patch("scanner.http_probe.requests.get", return_value=get_resp):
            hit = http_mod.http_probe("192.168.1.1")
            self.assertEqual(hit, {"url": "http://192.168.1.1", "status": 200, "server": "nginx"})

        # SSL error on 8443 should genuinely retry as http://ip:8443
        ok_resp = types.SimpleNamespace(status_code=200, headers={"Server": "AdminUI"})

        def fake_head(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.SSLError("not TLS")
            return ok_resp

        with mock.patch("scanner.http_probe._port_open_fast", side_effect=lambda ip, p, timeout: p == 8443), \
             mock.patch("scanner.http_probe.requests.head", side_effect=fake_head):
            hit = http_mod.http_probe("192.168.1.1")
            self.assertEqual(hit, {"url": "http://192.168.1.1:8443", "status": 200, "server": "AdminUI"})

    def test_http_scan_parses_arp_after_ping(self):
        call_order = []

        def fake_ping(ip):
            call_order.append(("ping", ip))
            return False

        def fake_arp():
            call_order.append(("arp",))
            return {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

        def fake_probe(ip, timeout=2.0, find_all=True):
            return [{"url": f"http://{ip}", "status": 200, "server": "Router"}]

        net = ipaddress.ip_network("192.168.1.0/30")
        with mock.patch("scanner.http_probe._ping", side_effect=fake_ping), \
             mock.patch("scanner.http_probe._parse_arp_table", side_effect=fake_arp), \
             mock.patch("scanner.http_probe.http_probe", side_effect=fake_probe):
            results = http_mod.http_scan_subnet(net)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["url"], "http://192.168.1.1")
            arp_idx = call_order.index(("arp",))
            last_ping_idx = max(i for i, item in enumerate(call_order) if item[0] == "ping")
            self.assertGreater(arp_idx, last_ping_idx)

    def test_smb_parsers(self):
        win_out = (
            "Shared resources at \\\\192.168.1.5\n\n"
            "Share name  Type  Used as  Comment\n"
            "-----------------------------------\n"
            "Public      Disk\n"
            "ADMIN$      Disk           Remote Admin\n"
            "The command completed successfully.\n"
        )
        self.assertEqual(smb._parse_net_view_shares(win_out), ["Public"])

        linux_out = (
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tMedia           Disk      Shared media\n"
            "\tIPC$            IPC       IPC Service\n"
        )
        self.assertEqual(smb._parse_smbclient_shares(linux_out), ["Media"])


class TestInspectorAndDiscovery(unittest.TestCase):
    def test_noise_filter_and_process_name_and_direction(self):
        addr = lambda ip, port: types.SimpleNamespace(ip=ip, port=port)
        udp_ok = types.SimpleNamespace(
            type=socket.SOCK_DGRAM,
            status="NONE",
            laddr=addr("192.168.1.10", 55000),
            raddr=addr("8.8.8.8", 443),
        )
        self.assertFalse(inspector._is_noise_traffic(udp_ok))

        udp_unbound = types.SimpleNamespace(
            type=socket.SOCK_DGRAM, status="NONE", laddr=addr("192.168.1.10", 55000), raddr=None
        )
        self.assertTrue(inspector._is_noise_traffic(udp_unbound))
        self.assertEqual(inspector._get_process_name(None), "N/A")

        # Non-/24 office subnet (/22) accurately classifies cross-/24 peer as LAN
        office_sub = ipaddress.ip_network("10.10.0.0/22")
        self.assertEqual(inspector._detect_direction("10.10.1.5", "10.10.2.8", office_sub), "LAN")
        self.assertEqual(inspector._detect_direction("10.10.1.5", "8.8.8.8", office_sub), "OUT")
        self.assertEqual(
            inspector._detect_direction("10.10.1.5", "8.8.8.8", office_sub, is_server_side=True),
            "IN",
        )

    def test_inspector_respects_timeout_without_hanging(self):
        with mock.patch("scanner.inspector.psutil.net_connections", return_value=[]):
            stop_ev, thread = inspector.start_connection_inspector(
                interval=0.05,
                timeout=1,
                local_subnet=ipaddress.ip_network("192.168.1.0/24"),
            )
            thread.join(timeout=2.5)
            self.assertFalse(thread.is_alive())
            self.assertTrue(stop_ev.is_set())

    def test_apipa_guard_blocks_guess_by_default(self):
        self.assertEqual(discovery.discover_network(None, local_ip="169.254.1.5"), [])
        self.assertEqual(export.test_print(None, local_ip="169.254.1.5"), [])


class TestExportAndCli(unittest.TestCase):
    def test_exports_json_csv_txt(self):
        records = [
            {"ip": "192.168.1.1", "hostname": "router", "mac": "aa:bb:cc:dd:ee:ff", "alive": True, "open_ports": ["80/tcp", "53/udp"]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "out.json")
            csv_path = os.path.join(tmp, "out.csv")
            txt_path = os.path.join(tmp, "out.txt")

            export.export_results(records, fmt="json", path=json_path)
            with open(json_path, "r", encoding="utf-8") as f:
                self.assertEqual(json.load(f), records)

            export.export_results(records, fmt="csv", path=csv_path)
            with open(csv_path, "r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["ip"], "192.168.1.1")
            self.assertEqual(rows[0]["open_ports"], "80/tcp; 53/udp")

            export.log_buffer.write("sample line\n")
            export.export_results(records, fmt="txt", path=txt_path, clear_buffer=True)
            with open(txt_path, "r", encoding="utf-8") as f:
                self.assertIn("sample line", f.read())
            self.assertEqual(export.log_buffer.getvalue(), "")

    def test_cli_arg_parser(self):
        parser = ns.build_arg_parser()
        args = parser.parse_args(
            ["--range", "192.168.1.0/24", "--fast", "--ports", "22,80,443", "--output", "res.json"]
        )
        self.assertEqual(args.range, "192.168.1.0/24")
        self.assertTrue(args.fast)
        self.assertEqual(args.ports, "22,80,443")
        self.assertEqual(args.output, "res.json")

        flow_args = parser.parse_args(["--flow", "--timeout", "15", "--interval", "0.2", "--log"])
        self.assertTrue(flow_args.flow)
        self.assertEqual(flow_args.timeout, 15)
        self.assertAlmostEqual(flow_args.interval, 0.2)
        self.assertEqual(flow_args.log, "scan.log")

    def test_interactive_command_parsing(self):
        # Case-insensitive flags while preserving output filename casing
        kind, args = ns.parse_interactive_command(
            "SCAN --RANGE 192.168.1.0/24 --Fast --Ports 22,80 --Output MyReport.json"
        )
        self.assertEqual(kind, "scan")
        self.assertEqual(args.range, "192.168.1.0/24")
        self.assertTrue(args.fast)
        self.assertEqual(args.ports, "22,80")
        self.assertEqual(args.output, "MyReport.json")

        # Bare `scan --range` uses interactive prompt callback
        kind, args = ns.parse_interactive_command(
            "scan --range --fast",
            prompt_range_target=lambda: "192.168.1.10",
        )
        self.assertEqual(kind, "scan")
        self.assertEqual(args.range, "192.168.1.10")
        self.assertTrue(args.fast)

        # Export command (with and without explicit path)
        self.assertEqual(ns.parse_interactive_command("export json"), ("export", ("json", None)))
        self.assertEqual(
            ns.parse_interactive_command("EXPORT CSV OutFile.csv"),
            ("export", ("csv", "OutFile.csv")),
        )

        # Legacy `scan -L` removed -> returns error without raising SystemExit
        kind, _ = ns.parse_interactive_command("scan -L")
        self.assertEqual(kind, "error")

        # Help and exit
        self.assertEqual(ns.parse_interactive_command("HELP"), ("help", None))
        self.assertEqual(ns.parse_interactive_command("exit"), ("exit", None))

    def test_maximize_console_guards_and_posix_sequence(self):
        fake_non_tty = mock.MagicMock()
        fake_non_tty.isatty.return_value = False
        with mock.patch("scanner.export.sys.stdout", fake_non_tty):
            self.assertFalse(export.maximize_console())

        fake_tty = mock.MagicMock()
        fake_tty.isatty.return_value = True
        with mock.patch("scanner.export.sys.stdout", fake_tty), \
             mock.patch.dict(os.environ, {"TERM_PROGRAM": "vscode"}, clear=False):
            self.assertFalse(export.maximize_console())

        with mock.patch("scanner.export.sys.stdout", fake_tty), \
             mock.patch("scanner.export.sys.platform", "linux"), \
             mock.patch.dict(os.environ, {"TERM_PROGRAM": "", "VSCODE_INJECTION": "", "TERMINAL_EMULATOR": ""}, clear=False):
            self.assertTrue(export.maximize_console())
            fake_tty.write.assert_called_once_with("\x1b[9;1t")
            fake_tty.flush.assert_called_once()


if __name__ == "__main__":
    unittest.main()
