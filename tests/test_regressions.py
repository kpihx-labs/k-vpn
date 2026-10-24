"""Offline regression tests; never launch root commands or live tunnels."""

import base64
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from typer.testing import CliRunner

from k_vpn import config, probes, profiles
from k_vpn import main as vpn

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def rendered_text(output: str) -> str:
    """Normalize Rich terminal formatting for content assertions."""
    return " ".join(ANSI_ESCAPE.sub("", output).split())


class ProfileTests(unittest.TestCase):
    def command(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ovpn"
            path.write_text(text)
            return vpn.build_ovpn_cmd(
                str(path), "/unused-public-vpngate-credentials", False
            )

    def test_historical_vpngate_credentials_without_profile_directive(self):
        self.assertIn("--auth-user-pass", self.command("client\nproto tcp\n"))

    def test_requested_auth_retained(self):
        self.assertIn("--auth-user-pass", self.command("client\nauth-user-pass\n"))

    def test_commented_auth_cannot_override_credentials(self):
        command = self.command("# auth-user-pass /untrusted\n")
        self.assertNotIn("/untrusted", command)
        self.assertEqual(
            command[command.index("--auth-user-pass") + 1],
            "/unused-public-vpngate-credentials",
        )

    def test_legacy_cipher_only_when_profile_requests_it(self):
        self.assertIn("--data-ciphers-fallback", self.command("cipher AES-128-CBC\n"))
        self.assertNotIn("--data-ciphers-fallback", self.command("client\n"))

    def test_interactive_sudo_is_preserved(self):
        self.assertEqual(self.command("client\n")[:2], ["sudo", "openvpn"])

    def test_server_role_validation_enabled(self):
        self.assertIn("--remote-cert-tls", self.command("client\n"))

    def test_commented_udp_does_not_override_tcp(self):
        profile = b"# proto udp\nproto tcp-client\nremote relay.test 443\n"
        self.assertFalse(vpn.config_is_udp(profile))
        self.assertEqual(vpn.get_config_priority(base64.b64encode(profile).decode()), 2)

    def test_multi_remote_parsing(self):
        self.assertEqual(
            profiles.remotes(
                "proto tcp-client\nremote a.test 443\nremote b.test 1234 udp\n"
            ),
            [("a.test", 443, "tcp"), ("b.test", 1234, "udp")],
        )

    def test_public_profile_hooks_rejected(self):
        for directive in (
            "up /tmp/untrusted",
            "plugin /tmp/untrusted.so",
            "config /etc/openvpn/other",
            "log /etc/overwritten",
        ):
            with self.subTest(directive=directive), self.assertRaises(ValueError):
                profiles.validate(f"client\n{directive}\n")

    def test_inline_certificates_are_allowed(self):
        profiles.validate("client\n<ca>\nCERTIFICATE\n</ca>\n")

    def test_external_key_reference_rejected(self):
        with self.assertRaises(ValueError):
            profiles.validate("key /private.key\n")

    def test_buffered_ready_message(self):
        class Process:
            stdout = io.StringIO("log\nInitialization Sequence Completed\n")

        self.assertTrue(vpn._wait_connected(Process(), timeout=0.5))

    def test_eof_before_ready(self):
        class Process:
            stdout = io.StringIO("AUTH_FAILED\n")

        self.assertFalse(vpn._wait_connected(Process(), timeout=0.5))

    def test_benchmark_always_cleans_on_interrupt(self):
        with (
            patch.object(
                vpn, "_openvpn_start", return_value=(object(), "cfg", "creds")
            ),
            patch.object(vpn, "_wait_connected", side_effect=KeyboardInterrupt),
            patch.object(vpn, "_cleanup_session") as cleanup,
        ):
            with self.assertRaises(KeyboardInterrupt):
                vpn._bench_one({}, "/unused")
            cleanup.assert_called_once()

    def test_management_shutdown_waits_for_ack_without_new_sudo(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        process._vpn_management_socket = "/unused-owned-control.sock"
        connection = Mock()
        connection.recv.side_effect = [
            b">INFO:ready\n",
            b"SUCCESS: signal SIGTERM thrown\n",
        ]
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with (
            patch.object(vpn.socket, "socket", return_value=context),
            patch.object(vpn.subprocess, "run") as privileged,
        ):
            vpn._cleanup_session(process, None, None)
            privileged.assert_not_called()
        self.assertEqual(connection.recv.call_count, 2)
        connection.sendall.assert_called_once_with(b"signal SIGTERM\n")

    def test_final_connection_cleans_on_interrupt_during_handshake(self):
        with (
            patch.object(
                vpn, "_openvpn_start", return_value=(object(), "cfg", "creds")
            ),
            patch.object(vpn, "_wait_connected", side_effect=KeyboardInterrupt),
            patch.object(vpn, "_cleanup_session") as cleanup,
        ):
            self.assertTrue(vpn._run_session({}, "/unused", "Japan", 1))
            cleanup.assert_called_once()


class XDGTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir()
        self.runtime = Path(self.temporary.name) / "runtime"
        self.runtime.mkdir()
        self.environment = patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "XDG_CONFIG_HOME": "",
                "XDG_CACHE_HOME": "",
                "XDG_RUNTIME_DIR": str(self.runtime),
            },
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_paths_follow_linux_defaults_without_creating_files(self):
        self.assertEqual(config.config_file(), self.home / ".config/k-vpn/config.json")
        self.assertEqual(
            config.cache_file(), self.home / ".cache/k-vpn/measurements.json"
        )
        self.assertEqual(config.load(), config.Settings())
        self.assertEqual(list(self.home.iterdir()), [])

    def test_configuration_created_once_with_private_permissions(self):
        config.initialize()
        path = config.config_file()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_text(
            '{"bench": 2, "min_speed": 0.2, "tuning": "balanced", "strict_discovery": true}'
        )
        config.initialize()
        self.assertEqual(config.load().tuning, "balanced")
        self.assertTrue(config.load().strict_discovery)
        self.assertIn('"bench": 2', path.read_text())

    def test_xdg_overrides(self):
        with patch.dict(
            os.environ,
            {
                "XDG_CONFIG_HOME": str(self.home / "cfg"),
                "XDG_CACHE_HOME": str(self.home / "cache"),
            },
        ):
            config.initialize()
            vpn.save_bench_cache({"test": {"speed": 1}})
            self.assertTrue((self.home / "cfg/k-vpn/config.json").is_file())
            self.assertTrue((self.home / "cache/k-vpn/measurements.json").is_file())
            self.assertEqual({p.name for p in self.home.iterdir()}, {"cfg", "cache"})

    def test_xdg_cannot_create_an_application_directory_at_home_root(self):
        with patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.home), "XDG_CACHE_HOME": str(self.home)},
        ):
            self.assertEqual(config.config_file().parent, self.home / ".config/k-vpn")
            self.assertEqual(config.cache_file().parent, self.home / ".cache/k-vpn")

    def test_temporary_profiles_cleaned_on_error(self):
        path = None
        with self.assertRaises(RuntimeError), config.session_directory() as directory:
            path = Path(directory)
            self.assertEqual(path.parent, self.runtime)
            (path / "test.ovpn").write_text("client\n")
            raise RuntimeError("cancelled")
        self.assertIsNotNone(path)
        self.assertFalse(path.exists())

    def test_session_wrapper_cleans_private_directory(self):
        observed = []

        def inner(*arguments, **kwargs):
            observed.append(Path(arguments[-1]))
            self.assertTrue(observed[-1].is_dir())
            raise RuntimeError("cancelled")

        with (
            patch.object(vpn, "_connect_to_country", side_effect=inner),
            self.assertRaises(RuntimeError),
        ):
            vpn.connect_to_country("Japan", [])
        self.assertFalse(observed[0].exists())

    def test_help_does_not_create_user_configuration(self):
        result = CliRunner().invoke(vpn.app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_connect_missing_openvpn_stops_before_discovery(self):
        with (
            patch.object(vpn.shutil, "which", return_value=None),
            patch.object(vpn, "fetch_vpn_servers") as fetch,
        ):
            result = CliRunner().invoke(vpn.app, ["connect", "-c", "JP"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("sudo apt install openvpn", rendered_text(result.output))
        fetch.assert_not_called()

    def test_doctor_never_invokes_sudo(self):
        with (
            patch.object(vpn.shutil, "which", return_value=None),
            patch.object(vpn.subprocess, "run") as run,
        ):
            result = CliRunner().invoke(vpn.app, ["doctor"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("openvpn", result.output)
        run.assert_not_called()

    def test_cli_overrides_configuration_including_zero(self):
        config.initialize()
        config.config_file().write_text('{"bench": 9, "min_speed": 4}')
        relay = {"CountryLong": "Japan", "CountryShort": "JP"}
        with (
            patch.object(vpn, "fetch_vpn_servers", return_value=[relay]),
            patch.object(vpn, "connect_to_country") as connect,
        ):
            result = CliRunner().invoke(
                vpn.app,
                [
                    "connect",
                    "--country",
                    "JP",
                    "--bench",
                    "1",
                    "--min-speed",
                    "0",
                    "--test-only",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(connect.call_args.args[2:5], (1, 0.0, True))

    def test_unknown_or_invalid_settings_are_rejected(self):
        config.initialize()
        for payload in (
            {"attempts": 0},
            {"attempts": -1},
            {"attempts": True},
            {"tuning": "magic"},
            {"strict_discovery": "yes"},
            {"unknown": 1},
            [],
        ):
            with self.subTest(payload=payload):
                config.config_file().write_text(json.dumps(payload))
                with self.assertRaises((ValueError, TypeError)):
                    config.load()

    def test_cli_attempts_override_persistent_preference(self):
        config.initialize()
        config.config_file().write_text('{"attempts": 2}')
        relay = {"CountryLong": "Japan", "CountryShort": "JP"}
        with (
            patch.object(vpn, "fetch_vpn_servers", return_value=[relay]),
            patch.object(vpn, "connect_to_country") as connect,
        ):
            result = CliRunner().invoke(
                vpn.app, ["connect", "--country", "JP", "--attempts", "12"]
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(connect.call_args.kwargs["attempts"], 12)

    def test_short_options_match_long_connection_options(self):
        relay = {"CountryLong": "Japan", "CountryShort": "JP"}
        with (
            patch.object(vpn, "fetch_vpn_servers", return_value=[relay]),
            patch.object(vpn, "connect_to_country") as connect,
        ):
            result = CliRunner().invoke(
                vpn.app,
                [
                    "connect",
                    "-c",
                    "JP",
                    "-a",
                    "7",
                    "-b",
                    "1",
                    "-m",
                    "0",
                    "-t",
                    "-T",
                    "native",
                    "-D",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(connect.call_args.args[2:5], (1, 0.0, True))
        self.assertEqual(connect.call_args.kwargs["attempts"], 7)

    def test_old_generated_settings_cannot_enable_automatic_measurements(self):
        config.initialize()
        config.config_file().write_text('{"bench": 10, "min_speed": 3.0}')
        relay = {"CountryLong": "Japan", "CountryShort": "JP"}
        with (
            patch.object(vpn, "fetch_vpn_servers", return_value=[relay]),
            patch.object(vpn, "connect_to_country") as connect,
        ):
            result = CliRunner().invoke(vpn.app, ["connect", "--country", "JP"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(connect.call_args.args[2:5], (0, 0.0, False))

    def test_generated_configuration_has_no_auto_measurement_preferences(self):
        config.initialize()
        self.assertEqual(
            set(json.loads(config.config_file().read_text())),
            {"attempts", "tuning", "strict_discovery"},
        )

    def test_interactive_connection_does_not_promise_a_benchmark(self):
        relay = {"CountryLong": "Japan", "CountryShort": "JP", "Speed": "100"}
        with (
            patch.object(vpn, "fetch_vpn_servers", return_value=[relay]),
            patch.object(vpn, "connect_to_country") as connect,
            patch.object(vpn, "load_bench_cache", return_value={}),
        ):
            result = CliRunner().invoke(vpn.app, ["connect"], input="1\n")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("no benchmark", rendered_text(result.output))
        self.assertEqual(connect.call_args.kwargs["bench"], 0)
        self.assertEqual(connect.call_args.kwargs["min_speed"], 0)

    def test_status_observes_active_route_without_starting_a_measurement(self):
        route = probes.Route("tailscale0", "100.82.95.70", "")
        with (
            patch.object(vpn.probes, "active_route", return_value=route),
            patch.object(vpn.probes, "public_ip", return_value="1.2.3.4"),
            patch.object(
                vpn.probes,
                "geolocate",
                return_value={
                    "country": "France",
                    "country_code": "FR",
                    "city": "Paris",
                    "isp": "Example ISP",
                },
            ),
            patch.object(vpn.probes, "measure_active_route") as measure,
        ):
            result = CliRunner().invoke(vpn.app, ["status"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("tailscale0", result.output)
        self.assertIn("1.2.3.4", result.output)
        measure.assert_not_called()

    def test_status_measures_only_when_explicitly_requested(self):
        route = probes.Route("wlp0s20f3", "192.0.2.1", "192.0.2.254")
        measured = probes.Measurement(
            "VERIFIED",
            mbps=42.0,
            bytes_received=1_000_000,
            elapsed_s=0.2,
            endpoint="https://example.test/download",
        )
        with (
            patch.object(vpn.probes, "active_route", return_value=route),
            patch.object(vpn.probes, "public_ip", return_value="1.2.3.4"),
            patch.object(vpn.probes, "geolocate", return_value={}),
            patch.object(
                vpn.probes, "measure_active_route", return_value=measured
            ) as measure,
            patch.object(
                vpn.probes, "measure_upload_active_route", return_value=measured
            ) as upload,
        ):
            result = CliRunner().invoke(vpn.app, ["status", "-s", "-n", "4"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("42.00 Mbps", result.output)
        measure.assert_called_once_with(4)
        upload.assert_called_once_with(4)


class ConnectionBehaviorTests(unittest.TestCase):
    def relay(self):
        return {
            "IP": "1.2.3.4",
            "Speed": "100",
            "OpenVPN_ConfigData_Base64": base64.b64encode(
                b"client\nproto tcp\nremote 1.2.3.4 443\n"
            ).decode(),
        }

    def test_normal_connection_never_calls_measurement_or_ip_services(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(
                vpn.probes,
                "public_ip",
                side_effect=AssertionError("Unexpected IP service"),
            ),
            patch.object(
                vpn.probes, "measure", side_effect=AssertionError("Unexpected transfer")
            ),
            patch.object(
                vpn, "_bench_one", side_effect=AssertionError("Unexpected benchmark")
            ),
            patch.object(vpn, "_run_session", return_value=True) as connect,
        ):
            vpn._connect_to_country("Japan", [self.relay()], 0, 0, False, directory)
            connect.assert_called_once()

    def test_historical_score_order_overrides_port_and_advertised_speed(self):
        high_score = dict(
            self.relay(),
            IP="2.3.4.5",
            Score="100",
            Speed="1",
            priority=10,
            OpenVPN_ConfigData_Base64=base64.b64encode(
                b"client\nproto tcp\nremote 2.3.4.5 1223\n"
            ).decode(),
        )
        high_reported_speed = dict(
            self.relay(), Score="1", Speed="9999999999", priority=1
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vpn, "_run_session", return_value=True) as connect,
        ):
            vpn._connect_to_country(
                "Japan", [high_reported_speed, high_score], 0, 0, False, directory
            )
        self.assertEqual(connect.call_args.args[0]["IP"], "2.3.4.5")

    def test_requested_relay_attempt_budget_is_respected(self):
        servers = [
            dict(self.relay(), IP=f"1.2.3.{n}", Score=str(n)) for n in range(1, 5)
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vpn, "_run_session", return_value=False) as connect,
            vpn.console.capture() as output,
        ):
            vpn._connect_to_country(
                "Japan", servers, 0, 0, False, directory, attempts=2
            )
        self.assertEqual(connect.call_count, 2)
        rendered = rendered_text(output.get())
        self.assertIn("All 2 connection attempts failed", rendered)
        self.assertIn("4 relays were listed", rendered)

    def test_normal_session_waits_without_a_speed_probe(self):
        process = Mock()
        with (
            patch.object(vpn, "_openvpn_start", return_value=(process, "cfg", "creds")),
            patch.object(vpn, "_wait_connected", return_value=True),
            patch.object(
                vpn.probes, "measure", side_effect=AssertionError("Unexpected transfer")
            ),
            patch.object(vpn, "_cleanup_session") as cleanup,
            vpn.console.capture() as output,
        ):
            self.assertFalse(vpn._run_session(self.relay(), "/unused", "Japan", 0))
        process.wait.assert_called_once()
        cleanup.assert_called_once()
        self.assertIn("OPENVPN TUNNEL ESTABLISHED", output.get())
        self.assertNotIn("HTTPS EGRESS VERIFIED", output.get())

    def test_explicit_benchmark_still_runs_and_test_only_never_connects(self):
        relay = self.relay()

        def benchmark(server, directory):
            server["_last_result"] = {"status": "VERIFIED"}
            return 2.5

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vpn.probes, "public_ip", return_value="9.9.9.9"),
            patch.object(vpn, "_bench_one", side_effect=benchmark) as bench,
            patch.object(vpn, "_run_session") as connect,
            patch.object(vpn, "load_bench_cache", return_value={}),
            patch.object(vpn, "save_bench_cache"),
            patch.object(vpn, "_measurement_key", return_value="key"),
        ):
            vpn._connect_to_country("Japan", [relay], 1, 0, True, directory)
        bench.assert_called_once()
        connect.assert_not_called()

    def test_explicit_monitor_probes_only_after_its_interval(self):
        process = Mock()
        process.poll.return_value = None
        with (
            patch.object(vpn, "_openvpn_start", return_value=(process, "cfg", "creds")),
            patch.object(vpn, "_wait_connected", return_value=True),
            patch.object(vpn.time, "sleep") as delay,
            patch.object(
                vpn.probes,
                "measure",
                return_value=probes.Measurement("VERIFIED", mbps=0.1),
            ) as measure,
            patch.object(vpn, "_cleanup_session"),
        ):
            self.assertFalse(vpn._run_session(self.relay(), "/unused", "Japan", 1))
        self.assertEqual(measure.call_count, 2)
        self.assertEqual(delay.call_count, 2)


class ProbeTests(unittest.TestCase):
    def test_active_route_measurement_is_not_limited_to_tun(self):
        data = {"http_code": 200, "size_download": 1_000_000, "time_total": 2}
        result = subprocess.CompletedProcess([], 28, json.dumps(data), "timeout")
        with (
            patch.object(probes, "active_route", return_value=probes.Route("wg0")),
            patch.object(probes, "public_ip", return_value="1.2.3.4"),
            patch.object(probes, "_curl", return_value=result) as curl,
        ):
            measured = probes.measure_active_route()
        self.assertEqual(measured.mbps, 4)
        self.assertIn("wg0", curl.call_args.args[0])

    def test_upload_measurement_posts_only_in_memory_to_active_route(self):
        data = {"http_code": 200, "size_upload": 1_000_000, "time_total": 2}
        result = subprocess.CompletedProcess([], 0, json.dumps(data), "")
        with (
            patch.object(probes, "active_route", return_value=probes.Route("wg0")),
            patch.object(probes, "_curl", return_value=result) as curl,
        ):
            measured = probes.measure_upload_active_route()
        self.assertEqual(measured.mbps, 4)
        self.assertIn("POST", curl.call_args.args[0])
        self.assertIn("wg0", curl.call_args.args[0])
        self.assertEqual(len(curl.call_args.args[2]), probes.UPLOAD_BYTES)

    def test_no_tunnel_no_measurement(self):
        with patch.object(
            probes, "tunnel_interface", side_effect=ConnectionError("not tun")
        ):
            self.assertEqual(probes.measure().status, "EGRESS_UNVERIFIED")

    def test_unchanged_egress_rejected(self):
        with (
            patch.object(probes, "tunnel_interface", return_value="tun0"),
            patch.object(probes, "public_ip", return_value="1.2.3.4"),
        ):
            self.assertEqual(
                probes.measure(baseline_ip="1.2.3.4").status, "EGRESS_UNCHANGED"
            )

    def test_timed_transfer_is_valid_and_bound_to_tun(self):
        data = {"http_code": 200, "size_download": 1_000_000, "time_total": 2}
        result = subprocess.CompletedProcess([], 28, json.dumps(data), "timeout")
        with (
            patch.object(probes, "tunnel_interface", return_value="tun0"),
            patch.object(probes, "public_ip", return_value="1.2.3.4"),
            patch.object(probes, "_curl", return_value=result) as curl,
        ):
            measured = probes.measure()
            self.assertEqual(measured.mbps, 4)
            self.assertIn("--interface", curl.call_args.args[0])
            self.assertIn("tun0", curl.call_args.args[0])

    def test_403_uses_alternative_endpoint(self):
        denied = subprocess.CompletedProcess(
            [], 0, json.dumps({"http_code": 403, "size_download": 100}), ""
        )
        ok = subprocess.CompletedProcess(
            [],
            0,
            json.dumps({"http_code": 200, "size_download": 1_000_000, "time_total": 1}),
            "",
        )
        with (
            patch.object(probes, "tunnel_interface", return_value="tun0"),
            patch.object(probes, "public_ip", return_value="1.2.3.4"),
            patch.object(probes, "_curl", side_effect=[denied, ok]),
        ):
            measured = probes.measure()
            self.assertEqual(measured.status, "VERIFIED")
            self.assertEqual(measured.endpoint, probes.SPEED_ENDPOINTS[1])

    def test_both_denied_still_distinguish_working_egress(self):
        denied = subprocess.CompletedProcess(
            [], 0, json.dumps({"http_code": 403, "size_download": 100}), ""
        )
        with (
            patch.object(probes, "tunnel_interface", return_value="tun0"),
            patch.object(probes, "public_ip", return_value="1.2.3.4"),
            patch.object(probes, "_curl", return_value=denied),
        ):
            measured = probes.measure()
            self.assertEqual(measured.status, "EGRESS_VERIFIED")
            self.assertIsNone(measured.mbps)


class DiscoveryTests(unittest.TestCase):
    def response(self):
        profile = base64.b64encode(b"client\nproto tcp\nremote 1.2.3.4 443\n").decode()
        return Mock(
            status_code=200,
            text="*vpn_servers\n#IP,CountryLong,CountryShort,Speed,OpenVPN_ConfigData_Base64\n1.2.3.4,Japan,JP,10,"
            + profile,
        )

    def test_legacy_fallback_does_not_disable_https_verification(self):
        with (
            patch.object(vpn, "VPN_GATE_URLS", ["https://a.test", "http://b.test"]),
            patch.object(
                vpn,
                "_get_bounded",
                side_effect=[
                    requests.exceptions.SSLError("untrusted"),
                    self.response(),
                ],
            ) as get,
            vpn.console.capture() as output,
        ):
            servers = vpn.fetch_vpn_servers()
            self.assertEqual(len(servers), 1)
            self.assertTrue(get.call_args_list[0].args[2])
            self.assertEqual(get.call_args_list[1].args[0], "http://b.test")
        self.assertNotIn("Mirror unavailable", output.get())
        self.assertIn("HTTP (not authenticated)", rendered_text(output.get()))

    def test_default_discovery_does_not_probe_https_before_working_mirror(self):
        with patch.object(vpn, "_get_bounded", return_value=self.response()) as get:
            vpn.fetch_vpn_servers()
        get.assert_called_once()
        self.assertEqual(get.call_args.args[0], "http://130.158.6.82/api/iphone/")

    def test_all_mirror_failures_are_reported(self):
        with (
            patch.object(vpn, "VPN_GATE_URLS", ["http://a.test", "https://b.test"]),
            patch.object(vpn, "_get_bounded", side_effect=requests.Timeout("failed")),
            vpn.console.capture() as output,
            self.assertRaises(SystemExit),
        ):
            vpn.fetch_vpn_servers()
        self.assertIn("http://a.test", output.get())
        self.assertIn("https://b.test", output.get())
        self.assertIn("Discovery failed", output.get())

    def test_strict_discovery_does_not_fall_back_to_http(self):
        with (
            patch.object(vpn, "VPN_GATE_URLS", ["https://a.test", "http://b.test"]),
            patch.object(
                vpn,
                "_get_bounded",
                side_effect=requests.exceptions.SSLError("untrusted"),
            ) as get,
        ):
            with self.assertRaises(SystemExit):
                vpn.fetch_vpn_servers(allow_http=False)
            self.assertEqual(get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
