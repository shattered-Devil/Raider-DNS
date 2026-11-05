from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

from raider_dns import __version__
from raider_dns.services.engine_supervisor import EngineSupervisor
from raider_dns.services.network_recovery_intelligence import NetworkRecoveryIntelligence
from raider_dns.storage import ActivityLogStore, ConfigStore
from raider_dns.ui.i18n import is_rtl, set_language, translate
from raider_dns.ui.theme import TOGGLE_SWITCH_COLORS, toggle_switch_colors

ROOT = Path(__file__).resolve().parents[1]


class V020ReleaseTests(unittest.TestCase):
    def test_release_version(self) -> None:
        self.assertEqual(__version__, "0.2.0-beta")

    def test_navigation_has_unique_icons_and_no_removed_pages(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        main_window = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MainWindow")
        nav_node = next(node.value for node in main_window.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "NAV_ITEMS" for target in node.targets))
        items = ast.literal_eval(nav_node)
        keys = [item[2] for item in items]
        icons = [item[1] for item in items]
        self.assertEqual(len(items), 9)
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(icons), len(set(icons)))
        self.assertNotIn("network_intelligence", keys)
        self.assertNotIn("profiles", keys)
        for icon in icons:
            self.assertTrue((ROOT / "assets/icons" / icon).is_file(), icon)

    def test_hardware_inventory_collector_is_removed_from_v020(self) -> None:
        self.assertFalse((ROOT / "raider_dns/services/network_inventory.py").exists())
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertNotIn("read_windows_network_inventory", source)
        self.assertNotIn("Get-PnpDevice", source)
        self.assertNotIn("Win32_PnPSignedDriver", source)

    def test_removed_pages_are_not_constructed(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertNotIn("def _build_network_intelligence_page", source)
        self.assertNotIn("def _build_profiles_page", source)
        self.assertNotIn('make_label("NETWORK INTELLIGENCE"', source)
        self.assertIn('self.providers_page = self._build_providers_page()', source)
        self.assertIn('self.network_profile_list', source)

    def test_tooltip_delay_is_fixed_and_not_a_setting(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        storage = (ROOT / "raider_dns/storage.py").read_text(encoding="utf-8")
        self.assertIn("DEFAULT_DELAY_MS = 750", source)
        self.assertNotIn("tooltip_delay_ms", source)
        self.assertIn('merged.pop("tooltip_delay_ms", None)', storage)

    def test_settings_preferences_use_theme_aware_toggle_switches(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        settings_builder = source.split("def _build_settings_page", 1)[1].split("def _build_about", 1)[0]
        self.assertGreaterEqual(settings_builder.count("ToggleSwitch("), 9)
        self.assertIn("self.setObjectName(\"SettingsToggle\")", source)
        self.assertIn("def apply_theme(self, theme: str)", source)
        self.assertIn("toggle_switch_colors(theme)", source)
        self.assertIn("self._apply_toggle_switch_theme()", source)
        theme_method = source.split("def _apply_theme(self)", 1)[1].split("def _settings_changed", 1)[0]
        self.assertLess(
            theme_method.index("self.setStyleSheet(current_stylesheet)"),
            theme_method.index("self._apply_toggle_switch_theme()"),
        )
        toggle_source = source.split("class ToggleSwitch(", 1)[1].split("\n\nclass Panel", 1)[0]
        self.assertNotIn("QPalette.ColorRole.Highlight", toggle_source)
        self.assertIn("self._checked_track_color if self.isChecked()", toggle_source)

    def test_toggle_switch_colors_follow_every_supported_theme(self) -> None:
        expected_themes = {
            "dark", "light", "light_mild", "paper", "warm_sand",
            "mist_blue", "midnight", "ocean", "high_contrast",
        }
        self.assertEqual(set(TOGGLE_SWITCH_COLORS), expected_themes)
        checked_colors = {toggle_switch_colors(theme)[0] for theme in expected_themes}
        self.assertEqual(len(checked_colors), len(expected_themes))
        self.assertEqual(toggle_switch_colors("unknown"), toggle_switch_colors("dark"))

    def test_persian_dictionary_has_rtl_and_settings_translations(self) -> None:
        try:
            set_language("fa")
            self.assertTrue(is_rtl())
            self.assertEqual(translate("Dashboard"), "داشبورد")
            self.assertEqual(translate("Appearance"), "نمایش")
            self.assertEqual(translate("Engine supervision"), "نظارت بر موتورهای شبکه")
        finally:
            set_language("en")
        self.assertFalse(is_rtl())

    def test_language_setting_is_persisted_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = ConfigStore(Path(temp) / "settings.json")
            settings = store.load()
            settings["language"] = "fa"
            store.save(settings)
            self.assertEqual(store.load()["language"], "fa")
            settings["language"] = "not-a-language"
            store.save(settings)
            self.assertEqual(store.load()["language"], "en")

    def test_supervisor_distinguishes_expected_and_unexpected_stop(self) -> None:
        supervisor = EngineSupervisor()
        supervisor.observe("dnscrypt", "DNSCrypt Proxy", configured=True, running=True)
        supervisor.mark_expected_stop("dnscrypt")
        expected = supervisor.observe("dnscrypt", "DNSCrypt Proxy", configured=True, running=False)
        self.assertEqual(expected.state, "stopped")

        supervisor.observe("singbox", "sing-box", configured=True, running=True)
        unexpected = supervisor.observe("singbox", "sing-box", configured=True, running=False)
        self.assertEqual(unexpected.state, "failed")
        self.assertIn("unexpectedly", unexpected.detail)

    def test_supervisor_event_history_is_bounded(self) -> None:
        supervisor = EngineSupervisor()
        for index in range(80):
            supervisor.observe("dnscrypt", "DNSCrypt Proxy", configured=True, running=bool(index % 2))
        self.assertLessEqual(len(supervisor.events()), supervisor.MAX_EVENTS)

    def test_old_recovery_snapshot_is_sanitized_before_being_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "network-intelligence.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "snapshots": [{
                    "captured_at": "2026-01-01T00:00:00+00:00",
                    "adapter": "Ethernet Private Adapter Name",
                    "gateway": "192.0.2.1",
                    "wifi_ssid": "Secret WiFi",
                    "wifi_driver_version": "99.0",
                    "adapter_status": "Up",
                    "dhcp_enabled": True,
                    "checks": [{"id": "dns", "title": "DNS", "status": "PASS", "details": "192.0.2.53"}],
                }],
            }), encoding="utf-8")
            store = NetworkRecoveryIntelligence(path)
            snapshot = store.latest()
            self.assertIsNotNone(snapshot)
            serialized = json.dumps(snapshot)
            for private_value in ("Ethernet Private Adapter Name", "192.0.2.1", "Secret WiFi", "99.0", "192.0.2.53"):
                self.assertNotIn(private_value, serialized)
            self.assertEqual(snapshot["adapter_status"], "Up")

    def test_activity_history_limit_change_trims_persisted_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = ActivityLogStore(Path(temp) / "activity.json", limit=500)
            store.append_many([{"timestamp": str(index), "level": "INFO", "action": f"event-{index}"} for index in range(150)])
            store.set_limit(100)
            records = store.load()
            self.assertEqual(len(records), 100)
            self.assertEqual(records[0]["action"], "event-50")
            self.assertEqual(records[-1]["action"], "event-149")

    def test_settings_have_engine_monitor_controls(self) -> None:
        defaults = ConfigStore.__module__
        self.assertTrue(defaults)
        values = ConfigStore.defaults() if hasattr(ConfigStore, "defaults") else None
        if values is None:
            from raider_dns.storage import default_settings
            values = default_settings()
        self.assertTrue(values["engine_supervisor_enabled"])
        self.assertIn(values["engine_monitor_interval_seconds"], {5, 10, 15, 30})

    def test_persian_translations_cover_managed_singbox_and_dnscrypt_sections(self) -> None:
        keys = {
            "Traffic tunnel": "تونل ترافیک",
            "SING-BOX · FULL-DEVICE ROUTING": "sing-box · مسیریابی کامل دستگاه",
            "Open profile folder": "باز کردن پوشه پروفایل",
            "Check profile": "بررسی پروفایل",
            "Start traffic tunnel": "شروع تونل ترافیک",
            "Stop tunnel": "توقف تونل",
            "DNSCrypt local engine": "موتور محلی DNSCrypt",
        }
        try:
            set_language("fa")
            for source, expected in keys.items():
                with self.subTest(source=source):
                    self.assertEqual(translate(source), expected)
        finally:
            set_language("en")

    def test_both_installer_variants_require_both_engines(self) -> None:
        for installer_name in ("RaiderDNS.iss", "RaiderDNS_OneFile.iss"):
            source = (ROOT / "installer" / installer_name).read_text(encoding="utf-8")
            self.assertRegex(source, r'Name: "dnscrypt"; Description: "DNSCrypt Proxy engine \(required\)"; Types: full custom; Flags: fixed')
            self.assertRegex(source, r'Name: "singbox"; Description: "sing-box TUN Engine \(required\)"; Types: full custom; Flags: fixed')
            self.assertIn('Source: "payload\\dnscrypt-proxy\\*"', source)
            self.assertIn('Source: "payload\\sing-box\\*"', source)

    def test_onefile_installer_stages_and_verifies_both_engines(self) -> None:
        source = (ROOT / "build_onefile_installer.bat").read_text(encoding="utf-8")
        self.assertIn('prepare_dnscrypt_proxy.ps1', source)
        self.assertIn('prepare_singbox_payload.ps1', source)
        self.assertIn('The application, DNSCrypt Proxy, and sing-box engine are mandatory installer components.', source)

    def test_tunnel_ui_has_profile_selection_but_no_executable_selection(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn("singbox_config_path_edit", source)
        self.assertIn("_browse_singbox_config", source)
        self.assertIn("discover_bundled_binary()", source)
        self.assertNotIn("singbox_path_edit", source)
        self.assertNotIn("_browse_singbox_executable", source)

    def test_dns_tunnel_guidance_explains_profile_owned_dns(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn("DNS routing follows the DNS section in your sing-box JSON profile", source)
        self.assertIn("dns_mode to disabled", source)

    def test_persian_retranslation_supports_table_cells(self) -> None:
        source = (ROOT / "raider_dns/ui/main_window.py").read_text(encoding="utf-8")
        self.assertIn("if isinstance(widget, QTableWidget):", source)
        self.assertIn("item.setText(translate(item_source))", source)


if __name__ == "__main__":
    unittest.main()
