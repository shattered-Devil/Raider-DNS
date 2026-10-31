from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from raider_dns.models import PROVIDERS
from raider_dns.storage import ConfigStore, default_settings


class ProviderCataloguePersistenceTests(unittest.TestCase):
    def test_builtin_override_and_hidden_provider_are_normalized(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({
                "provider_overrides": {
                    "cloudflare": {
                        "name": "Cloudflare Home",
                        "description": "A local name for the same resolver",
                        "primary": "1.1.1.1",
                        "secondary": "1.0.0.1",
                        "category": "Custom label",
                        "doh_url": "https://cloudflare-dns.com/dns-query",
                        "dot_hostname": "one.one.one.one",
                        "website": "https://one.one.one.one/",
                    },
                    "not-a-provider": {"name": "Invalid", "primary": "1.1.1.1"},
                },
                "disabled_builtin_providers": ["google", "unknown"],
            }), encoding="utf-8")
            settings = ConfigStore(path).load()
        self.assertEqual(settings["provider_overrides"]["cloudflare"]["name"], "Cloudflare Home")
        self.assertEqual(settings["provider_overrides"]["cloudflare"]["primary"], "1.1.1.1")
        self.assertNotIn("not-a-provider", settings["provider_overrides"])
        self.assertEqual(settings["disabled_builtin_providers"], ["google"])
        self.assertNotEqual(settings["selected_provider"], "google")

    def test_settings_cannot_disable_the_entire_provider_catalogue(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({
                "disabled_builtin_providers": [provider.id for provider in PROVIDERS],
                "custom_providers": [],
            }), encoding="utf-8")
            settings = ConfigStore(path).load()
        self.assertEqual(settings["disabled_builtin_providers"], [])
        self.assertIn(settings["selected_provider"], {provider.id for provider in PROVIDERS})
        self.assertIn(settings["fallback_provider"], {provider.id for provider in PROVIDERS})

    def test_v015_defaults_use_dns_only_scope_settings(self) -> None:
        settings = default_settings()
        self.assertEqual(settings["connection_dns_method"], "standard")
        self.assertEqual(settings["dns_scope_mode"], "inclusive")
        for key in ("connection_engine_path", "connection_profile_path", "connection_network_lock"):
            self.assertNotIn(key, settings)


class V015ConnectionAndProviderUIStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).parents[1]
        cls.ui_source = (root / "raider_dns" / "ui" / "main_window.py").read_text(encoding="utf-8")
        cls.storage_source = (root / "raider_dns" / "storage.py").read_text(encoding="utf-8")
        cls.all_active_source = "\n".join(path.read_text(encoding="utf-8") for path in [root / "main.py", *list((root / "raider_dns").rglob("*.py"))])

    def test_connection_has_premium_full_card_layout_and_four_horizontal_modes(self) -> None:
        self.assertIn('"Your DNS. Your rules."', self.ui_source)
        self.assertIn('methods_grid.addWidget(card, 0, index)', self.ui_source)
        self.assertIn('self.connection_method_cards', self.ui_source)
        self.assertIn('self.connection_advanced_details.setVisible(False)', self.ui_source)

    def test_inclusive_exclusive_scope_is_persisted_and_explained(self) -> None:
        self.assertIn('"inclusive"', self.storage_source)
        self.assertIn('"exclusive"', self.storage_source)
        self.assertIn('Inclusive — selected browsers only', self.ui_source)
        self.assertIn('Exclusive — all except selected', self.ui_source)
        self.assertIn('BrowserSecureDnsController.resolve_scope_targets', self.ui_source)
        self.assertIn('does not intercept DNS from arbitrary Windows applications', self.ui_source)

    def test_provider_modify_saves_builtin_overrides_and_custom_rows(self) -> None:
        editor = self.ui_source[self.ui_source.index('def _provider_editor_dialog'):self.ui_source.index('def _register_provider_context_menu')]
        self.assertIn('self.settings["custom_providers"] = [updated if row.get("id") == provider_id else row', editor)
        self.assertIn('overrides[provider_id] = updated', editor)
        self.assertIn('self._save_settings()', editor)

    def test_provider_delete_confirms_and_persists_permanent_catalogue_removal(self) -> None:
        method = self.ui_source[self.ui_source.index('def _delete_provider'):self.ui_source.index('def _update_favorite_controls')]
        self.assertIn('QMessageBox.question', method)
        self.assertIn('self.settings["disabled_builtin_providers"] = disabled', method)
        self.assertIn('self.settings["custom_providers"] = [row for row in self.settings.get("custom_providers", []) if row.get("id") != provider_id]', method)
        self.assertIn('self._save_settings()', method)

    def test_active_application_code_does_not_include_the_removed_tunnel_engine(self) -> None:
        self.assertNotIn("WireSockEngine", self.all_active_source)
        self.assertNotIn("WireGuard", self.all_active_source)
        self.assertNotIn("from raider_dns.services.app_connections", self.all_active_source)


if __name__ == "__main__":
    unittest.main()
