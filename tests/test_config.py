"""Tests for evilkit.config — loading, coercion, writing and paths."""

from __future__ import annotations

import os
import sys
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.config import (  # noqa: E402
    Config,
    DashboardConfig,
    config_dir,
    config_path,
    dumps,
    load,
    save,
)
from evilkit.scope import SOLO_SCOPE  # noqa: E402


class TestConfigDefaults(EvilkitTestCase):
    def test_missing_file_is_not_an_error(self):
        self.assertFalse(self.config_file.exists())
        config, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(config.kimi_bin, "kimi")
        self.assertEqual(config.default_scope, SOLO_SCOPE)
        self.assertEqual(config.backup_keep, 5)
        self.assertTrue(config.write_mcp_json)
        self.assertEqual(config.extra_env, {})
        self.assertIsNone(config.source)

    def test_explicit_path_is_used_instead_of_the_environment(self):
        other = self.tmp / "elsewhere.toml"
        other.write_text('kimi_bin = "from-explicit-path"\n', encoding="utf-8")
        config, problems = load(other)
        self.assertEqual(problems, [])
        self.assertEqual(config.kimi_bin, "from-explicit-path")
        self.assertEqual(config.source, other)

    def test_malformed_toml_is_reported_and_never_raised(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text("kimi_bin = \nnot toml at all\n", encoding="utf-8")
        config, problems = load()
        self.assertEqual(config.kimi_bin, "kimi")
        self.assertEqual(config.default_scope, SOLO_SCOPE)
        self.assertTrue(problems)
        self.assertTrue(all(isinstance(p, str) for p in problems))
        self.assertIn(str(self.config_file), problems[0])


class TestConfigCoercion(EvilkitTestCase):
    def _load_text(self, text: str):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(text, encoding="utf-8")
        return load()

    def test_wrong_typed_values_are_reported_without_crashing(self):
        cases = {
            'backup_keep = "many"\n': ("backup_keep", "integer"),
            "backup_keep = -1\n": ("backup_keep", "zero or greater"),
            "backup_keep = true\n": ("backup_keep", "integer"),
            "backup_keep = 1.9\n": ("backup_keep", "integer"),
            "backup_keep = [1]\n": ("backup_keep", "integer"),
            "kimi_bin = 5\n": ("kimi_bin", "non-empty string"),
            'kimi_bin = "   "\n': ("kimi_bin", "non-empty string"),
            'write_mcp_json = "yes"\n': ("write_mcp_json", "true or false"),
            'extra_env = { A = 1 }\n': ("extra_env", "table of string values"),
            'extra_env = "nope"\n': ("extra_env", "table of string values"),
        }
        for text, (key, fragment) in cases.items():
            with self.subTest(text=text):
                config, problems = self._load_text(text)
                self.assertTrue(
                    any(key in problem and fragment in problem for problem in problems),
                    f"expected a {key!r} problem mentioning {fragment!r}, got {problems!r}",
                )
                # The dataclass default survives a rejected value.
                self.assertEqual(config.backup_keep, 5)
                self.assertEqual(config.kimi_bin, "kimi")

    def test_bad_values_do_not_discard_the_good_ones(self):
        config, problems = self._load_text(
            'kimi_bin = "/opt/kimi/bin/kimi"\n'
            'backup_keep = "many"\n'
            'write_mcp_json = false\n'
        )
        self.assertEqual(config.kimi_bin, "/opt/kimi/bin/kimi")
        self.assertFalse(config.write_mcp_json)
        self.assertEqual(config.backup_keep, 5)
        self.assertEqual(len(problems), 1)
        self.assertIn("backup_keep", problems[0])

    def test_rejected_default_scope_falls_back_to_the_solo_default(self):
        config, problems = self._load_text('default_scope = "10.0.0.0/24;rm -rf /"\n')
        self.assertEqual(config.default_scope, SOLO_SCOPE)
        self.assertTrue(any("default_scope" in p for p in problems))

    def test_default_scope_is_normalised_on_load(self):
        config, problems = self._load_text('default_scope = "10.0.0.5, APP.LAN"\n')
        self.assertEqual(problems, [])
        self.assertEqual(config.default_scope, "10.0.0.5/32,app.lan")

    def test_unknown_keys_are_reported_but_harmless(self):
        config, problems = self._load_text("nonsense = 1\nkimi_bin = \"kimi\"\n")
        self.assertTrue(any("nonsense" in p for p in problems))
        self.assertEqual(config.kimi_bin, "kimi")

    def test_extra_env_accepts_a_table_of_strings(self):
        config, problems = self._load_text(
            "[extra_env]\nFOO = \"bar\"\nEMPTY = \"\"\n"
        )
        self.assertEqual(problems, [])
        self.assertEqual(config.extra_env, {"FOO": "bar", "EMPTY": ""})

    def test_extra_env_cannot_carry_the_scope_key(self):
        config, problems = self._load_text(
            "[extra_env]\nPENTEST_ALLOWED_TARGETS = \"0.0.0.0/0\"\nFOO = \"bar\"\n"
        )
        self.assertEqual(config.extra_env, {"FOO": "bar"})
        self.assertEqual(len(problems), 1)
        self.assertIn("PENTEST_ALLOWED_TARGETS", problems[0])
        self.assertIn("extra_env", problems[0])

    def test_source_records_where_settings_came_from(self):
        config, _ = self._load_text('kimi_bin = "kimi"\n')
        self.assertEqual(config.source, self.config_file)


class TestBackupKeepTyping(EvilkitTestCase):
    """``backup_keep`` must be a real integer, not something int() can chew on."""

    def _load_text(self, text: str):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(text, encoding="utf-8")
        return load()

    def test_a_bool_is_rejected_rather_than_becoming_one(self):
        config, problems = self._load_text("backup_keep = true\n")
        self.assertEqual(config.backup_keep, 5)
        self.assertEqual(len(problems), 1)
        self.assertIn("backup_keep", problems[0])

    def test_a_fractional_float_is_rejected_rather_than_truncated(self):
        config, problems = self._load_text("backup_keep = 1.9\n")
        self.assertEqual(config.backup_keep, 5)
        self.assertTrue(any("backup_keep" in problem for problem in problems))

    def test_a_real_integer_is_accepted(self):
        config, problems = self._load_text("backup_keep = 3\n")
        self.assertEqual(problems, [])
        self.assertEqual(config.backup_keep, 3)


class TestUnreadableConfig(EvilkitTestCase):
    def _write_bytes(self, payload: bytes) -> None:
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_bytes(payload)

    def test_invalid_utf8_is_reported_as_a_problem(self):
        self._write_bytes(b'kimi_bin = "\xff\xfe"\n')
        config, problems = load()
        self.assertEqual(config.kimi_bin, "kimi")
        self.assertEqual(len(problems), 1)
        self.assertIn(str(self.config_file), problems[0])

    def test_deeply_nested_toml_is_reported_as_a_problem(self):
        self._write_bytes(("arr = " + "[" * 100_000 + "]" * 100_000 + "\n").encode())
        config, problems = load()
        self.assertEqual(config.kimi_bin, "kimi")
        self.assertEqual(len(problems), 1)
        self.assertIn(str(self.config_file), problems[0])


class TestConfigRoundTrip(EvilkitTestCase):
    def test_every_field_survives_save_then_load(self):
        original = Config(
            kimi_bin="/opt/kimi/bin/kimi",
            default_scope="10.0.0.0/8,app.lan,2001:db8::/32",
            backup_keep=0,
            write_mcp_json=False,
            extra_env={"FOO": "bar", "EMPTY": "", "QUOTED": 'he said "hi"'},
        )
        save(original, self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded.kimi_bin, original.kimi_bin)
        self.assertEqual(loaded.default_scope, original.default_scope)
        self.assertEqual(loaded.backup_keep, original.backup_keep)
        self.assertEqual(loaded.write_mcp_json, original.write_mcp_json)
        self.assertEqual(loaded.extra_env, original.extra_env)
        self.assertEqual(loaded.source, self.config_file)

    def test_round_trip_of_the_true_defaults(self):
        save(Config(), self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded, Config(source=self.config_file))

    def test_dumped_text_is_valid_toml(self):
        text = dumps(Config(extra_env={"A": "b"}))
        parsed = tomllib.loads(text)
        self.assertEqual(parsed["kimi_bin"], "kimi")
        self.assertEqual(parsed["extra_env"], {"A": "b"})

    def test_save_creates_missing_parent_directories(self):
        nested = self.tmp / "a" / "b" / "c" / "config.toml"
        returned = save(Config(), nested)
        self.assertEqual(returned, nested)
        self.assertTrue(nested.is_file())

    def test_save_returns_the_path_it_wrote(self):
        self.assertEqual(save(Config(), self.config_file), self.config_file)
        self.assertTrue(self.config_file.is_file())

    def test_extra_env_is_written_in_a_stable_order(self):
        text = dumps(Config(extra_env={"ZED": "1", "ALPHA": "2"}))
        self.assertLess(text.index("ALPHA"), text.index("ZED"))

    def test_control_characters_survive_save_then_load(self):
        original = Config(
            kimi_bin="kimi",
            extra_env={"OK": "a\x00b\x0bc", "TAB": "x\ty", "DEL": "z\x7f"},
        )
        save(original, self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded.extra_env, original.extra_env)

    def test_a_control_character_in_a_key_survives_save_then_load(self):
        original = Config(extra_env={"\x01key": "value"})
        save(original, self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded.extra_env, original.extra_env)

    def test_no_raw_control_character_reaches_the_file(self):
        text = dumps(Config(extra_env={"A": "b\x00c\x1fd\x7f"}))
        self.assertNotIn("\x00", text)
        self.assertNotIn("\x1f", text)
        self.assertNotIn("\x7f", text)
        tomllib.loads(text)


class TestConfigPaths(EvilkitTestCase):
    def test_env_override_wins(self):
        self.assertEqual(config_path(), self.config_file)

    def test_xdg_config_home_is_honoured_when_the_override_is_empty(self):
        with mock.patch.dict(os.environ, {"EVILKIT_CONFIG": ""}):
            self.assertEqual(
                config_path(),
                self.tmp / "xdg-config" / "evilkit" / "config.toml",
            )
            self.assertEqual(config_dir(), self.tmp / "xdg-config" / "evilkit")

    def test_home_config_is_the_last_resort(self):
        with mock.patch.dict(os.environ, {"EVILKIT_CONFIG": "", "XDG_CONFIG_HOME": ""}):
            self.assertEqual(config_path(), self.home / ".config" / "evilkit" / "config.toml")

    def test_no_config_path_escapes_the_temp_environment(self):
        for path in (config_path(), config_dir()):
            self.assertTrue(
                str(path).startswith(str(self.tmp)),
                f"{path} is outside the per-test temp directory",
            )


class TestResolvedKimiBin(EvilkitTestCase):
    def test_env_override_wins(self):
        self.assertEqual(Config(kimi_bin="/opt/kimi").resolved_kimi_bin(), str(self.stub))

    def test_configured_path_is_expanded(self):
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": ""}):
            self.assertEqual(
                Config(kimi_bin="~/bin/kimi").resolved_kimi_bin(),
                str(self.home / "bin" / "kimi"),
            )
            self.assertEqual(
                Config(kimi_bin="/opt/kimi/bin/kimi").resolved_kimi_bin(),
                "/opt/kimi/bin/kimi",
            )

    def test_bare_name_is_resolved_through_path(self):
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        tool = bin_dir / "kimi-from-path"
        tool.write_text("#!/bin/sh\n", encoding="utf-8")
        tool.chmod(0o755)
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": "", "PATH": str(bin_dir)}):
            self.assertEqual(Config(kimi_bin="kimi-from-path").resolved_kimi_bin(), str(tool))

    def test_unresolvable_bare_name_is_returned_unchanged(self):
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": "", "PATH": str(self.tmp / "empty")}):
            self.assertEqual(Config(kimi_bin="definitely-not-installed").resolved_kimi_bin(),
                             "definitely-not-installed")


class TestExtraEnvKeys(EvilkitTestCase):
    def test_extra_env_keys_survive_a_round_trip(self):
        """Regression: extra_env keys used to be emitted as bare TOML keys.

        _format_value() escaped extra_env *values* but the keys went out verbatim
        as bare TOML keys, so a key outside bare-key syntax either produced
        invalid TOML -- discarding the whole config on the next load -- or was
        silently reinterpreted as a nested table:

            [extra_env]
            MY VAR = "1"   -> TOMLDecodeError, every setting lost
            A.B = "2"      -> read back as {"A": {"B": "2"}}, so extra_env is
                              reported as invalid and dropped

        load() accepts the same keys when they are quoted, so the writer could
        not represent everything the reader accepted. Keys are now quoted and
        escaped whenever TOML cannot express them bare.
        """
        save(Config(extra_env={"MY VAR": "1", "A.B": "2"}), self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded.extra_env, {"MY VAR": "1", "A.B": "2"})


class TestDashboardConfig(EvilkitTestCase):
    """The [dashboard] table: the lab run controls' URL, opt-in and timeout."""

    def _load_text(self, text: str):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(text, encoding="utf-8")
        return load()

    def test_defaults_attach_nothing(self):
        # No default address: a guessed host would either fail obscurely or reach
        # something that is not the board the operator meant.
        dashboard = Config().dashboard
        self.assertEqual(dashboard, DashboardConfig(url="", attach=False, timeout=5.0))
        self.assertFalse(dashboard.enabled())

    def test_a_configured_url_is_usable_and_trailing_slashes_are_dropped(self):
        config, problems = self._load_text('[dashboard]\nurl = "http://10.0.0.9:8793/"\n')
        self.assertEqual(problems, [])
        self.assertEqual(config.dashboard.url, "http://10.0.0.9:8793")
        self.assertTrue(config.dashboard.enabled())

    def test_a_non_http_url_is_reported_and_dropped(self):
        for text in ('url = "ftp://host:8793"\n', 'url = "10.0.0.9:8793"\n', "url = 8793\n"):
            with self.subTest(text=text):
                config, problems = self._load_text(f"[dashboard]\n{text}")
                self.assertTrue(problems, text)
                self.assertEqual(config.dashboard.url, "")

    def test_auto_without_a_url_is_reported(self):
        config, problems = self._load_text("[dashboard]\nauto = true\n")
        self.assertTrue(config.dashboard.auto)
        self.assertTrue(any("auto is true but url is empty" in problem for problem in problems), problems)

    def test_auto_survives_save_then_load(self):
        save(Config(dashboard=DashboardConfig(url="http://10.0.0.9:8793", attach=True, auto=True)),
             self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertTrue(loaded.dashboard.auto)
        self.assertTrue(loaded.dashboard.attach)

    def test_attach_without_a_url_is_reported(self):
        config, problems = self._load_text("[dashboard]\nattach = true\n")
        self.assertTrue(config.dashboard.attach)
        self.assertTrue(any("attach is true but url is empty" in problem for problem in problems), problems)

    def test_wrong_typed_values_are_reported_without_crashing(self):
        cases = {
            'attach = "yes"\n': ("attach", "true or false"),
            "auto = 1\n": ("auto", "true or false"),
            "timeout = 0\n": ("timeout", "positive number"),
            'timeout = "soon"\n': ("timeout", "positive number"),
            "timeout = true\n": ("timeout", "positive number"),
        }
        for text, (key, fragment) in cases.items():
            with self.subTest(text=text):
                config, problems = self._load_text(f"[dashboard]\n{text}")
                self.assertTrue(
                    any(key in problem and fragment in problem for problem in problems),
                    f"expected a {key!r} problem mentioning {fragment!r}, got {problems!r}",
                )
                self.assertEqual(config.dashboard, DashboardConfig())

    def test_an_unknown_key_is_reported_but_harmless(self):
        config, problems = self._load_text(
            '[dashboard]\nurl = "http://10.0.0.9:8793"\ntypo = 1\n'
        )
        self.assertEqual(config.dashboard.url, "http://10.0.0.9:8793")
        self.assertTrue(any("unknown [dashboard] key" in problem for problem in problems), problems)

    def test_a_non_table_is_reported(self):
        _, problems = self._load_text('dashboard = "http://10.0.0.9:8793"\n')
        self.assertTrue(any("[dashboard] must be a table" in problem for problem in problems), problems)

    def test_an_exported_url_wins_over_the_file(self):
        config = Config(dashboard=DashboardConfig(url="http://from-file:8793", attach=True))
        with mock.patch.dict(os.environ, {"EVILKIT_DASHBOARD_URL": "http://from-env:8793"}):
            self.assertEqual(config.dashboard.resolved_url(), "http://from-env:8793")
            self.assertTrue(config.dashboard.enabled())
        with mock.patch.dict(os.environ, {"EVILKIT_DASHBOARD_URL": ""}):
            self.assertEqual(config.dashboard.resolved_url(), "http://from-file:8793")

    def test_the_table_survives_save_then_load(self):
        save(Config(dashboard=DashboardConfig(url="http://10.0.0.9:8793", attach=True, timeout=2.5)),
             self.config_file)
        loaded, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(loaded.dashboard, DashboardConfig(url="http://10.0.0.9:8793",
                                                           attach=True, timeout=2.5))

    def test_the_dumped_table_parses(self):
        parsed = tomllib.loads(dumps(Config()))
        self.assertEqual(parsed["dashboard"],
                         {"url": "", "attach": False, "auto": False, "timeout": 5})


if __name__ == "__main__":
    unittest.main()
