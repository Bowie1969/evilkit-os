"""Tests for evilkit.theme and the ``evilkit theme`` command."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit import theme  # noqa: E402


class ThemeTestCase(EvilkitTestCase):
    @property
    def installed_path(self) -> pathlib.Path:
        return pathlib.Path(theme.kimi_themes_dir()) / f"{theme.THEME_NAME}.json"


class TestThemeInstall(ThemeTestCase):
    def test_theme_name(self):
        self.assertEqual(theme.THEME_NAME, "evilkit")

    def test_bundled_theme_exists_and_is_valid_json(self):
        source = theme.theme_source()
        self.assertTrue(source.is_file(), source)
        self.assertEqual(json.loads(source.read_text(encoding="utf-8"))["name"], theme.THEME_NAME)

    def test_themes_dir_honours_the_kimi_home_override(self):
        self.assertEqual(theme.kimi_themes_dir(), self.kimi_home / "themes")

    def test_themes_dir_defaults_under_home(self):
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_HOME": ""}):
            self.assertEqual(theme.kimi_themes_dir(), self.home / ".kimi-code" / "themes")

    def test_is_installed_is_false_until_installed(self):
        self.assertFalse(theme.is_installed())
        theme.install()
        self.assertTrue(theme.is_installed())

    def test_install_writes_the_bundled_theme_and_creates_the_directory(self):
        target = theme.install()
        self.assertEqual(target, self.installed_path)
        self.assertTrue(target.is_file())
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            theme.theme_source().read_text(encoding="utf-8"),
        )

    def test_install_accepts_an_explicit_directory(self):
        elsewhere = self.tmp / "elsewhere" / "themes"
        target = theme.install(themes_dir=elsewhere)
        self.assertEqual(target, elsewhere / "evilkit.json")
        self.assertTrue(target.is_file())
        self.assertFalse(self.installed_path.exists())

    def test_install_is_idempotent(self):
        target = theme.install()
        before = target.stat().st_mtime_ns
        self.assertEqual(theme.install(), target)
        self.assertEqual(target.stat().st_mtime_ns, before)

    def test_install_reports_a_missing_bundled_theme(self):
        with mock.patch.object(theme, "theme_source", return_value=self.tmp / "absent.json"):
            with self.assertRaises(FileNotFoundError):
                theme.install()

    def test_install_rejects_a_corrupt_bundled_theme(self):
        corrupt = self.tmp / "corrupt.json"
        corrupt.write_text("{not json", encoding="utf-8")
        with mock.patch.object(theme, "theme_source", return_value=corrupt):
            with self.assertRaises(ValueError):
                theme.install()
        self.assertFalse(self.installed_path.exists())


class TestThemeSymlink(ThemeTestCase):
    def _plant_symlink(self) -> tuple[pathlib.Path, bytes]:
        self.installed_path.parent.mkdir(parents=True, exist_ok=True)
        victim = self.tmp / "victim.json"
        payload = b'{"victim": true}\n'
        victim.write_bytes(payload)
        self.installed_path.symlink_to(victim)
        return victim, payload

    def test_install_refuses_to_write_through_a_symlink(self):
        victim, payload = self._plant_symlink()

        with self.assertRaises(ValueError):
            theme.install(force=True)

        self.assertEqual(victim.read_bytes(), payload)
        self.assertTrue(self.installed_path.is_symlink())

    def test_install_without_force_also_refuses_a_symlink(self):
        victim, payload = self._plant_symlink()

        with self.assertRaises(ValueError):
            theme.install(force=False)

        self.assertEqual(victim.read_bytes(), payload)

    def test_a_regular_file_keeps_its_existing_behaviour(self):
        self.installed_path.parent.mkdir(parents=True, exist_ok=True)
        self.installed_path.write_text('{"mine": true}\n', encoding="utf-8")

        self.assertEqual(theme.install(force=False), self.installed_path)
        self.assertEqual(
            self.installed_path.read_text(encoding="utf-8"), '{"mine": true}\n'
        )

        theme.install(force=True)
        self.assertEqual(
            self.installed_path.read_text(encoding="utf-8"),
            theme.theme_source().read_text(encoding="utf-8"),
        )

    def test_the_command_reports_a_symlink_and_exits_one(self):
        victim, payload = self._plant_symlink()

        code, _, err = self.call_main(["theme", "install", "--force"])

        self.assertEqual(code, 1)
        self.assertIn("symlink", err)
        self.assertEqual(victim.read_bytes(), payload)


class TestThemeCommand(ThemeTestCase):
    def test_status_exits_zero_and_reports_the_state(self):
        code, out, err = self.call_main(["theme", "status"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("not installed", out)

        self.call_main(["theme", "install"])
        code, out, _ = self.call_main(["theme", "status"])
        self.assertEqual(code, 0)
        self.assertIn("installed", out)

    def test_status_is_the_default_action(self):
        code, out, _ = self.call_main(["theme"])
        self.assertEqual(code, 0)
        self.assertIn("not installed", out)

    def test_install_writes_the_theme(self):
        code, out, err = self.call_main(["theme", "install"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn(str(self.installed_path), out)
        self.assertTrue(self.installed_path.is_file())

    def test_install_accepts_force(self):
        code, _, _ = self.call_main(["theme", "install", "--force"])
        self.assertEqual(code, 0)
        self.assertTrue(self.installed_path.is_file())

    def test_unknown_action_is_a_usage_error(self):
        code, _, err = self.call_main(["theme", "sideways"])
        self.assertEqual(code, 2)
        self.assertIn("usage", err.lower())


class TestThemeInstallSafety(ThemeTestCase):
    def test_install_does_not_overwrite_a_local_edit(self):
        """Regression: install() used to clobber a locally edited theme.

        The guard only short-circuited when the installed file was already
        identical, so an *existing but different* theme was overwritten even with
        ``force`` False -- making ``--force`` a no-op and silently destroying a
        local edit. An existing file is now left alone unless forced.
        """
        theme.install()
        local_edit = '{"name": "evilkit", "mine": true}\n'
        self.installed_path.write_text(local_edit, encoding="utf-8")

        theme.install(force=False)

        self.assertEqual(self.installed_path.read_text(encoding="utf-8"), local_edit)


if __name__ == "__main__":
    unittest.main()
