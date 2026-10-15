"""Les pages et complétions livrées doivent suivre les options réelles de `panther --help` (sinon la doc ment)."""
import os
import re
import unittest

from panther import __main__ as cli

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def real_options():
    return {o for action in cli.build_parser()._actions for o in action.option_strings if o.startswith("--")}


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class PackagingTests(unittest.TestCase):
    def test_man_page_documents_every_option(self):
        man = read("packaging", "panther.1").replace("\\-", "-")
        for opt in real_options() - {"--help"}:
            self.assertIn(opt, man, f"{opt} absent de la page de manuel")

    def test_completions_list_every_option(self):
        for name in ("panther.bash", "_panther"):
            text = read("packaging", "completions", name)
            for opt in real_options():
                self.assertIn(opt, text, f"{opt} absent de {name}")

    def test_completed_values_match_the_parser(self):
        depth = ("ecoute", "rapide", "normal", "approfondi")
        for name in ("panther.bash", "_panther"):
            text = read("packaging", "completions", name)
            self.assertTrue(all(d in text for d in depth), name)
        self.assertIn("fr en", read("packaging", "completions", "panther.bash"))

    def test_man_page_is_valid_roff_header(self):
        man = read("packaging", "panther.1")
        self.assertRegex(man, r'^\.TH PANTHER 1 ')
        self.assertEqual(re.findall(r"^\.SH (.+)$", man, re.M), ["NAME", "SYNOPSIS", "DESCRIPTION", "OPTIONS", "FILES", "SEE ALSO", "AUTHOR"])

    def test_changelog_has_an_unreleased_or_current_section(self):
        from panther import __version__
        log = read("CHANGELOG.md")
        self.assertTrue("## [Unreleased]" in log or f"## [{__version__}]" in log)


if __name__ == "__main__":
    unittest.main()


class InstallerTests(unittest.TestCase):
    def test_scripts_exist_and_have_no_personal_data(self):
        for name in ("install.sh", "install.ps1"):
            text = read("installer", name)
            self.assertNotRegex(text, r"/home/\w|C:\\Users\\\w|@\w+\.\w+", name)

    def test_unix_installer_installs_and_uninstalls_in_a_private_home(self):
        import shutil
        import subprocess
        import tempfile
        if not shutil.which("sh") or os.uname().sysname != "Linux":
            self.skipTest("Linux requis")
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "XDG_DATA_HOME": os.path.join(home, "data"), "PANTHER_NO_DEPS": "1"}
            script = os.path.join(ROOT, "installer", "install.sh")
            r = subprocess.run(["sh", script], env=env, capture_output=True, text=True, timeout=300)
            if r.returncode and "No matching distribution" in r.stderr + r.stdout:
                self.skipTest("pas de réseau pour construire le paquet")
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            launcher = os.path.join(home, ".local", "bin", "panther")
            self.assertTrue(os.access(launcher, os.X_OK))
            self.assertTrue(os.path.exists(os.path.join(home, "data", "applications", "panther.desktop")))
            v = subprocess.run([launcher, "--help"], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(v.returncode, 0, v.stderr)
            self.assertIn("--demo", v.stdout)
            u = subprocess.run(["sh", script, "--uninstall"], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(u.returncode, 0)
            self.assertFalse(os.path.exists(launcher))
            self.assertFalse(os.path.exists(os.path.join(home, "data", "panther")))
