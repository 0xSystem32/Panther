import contextlib
import io
import unittest
from unittest import mock

from panther import __main__ as cli
from panther import i18n


class FakeScanner:
    def __init__(self, result):
        self.result, self.started = result, None

    def start(self, targets, **kw):
        self.started = (targets, kw)

    def snapshot(self):
        return self.result


def device(**kw):
    d = {"ip": "192.168.1.5", "mac": "aa:bb:cc:00:00:05", "hostname": "tv-salon", "type": "tv", "os": "Linux", "vendor": "Samsung",
         "network": "192.168.1.0/24", "security": None}
    d.update(kw)
    return d


class ArgumentTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("fr")

    def test_defaults_and_options(self):
        a = cli.parse_args(["--cli", "--depth", "ecoute", "--target", "10.0.0.0/24", "--target", "10.0.1.0/24", "--security", "--lang", "en"])
        self.assertEqual((a.cli, a.depth, a.target, a.security, a.lang, a.demo, a.web), (True, "ecoute", ["10.0.0.0/24", "10.0.1.0/24"], True, "en", False, False))
        self.assertEqual(i18n.language(), "en")                                           # l'aide est déjà traduite à l'analyse

    def test_language_flag_is_read_in_both_forms_and_unknown_values_are_refused(self):
        self.assertEqual(cli._lang_from(["--lang=en"]), "en")
        self.assertEqual(cli._lang_from(["--cli", "--lang", "fr"]), "fr")
        self.assertIsNone(cli._lang_from(["--cli"]))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.parse_args(["--lang", "klingon"])

    def test_help_is_translated(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.parse_args(["--lang", "en", "--help"])
        self.assertIn("Local network scanner and mapper", out.getvalue())


class CliRunTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("fr")

    def run_cli(self, result, **args):
        a = cli.parse_args(["--cli", "--lang", "en"] + args.get("argv", []))
        fake = FakeScanner(result)
        out = io.StringIO()
        with mock.patch("panther.scanner.Scanner", lambda: fake), mock.patch.object(cli.time, "sleep", lambda s: None), contextlib.redirect_stdout(out):
            cli.run_cli(a)
        return out.getvalue(), fake

    def test_prints_a_table_and_warnings(self):
        out, fake = self.run_cli({"status": "done", "devices": [device()], "warnings": ["range ignored"]})
        lines = out.splitlines()
        self.assertEqual(lines[0], "Warning: range ignored")
        self.assertTrue(lines[1].startswith("IP") and "Vendor" in lines[1])
        self.assertIn("tv-salon", lines[2]); self.assertIn("Samsung", lines[2])
        self.assertEqual(fake.started[1]["depth"], "normal")

    def test_security_column_and_error_exit(self):
        out, _ = self.run_cli({"status": "done", "devices": [device(security=[{"severity": "élevé"}]), device(security=[], ip="192.168.1.6")]}, argv=["--security"])
        self.assertIn("Exposure", out)
        self.assertIn("élevé", out); self.assertIn("no findings", out)
        with self.assertRaises(SystemExit) as e:
            self.run_cli({"status": "error", "error": "Aucune route par défaut", "devices": []})
        self.assertEqual(str(e.exception), "Aucune route par défaut")


class MainTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("fr")

    def test_demo_cannot_be_combined_with_cli_or_web(self):
        for extra in ("--cli", "--web"):
            with self.assertRaises(SystemExit) as e:
                cli.main(["--demo", extra, "--lang", "en"])
            self.assertIn("--demo", str(e.exception))

    def test_dispatch(self):
        with mock.patch.object(cli, "run_cli") as run, mock.patch("panther.__main__.plog.setup"), mock.patch.object(cli.fingerprint, "load_all_oui"):
            cli.main(["--cli"])
            self.assertTrue(run.called)
        with mock.patch("panther.server.serve") as serve, mock.patch("panther.__main__.plog.setup"), mock.patch.object(cli.fingerprint, "load_all_oui"):
            cli.main(["--web", "--port", "9999"])
            serve.assert_called_once_with(9999)


if __name__ == "__main__":
    unittest.main()
