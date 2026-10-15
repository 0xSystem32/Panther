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
