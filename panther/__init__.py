"""Panther : scanner et cartographie de réseau local."""

__version__ = "0.1.0"

import logging as _logging

_logging.getLogger("panther").addHandler(_logging.NullHandler())  # silencieux tant que le journal n'est pas configuré
