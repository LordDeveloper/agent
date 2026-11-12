"""Stats HTTP routes.

The readable source of this module was truncated to an empty file. The body
below is the last compiled copy (Python 3.11).
"""

from __future__ import annotations

import marshal
from pathlib import Path

_BLOB = Path(__file__).with_name("_stats_body.pyc")
_code = marshal.loads(_BLOB.read_bytes()[16:])
exec(_code, globals())
