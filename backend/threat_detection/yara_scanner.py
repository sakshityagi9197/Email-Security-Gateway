"""YARA scanning helper with optional dependency.

If YARA or libyara.dll is not available, returns a structured skip response
instead of raising an ImportError that crashes the pipeline.
"""

import os
import contextlib
import io

_disable_env = os.getenv("DISABLE_YARA", "0") in ("1", "true", "True")

if _disable_env:
    yara = None  # type: ignore
    _HAVE_YARA = False
    _YARA_IMPORT_ERROR = "disabled via DISABLE_YARA env var"
else:
    try:
        # Suppress noisy prints from yara/libyara_wrapper on failed DLL load
        _sink_out, _sink_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(_sink_out), contextlib.redirect_stderr(_sink_err):
            import yara  # type: ignore
        _HAVE_YARA = True
        _YARA_IMPORT_ERROR = None
    except Exception as _e:  # ImportError or DLL load error on Windows
        yara = None  # type: ignore
        _HAVE_YARA = False
        _YARA_IMPORT_ERROR = str(_e)


def scan_with_yara(file_path: str, yara_rules_path="rules/index.yar") -> dict:
    if not _HAVE_YARA:
        return {
            "skipped": True,
            "reason": "yara library not available",
            "error": _YARA_IMPORT_ERROR,
        }

    try:
        rules = yara.compile(filepath=yara_rules_path)
        matches = rules.match(filepath=file_path)
        return {"matches": [str(m) for m in matches]}
    except Exception as e:
        # Catch yara.Error and any other exceptions consistently
        return {"error": str(e)}
