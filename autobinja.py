#!/usr/bin/env python3

"""
Run an arbitrary Binary Ninja script headlessly

Usage: autobinja.py [-hwqDBO] [--output=PATH] [--refresh=N] <binary> [<script>]

Options:
  -h, --help           Show this help message
  -r, --refresh=N      Check script readiness every N seconds (default: 5)
  -w, --wait           Wait for analysis to complete before running the script
  -q, --quiet          Silence all Binary Ninja log output
  -D, --save-db        Save an analysis database once the script is finished
  -B, --save-bin       Save the binary with any modifications from the script
  -o, --output=PATH    Output name for saved binary (use with -B)
  -O, --overwrite      Overwrite the input binary when saving modifications
"""

import datetime
import importlib.util as ilutil
import sys
import time
from types import ModuleType
from typing import Optional

from docopt import docopt


def timestamp() -> str:
    """Get the current local time in ISO-8601 form."""

    return datetime.datetime.now().isoformat()


def log(*args, **kwargs):
    """Log to standard output."""

    print(f"[Autobinja {timestamp()}]", *args, **kwargs)


def elog(*args, **kwargs):
    """Log to standard error."""

    print(f"[Autobinja {timestamp()}] Error:", *args, file=sys.stderr, **kwargs)


def load_user_script(path: Optional[str]) -> Optional[ModuleType]:
    """Load a user script as a Python module."""

    module = None

    spec = ilutil.spec_from_file_location("script", path)
    if spec:
        module = ilutil.module_from_spec(spec)

        if spec.loader:
            spec.loader.exec_module(module)

    return module


def main():
    args = docopt(__doc__)

    bin_path = args["<binary>"]
    refresh_rate = int(args["--refresh"] or 5)

    # Attempt to import the Binary Ninja API
    try:
        import binaryninja as bn
        from binaryninja import BinaryViewType
    except:
        elog("Could not import Binary Ninja module (check your Python path)")
        return

    log(
        f"Initialized backend ({bn.core_product()} "
        + bn.core_version()
        + f", {hex(bn.core_build_id())})"
    )

    # Silence logs if requested.
    if args["--quiet"]:
        bn.disable_default_log()

    # Load user script as a module; if not provided, this will be `None`!
    script = load_user_script(args["<script>"])

    # Ensure the script has a `run` function if a script was provided; it is the
    # only method that absolutely has to be defined.
    if script and not hasattr(script, "run"):
        elog("Script must define a `run` function")
        return

    # If the user script provides its own analysis options override function,
    # use the overrides provided; otherwise, don't make any changes. In either
    # case, the provided options are applied on top of the local user's default
    # Binary Ninja settings, which need to be accounted for.
    analysis_options = {}
    if script and hasattr(script, "analysis_options"):
        analysis_options = script.analysis_options()

    # The `update_analysis` option is set to false here since we want to start
    # analysis manually and manually control whether we wait for analysis to
    # finish or for a certain condition specified by the user script.
    log(f"Loading binary '{bin_path}'")
    bv = BinaryViewType.get_view_of_file_with_options(
        bin_path, update_analysis=False, options=analysis_options
    )

    # The harness should wait for analysis to complete prior to running the
    # script if either the `-w` (wait) flag was passed, or if the user script
    # does not define a `is_ready` function.
    log("Starting analysis")
    if args["--wait"] or not hasattr(script, "is_ready"):
        log("Waiting for analysis to complete")
        bv.update_analysis_and_wait()
    else:
        bv.update_analysis()

        log("Waiting until user script is ready")
        while not script.is_ready(bv):
            time.sleep(refresh_rate)

    # Run the actual user script (if provided).
    if script:
        log(f"Running user script '{args['<script>']}'")
        script.run(bv)

    # Save an analysis database and/or patched binary if requested.
    if args["--save-db"]:
        log(f"Saving analysis database")
        bv.create_database(bin_path + ".bndb")
    if args["--save-bin"]:
        output_name = bin_path
        if args["--output"]:
            output_name = args["--output"]
        elif not args["--overwrite"]:
            output_name += ".out"

        log(f"Saving binary with modifications as '{output_name}'")
        bv.save(output_name)

    # Analysis might still be going if the script uses a ready condition and
    # should be terminated before exiting.
    bv.abort_analysis()
    log("All tasks complete")


if __name__ == "__main__":
    main()
