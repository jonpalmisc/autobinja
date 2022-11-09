# example.py
#
# This is an example user script for use with Autobinja. It defines all of the
# possible user script functions, but specifies which are required and which can
# be omitted if not needed.

from binaryninja import BinaryView


def analysis_options():
    """
    Used to specify analysis option overrides.

    Can be left undefined if the default options are acceptable.
    """

    return {
        "analysis.mode": "controlFlow",
        "files.universal.architecturePreference": ["arm64"],
    }


def is_ready(bv: BinaryView):
    """
    Tells whether the script is ready to run.

    Typically, this funciton will check for the presence of certain data that
    the script needs to operate.

    If left undefined, the harness will wait for analysis to completely finish.
    """

    return bv.analysis_info.state == 2


def run(bv: BinaryView):
    """
    Perform analysis, patching, etc.

    Must be defined.
    """

    target = bv.get_function_at(0x100003F74)

    patch_code = bv.arch.assemble("mov x0, #0x1234; ret;", target.start)
    bv.write(target.start, patch_code)
