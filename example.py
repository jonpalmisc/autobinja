from binaryninja import BinaryView


def analysis_options():
    """
    Used to specify analysis options.

    Does not need to be defined if default options are acceptable.
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

    Must be defined.
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
