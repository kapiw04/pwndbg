from __future__ import annotations
import argparse
import os
from typing import List
import pwndbg
import pwndbg.commands
import pwndbg.aglib.memory
from pwndbg.commands import CommandCategory

import re

from pwndbg.lib.memory import Page 

if pwndbg.dbg.is_gdblib_available():
    import gdb # type: ignore

parser = argparse.ArgumentParser(description="Extracts and displays ASCII strings from all readable memory pages of the debugged process.")

parser.add_argument(
    "-n",                 type=int,            default=4,    help="Minimum length of ASCII strings to include")
parser.add_argument(
    "mapping_name",       type=str, nargs="?", default=None, help="Mapping to search [e.g. libc]")
parser.add_argument(
    "--save-as",          type=str,            default=None, help="Sets the filename for the output of this command [e.g. --save-as='out.txt']")

@pwndbg.commands.ArgparsedCommand(parser, command_name="strings", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def strings(N: int=4, mapping_name: str=None, save_as: str=None):
    """
    Extracts and displays ASCII strings from all readable memory pages of the debugged process.
    Only pages with read permissions (PF_R) are processed. See PF_X, PF_R, PF_W
    """

    # extract pages with readable permission
    readable_pages: List[Page] = [page for page in pwndbg.aglib.vmmap.get() if page.flags & 4] 

    if mapping_name:
        readable_pages = [m for m in readable_pages if mapping_name in m.objfile]

    if save_as:
        # create new file if one does not exist
        if not os.path.exists(save_as):
            with open(save_as, 'w') as fp:
                pass
        else:
            # Remove content from a file
            open(save_as, 'w').close() 

    for page in readable_pages:
        count = page.end - page.start
        start_address = page.vaddr

        try:
            data = pwndbg.aglib.memory.read(addr=start_address, count=count)
        except pwndbg.dbg_mod.Error as e:
            print(f"Skipping inaccessible page at {start_address:#x}: {e}")
            continue  # skip if access is denied
        
        # all strings in the `data`
        strings: List[bytes] = re.findall(rb'[ -~]{%d,}' % N, data)
        decoded_strings: List[str] = [s.decode('ascii', errors='ignore') for s in strings]

        if not save_as:
            for string in decoded_strings:
                print(string)
            continue

        with open(save_as, "a") as f:
           f.writelines(string + "\n" for string in decoded_strings)