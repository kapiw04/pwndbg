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

parser = argparse.ArgumentParser(description="Extracts and displays ASCII strings from all readable memory pages of the debugged process.")

parser.add_argument(
    "-n",                 type=int,            default=4,    help="Minimum length of ASCII strings to include")
parser.add_argument(
    "mapping_name",       type=str, nargs="?", default=None, help="Mapping to search [e.g. libc]")
parser.add_argument(
    "--save-as",          type=str,            default=None, help="Sets the filename for the output of this command [e.g. --save-as='out.txt']")

@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def strings(n: int=4, mapping_name: str=None, save_as: str=None):
    """
    Extracts and displays ASCII strings from all readable memory pages of the debugged process.
    Only pages with read permissions (PF_R) are processed. See PF_X, PF_R, PF_W
    """

    # extract pages with readable permission
    readable_pages: List[Page] = [page for page in pwndbg.aglib.vmmap.get() if page.flags & 4]

    if mapping_name:
        readable_pages = [m for m in readable_pages if mapping_name in m.objfile]

    for page in readable_pages:
        count = page.memsz
        start_address = page.vaddr

        try:
            data = pwndbg.aglib.memory.read(addr=start_address, count=count)
        except pwndbg.dbg_mod.Error as e:
            print(f"Skipping inaccessible page at {start_address:#x}: {e}")
            continue  # skip if access is denied

        # all strings in the `data`
        strings: List[bytes] = re.findall(rb'[ -~]{%d,}' % n, data)
        decoded_strings: List[str] = [s.decode('ascii', errors='ignore') for s in strings]

        if not save_as:
            for string in decoded_strings:
                print(string)
            continue

        with open(save_as, "w") as f:
           f.writelines(string + "\n" for string in decoded_strings)
