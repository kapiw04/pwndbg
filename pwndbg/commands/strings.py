from __future__ import annotations
import argparse
from typing import List
import pwndbg
import pwndbg.commands
import pwndbg.aglib.memory
from pwndbg.commands import CommandCategory

import re

from pwndbg.lib.memory import Page 

if pwndbg.dbg.is_gdblib_available():
    import gdb # type: ignore

parser = argparse.ArgumentParser(description="Calculate VA of RVA from PIE base.")

@pwndbg.commands.ArgparsedCommand(parser, command_name="strings", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def strings():
    """
    Extracts and displays ASCII strings from all readable memory pages of the debugged process.
    Only pages with read permissions (PF_R) are processed. See PF_X, PF_R, PF_W
    """

    # extract pages with readable permission
    readable_pages: List[Page] = [page for page in pwndbg.aglib.vmmap.get() if page.flags & 4] 

    for page in readable_pages:
        count = page.end - page.start
        start_address = page.vaddr

        try:
            data = pwndbg.aglib.memory.read(addr=start_address, count=count)
        except pwndbg.dbg_mod.Error as e:
            print(f"Skipping inaccessible page at {start_address:#x}: {e}")
            continue  # skip if access is denied
        
        # all strings in the `data`
        # TODO: parametrize the filter size. for now returns only strings longer than **4** characters
        strings = re.findall(rb'[ -~]{4,}', data)
        decoded_strings = [s.decode('utf-8', errors='ignore') for s in strings]
        for string in decoded_strings:
            print(string)

