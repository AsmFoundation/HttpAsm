"""where.py REPORT LIBRARY: names every location memcheck reported inside LIBRARY (tests/ct/run.sh
runs it on valgrind's output). valgrind names only sized function symbols, so the assembly's
internal routines (NASM's labels) show as "???"; this maps each address to the nearest symbol at
or below it in the library's .symtab, using the load address tests/native/ct prints (dladdr's
"ct: base 0x..."). Prints one line per distinct (report kind, symbol+offset), with how many
times memcheck counted it, sorted by symbol; prints nothing when memcheck reported nothing.
Exit status: 0; 2 when the report has no "ct: base" line or nm fails.
"""
import bisect
import collections
import re
import subprocess
import sys


def main() -> int:
    """Reads the report, maps its frames, prints the summary (see the module's docstring).

    Returns:
        0 when the summary was printed (empty when memcheck reported nothing); 2 on wrong usage,
        when nm fails, or when the report lacks tests/native/ct's "ct: base" line (without the
        load address no frame can be named).
    """
    if len(sys.argv) != 3:
        print('usage: where.py REPORT LIBRARY', file=sys.stderr)
        return 2
    report, library = sys.argv[1], sys.argv[2]
    listing = subprocess.run(['nm', '-n', library], capture_output=True, text=True)
    if listing.returncode != 0:
        print(f'where.py: nm failed on {library}', file=sys.stderr)
        return 2
    symbols = []
    for line in listing.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1].lower() in ('t', 'r', 'd', 'b'):
            symbols.append((int(parts[0], 16), parts[2]))
    symbols.sort()
    starts = [address for address, _ in symbols]

    text = open(report, errors='replace').read()
    base_line = re.search(r'ct: base (0x[0-9a-f]+) ', text)
    if base_line is None:
        print('where.py: the report has no "ct: base" line (tests/native/ct prints it)', file=sys.stderr)
        return 2
    base = int(base_line.group(1), 16)

    def name(address: int) -> str:
        """The nearest named symbol at or below an address, as name+offset; NASM's macro-local
        labels (..@N.label) are shown in brackets after the nearest real label above them.

        Args:
            address: a code address as valgrind printed it (in the process: load base included).

        Returns:
            "symbol+0xoffset", with " [..@N.label]" when a macro-local label is nearer; the
            address in hex when it lies below the library's first symbol.
        """
        i = bisect.bisect_right(starts, address - base) - 1
        if i < 0:
            return hex(address)
        j = i
        while j > 0 and symbols[j][1].startswith('..@'):
            j -= 1
        label = f' [{symbols[i][1]}]' if j != i else ''
        return f'{symbols[j][1]}+{address - base - symbols[j][0]:#x}{label}'

    counts = collections.Counter()
    for block in re.split(r'==\d+== \n', text):
        kind = re.search(r'(Conditional jump or move depends on uninitialised value\(s\)|'
                         r'Use of uninitialised value of size \d+|Syscall param [^\n]+|'
                         r'Invalid \w+ of size \d+)', block)
        frame = re.search(r'at 0x([0-9A-F]+): (\S+) \(in ([^)]+)\)', block)
        if not kind or not frame:
            continue
        where = frame.group(3)
        label = name(int(frame.group(1), 16)) if where == library else f'{frame.group(2)} (in {where.split("/")[-1]})'
        counts[(label, kind.group(1).split(' depends')[0])] += 1
    for (label, kind), n in sorted(counts.items()):
        print(f'{n:4} {kind:40} {label}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
