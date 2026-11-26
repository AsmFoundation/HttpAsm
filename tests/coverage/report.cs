// =============================================================================
// report.cs - what the tests ran of libhttpasm.so, block by block and branch edge by branch
// edge, and the coverage gate (docs/DESIGN.md section 2: every block runs under the tests, or
// is listed with the reason it cannot).
//
// Reads:
//   - the maps tests/coverage/instrument.cs wrote beside each object of the Coverage build
//     (*.covmap under the projects' obj/Coverage folders): every marker's kind, origin and text;
//   - the dumps tests/coverage/coverage_rt.asm wrote at each process's exit (cov-*.bin in the
//     run's directory): one octet per marker, nonzero when it ran. Every process of the run (the
//     suite at every tier and backend, the native programs natively and under SDE) adds its own,
//     and a marker counts as covered when any of them ran it;
//   - tests/coverage/unreachable.tsv: the markers that cannot run, each with its reason.
// Writes a summary per source file, then every marker that did not run, to stdout (Markdown).
//
// The gate fails (exit 1) on a marker that did not run and is not listed, and on a listed one
// that did run (the list must not go stale); --report-only prints without failing.
// --write-unreachable FILE writes the markers that did not run as a list to start from, each
// reason "TODO", for a person to replace or the tests to remove.
//
// Usage: dotnet run --file tests/coverage/report.cs -- --repo <root> --dumps <dir>
//          [--report-only] [--write-unreachable <file>]
// Exit status: 0, 1 when the gate fails, 2 for a usage error or unreadable input.
// =============================================================================
using System.Text;

return Coverage.Run(args);

/// <summary>The coverage report and gate: see this file's header.</summary>
internal static class Coverage
{
    /// <summary>The magic at the start of every object's region of markers.</summary>
    private static readonly byte[] Magic = "HACOV001"u8.ToArray();

    /// <summary>Sources the Coverage build assembled without markers, each with the reason.</summary>
    private static readonly List<string> Uninstrumented = [];

    /// <summary>One marker of one object.</summary>
    /// <param name="Id">Its index in the object's region.</param>
    /// <param name="Kind">block, taken, fall or dead (instrument.cs).</param>
    /// <param name="File">Its origin's file, relative to the repository.</param>
    /// <param name="Line">Its origin's line.</param>
    /// <param name="Scope">The label scope it is in (the function, usually).</param>
    /// <param name="Text">The labels or the jump it stands for.</param>
    private sealed record Marker(int Id, string Kind, string File, int Line, string Scope, string Text)
    {
        /// <summary>The identity unreachable.tsv lists a marker by: everything but its id.</summary>
        public string Key => $"{File}\t{Line}\t{Kind}\t{Scope}\t{Text}";
    }

    /// <summary>One object's map, and which of its markers ran.</summary>
    /// <param name="Source">The source it came from.</param>
    /// <param name="Markers">Its markers, by id.</param>
    /// <param name="Ran">One flag per marker.</param>
    private sealed record ObjectMap(string Source, List<Marker> Markers, bool[] Ran);

    /// <summary>Runs the report: see this file's header.</summary>
    /// <param name="args">The command line.</param>
    /// <returns>0, 1 when the gate fails, 2 for a usage error or unreadable input.</returns>
    public static int Run(string[] args)
    {
        string? repo = null, dumps = null, writeUnreachable = null;
        bool reportOnly = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--repo" when i + 1 < args.Length: repo = args[++i]; break;
                case "--dumps" when i + 1 < args.Length: dumps = args[++i]; break;
                case "--write-unreachable" when i + 1 < args.Length: writeUnreachable = args[++i]; break;
                case "--report-only": reportOnly = true; break;
                default:
                    Console.Error.WriteLine($"report.cs: unknown argument {args[i]}");
                    return 2;
            }
        }

        if (repo is null || dumps is null)
        {
            Console.Error.WriteLine("report.cs: usage: --repo <root> --dumps <dir> [--report-only] [--write-unreachable <file>]");
            return 2;
        }

        repo = Path.GetFullPath(repo).Replace('\\', '/').TrimEnd('/') + "/";
        Dictionary<ulong, ObjectMap> maps;
        try
        {
            maps = ReadMaps(repo);
            int dumped = ReadDumps(dumps, maps);
            if (dumped == 0)
            {
                Console.Error.WriteLine($"report.cs: no cov-*.bin in {dumps}: did any process of the run load the Coverage build?");
                return 2;
            }

            Console.WriteLine($"Coverage of libhttpasm.so: {maps.Count} objects, {maps.Values.Sum(m => m.Markers.Count)} markers, {dumped} process dumps.");
            Console.WriteLine();
        }
        catch (InvalidDataException e)
        {
            Console.Error.WriteLine($"report.cs: {e.Message}");
            return 2;
        }

        var notRun = maps.Values.SelectMany(m => m.Markers.Where(k => !m.Ran[k.Id])).ToList();
        PrintSummary(maps.Values);
        if (Uninstrumented.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Not instrumented ({Uninstrumented.Count}; these have no markers, so the gate cannot see their code):");
            foreach (string note in Uninstrumented.Order(StringComparer.Ordinal))
            {
                Console.WriteLine($"- {note}");
            }
        }

        PrintNotRun(notRun);

        if (writeUnreachable is not null)
        {
            WriteList(writeUnreachable, notRun);
        }

        string listPath = Path.Combine(repo, "tests/coverage/unreachable.tsv");
        Dictionary<string, int> listed;
        try
        {
            listed = ReadList(listPath);
        }
        catch (InvalidDataException e)
        {
            Console.Error.WriteLine($"report.cs: {e.Message}");
            return 2;
        }
        var notRunKeys = notRun.GroupBy(m => m.Key).ToDictionary(g => g.Key, g => g.Count());
        var unlisted = notRunKeys.Where(p => p.Value > listed.GetValueOrDefault(p.Key)).ToList();
        var stale = listed.Where(p => p.Value > notRunKeys.GetValueOrDefault(p.Key)).ToList();
        Console.WriteLine();
        Console.WriteLine($"Gate: {notRun.Count} markers did not run; {unlisted.Sum(p => p.Value - listed.GetValueOrDefault(p.Key))} of them are not in tests/coverage/unreachable.tsv; {stale.Count} listed entries ran or no longer exist.");
        foreach (var (key, _) in stale)
        {
            Console.WriteLine($"- stale: {key.Replace('\t', ' ')}");
        }

        return reportOnly || (unlisted.Count == 0 && stale.Count == 0) ? 0 : 1;
    }

    /// <summary>
    /// Reads every .covmap under the projects' obj/Coverage folders, keyed by the region hash
    /// their header names.
    /// </summary>
    /// <param name="repo">The repository root, with a trailing slash.</param>
    /// <returns>The maps.</returns>
    /// <exception cref="InvalidDataException">A map without its header, or with a malformed line.</exception>
    private static Dictionary<ulong, ObjectMap> ReadMaps(string repo)
    {
        var maps = new Dictionary<ulong, ObjectMap>();
        foreach (string project in new[] { "src/HttpAsm.Core", "src/HttpAsm" })
        {
            string obj = Path.Combine(repo, project, "obj", "Coverage");
            if (!Directory.Exists(obj))
            {
                throw new InvalidDataException($"{obj} is missing: build the Coverage configuration first (tests/coverage/run.sh)");
            }

            foreach (string path in Directory.EnumerateFiles(obj, "*.covmap", SearchOption.AllDirectories))
            {
                string[] lines = File.ReadAllLines(path);
                // "# source", path, "hash", hex, "count", n (instrument.cs writes it so).
                string[] header = lines.Length > 0 ? lines[0].Split('\t') : [];
                if (header.Length != 6 || header[0] != "# source" || header[2] != "hash" || header[4] != "count")
                {
                    throw new InvalidDataException($"{path}: no '# source' header");
                }

                ulong hash = Convert.ToUInt64(header[3], 16);
                int count = int.Parse(header[5]);
                var markers = new List<Marker>(count);
                foreach (string line in lines.Skip(1))
                {
                    if (line.StartsWith("# uninstrumented", StringComparison.Ordinal))
                    {
                        // instrument.cs could not preprocess the source alone (an %if over
                        // symbols) and assembled it as it is: shown, never silently dropped.
                        Uninstrumented.Add($"{Relative(repo, header[1])}: {line["# uninstrumented".Length..].Trim()}");
                        continue;
                    }

                    string[] f = line.Split('\t');
                    if (f.Length != 6)
                    {
                        throw new InvalidDataException($"{path}: malformed line: {line}");
                    }

                    markers.Add(new Marker(int.Parse(f[0]), f[1], Relative(repo, f[2]), int.Parse(f[3]), f[4], f[5]));
                }

                if (markers.Count != count)
                {
                    throw new InvalidDataException($"{path}: {markers.Count} markers, the header says {count}");
                }

                maps[hash] = new ObjectMap(Relative(repo, header[1]), markers, new bool[count]);
            }
        }

        return maps;
    }

    /// <summary>
    /// ORs every dump of the run into the maps: each dump is the whole "ha_cov" section, one
    /// region per object (magic, hash, count, the marker octets), each starting at a multiple of 8.
    /// </summary>
    /// <param name="dumps">The run's directory.</param>
    /// <param name="maps">The maps, by hash.</param>
    /// <returns>How many dumps were read.</returns>
    /// <exception cref="InvalidDataException">A region whose object has no map, or whose count
    /// differs from its map's (a dump from another build).</exception>
    private static int ReadDumps(string dumps, Dictionary<ulong, ObjectMap> maps)
    {
        int read = 0;
        foreach (string path in Directory.Exists(dumps) ? Directory.EnumerateFiles(dumps, "cov-*.bin") : [])
        {
            byte[] data = File.ReadAllBytes(path);
            int at = 0;
            while (at + 24 <= data.Length)
            {
                if (!data.AsSpan(at, 8).SequenceEqual(Magic))
                {
                    at += 8;                    // the linker's padding between regions
                    continue;
                }

                ulong hash = BitConverter.ToUInt64(data, at + 8);
                long count = BitConverter.ToInt64(data, at + 16);
                if (!maps.TryGetValue(hash, out ObjectMap? map) || map.Markers.Count != count || at + 24 + count > data.Length)
                {
                    throw new InvalidDataException($"{path}: a region (hash {hash:X16}, {count} markers) this build has no map for");
                }

                for (int i = 0; i < count; i++)
                {
                    map.Ran[i] |= data[at + 24 + i] != 0;
                }

                at += 24 + (int)count;
                at = (at + 7) & ~7;
            }

            read++;
        }

        return read;
    }

    /// <summary>Prints, per source file, how many blocks and branch edges ran.</summary>
    /// <param name="maps">Every object's map.</param>
    private static void PrintSummary(IEnumerable<ObjectMap> maps)
    {
        Console.WriteLine("| File | Blocks run | Branch edges run | Dead code |");
        Console.WriteLine("|---|---:|---:|---:|");
        var all = maps.SelectMany(m => m.Markers.Select(k => (Marker: k, Ran: m.Ran[k.Id]))).ToList();
        foreach (var file in all.GroupBy(x => x.Marker.File).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            Console.WriteLine($"| {file.Key} | {Ratio(file, "block")} | {Ratio(file, "taken", "fall")} | {file.Count(x => x.Marker.Kind == "dead")} |");
        }

        Console.WriteLine($"| **all** | {Ratio(all, "block")} | {Ratio(all, "taken", "fall")} | {all.Count(x => x.Marker.Kind == "dead")} |");

        static string Ratio(IEnumerable<(Marker Marker, bool Ran)> set, params string[] kinds)
        {
            var of = set.Where(x => kinds.Contains(x.Marker.Kind)).ToList();
            int ran = of.Count(x => x.Ran);
            return of.Count == 0 ? "-" : $"{ran}/{of.Count} ({100.0 * ran / of.Count:0.0}%)";
        }
    }

    /// <summary>Prints every marker that did not run, by file and line.</summary>
    /// <param name="notRun">The markers.</param>
    private static void PrintNotRun(List<Marker> notRun)
    {
        Console.WriteLine();
        Console.WriteLine($"Not run ({notRun.Count}):");
        foreach (var m in notRun.OrderBy(m => m.File, StringComparer.Ordinal).ThenBy(m => m.Line))
        {
            Console.WriteLine($"- {m.File}:{m.Line} {m.Kind} in {m.Scope}: {m.Text}");
        }
    }

    /// <summary>Writes markers as an unreachable.tsv to start from, each reason "TODO".</summary>
    /// <param name="path">The file.</param>
    /// <param name="markers">The markers.</param>
    private static void WriteList(string path, List<Marker> markers)
    {
        var text = new StringBuilder("# file\tline\tkind\tscope\ttext\treason\n");
        foreach (var m in markers.OrderBy(m => m.File, StringComparer.Ordinal).ThenBy(m => m.Line))
        {
            text.Append(m.Key).Append("\tTODO\n");
        }

        File.WriteAllText(path, text.ToString());
    }

    /// <summary>Reads unreachable.tsv as a multiset of marker keys (a missing file is empty).</summary>
    /// <param name="path">The file.</param>
    /// <returns>Each key and how many markers it covers.</returns>
    /// <exception cref="InvalidDataException">A line without its six fields, or a reason left "TODO".</exception>
    private static Dictionary<string, int> ReadList(string path)
    {
        var listed = new Dictionary<string, int>(StringComparer.Ordinal);
        if (!File.Exists(path))
        {
            return listed;
        }

        foreach (string line in File.ReadAllLines(path))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string[] f = line.Split('\t');
            if (f.Length != 6 || f[5].Length == 0 || f[5] == "TODO")
            {
                throw new InvalidDataException($"{path}: every entry needs file, line, kind, scope, text and a real reason: {line}");
            }

            string key = string.Join('\t', f[..5]);
            listed[key] = listed.GetValueOrDefault(key) + 1;
        }

        return listed;
    }

    /// <summary>A path relative to the repository, with forward slashes.</summary>
    /// <param name="repo">The repository root, with a trailing slash.</param>
    /// <param name="path">An absolute or relative path.</param>
    /// <returns>The relative path, or the path itself when outside the repository.</returns>
    private static string Relative(string repo, string path)
    {
        string full = path.Replace('\\', '/');
        return full.StartsWith(repo, StringComparison.OrdinalIgnoreCase) ? full[repo.Length..] : full;
    }
}
