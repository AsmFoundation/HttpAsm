namespace HttpAsm.Tests;

/// <summary>
/// Structural mutations of a DER encoding, for refusal tests that reach every element of a real
/// file rather than the few a hand-written case names: the encoding is parsed into a tree (a
/// constructed element's children, and the DER a primitive OCTET STRING or BIT STRING
/// encapsulates, as PKCS#8 nests a key and a certificate nests a public key), then each element
/// in turn is removed, doubled, followed by a NULL, replaced by a NULL, given the other form,
/// given the next tag number, made unreadable (its length run past its parent's end), or, for
/// an INTEGER, OBJECT IDENTIFIER or BOOLEAN, given another value; every length on the way back
/// to the root is re-encoded in DER's form. Mutations that leave the encoding as it was are
/// skipped. The trees are small (a key file's 10 to 40 elements), so every mutation of every
/// element is a few hundred encodings, deterministic, run in milliseconds.
/// </summary>
internal static class DerMutations
{
    /// <summary>One element of the parsed tree.</summary>
    private sealed class Node
    {
        /// <summary>The identifier octets (one octet, or the high-tag form's several).</summary>
        public byte[] Identifier = [];

        /// <summary>A primitive element's contents (null for a constructed one).</summary>
        public byte[]? Content;

        /// <summary>A constructed element's children, in order (null for a primitive one).</summary>
        public List<Node>? Children;

        /// <summary>The one DER element a primitive OCTET STRING or BIT STRING holds whole, when it
        /// holds one (a key's inner structure, a public key's RSAPublicKey).</summary>
        public Node? Encapsulated;

        /// <summary>Whether <see cref="Encapsulated"/> follows a BIT STRING's unused-bits octet (0).</summary>
        public bool AfterUnusedBits;
    }

    /// <summary>
    /// Every mutation of a DER encoding, named by the element's path (child indices from the
    /// root, "e" where the path enters an encapsulated encoding) and the change.
    /// </summary>
    /// <param name="der">A DER encoding, one element (a definite-length tree).</param>
    /// <returns>The mutated encodings, each with its name.</returns>
    /// <exception cref="ArgumentException">The input is not one DER element the parser takes
    /// (a test's own fixture is wrong: it must fail loudly, not mutate nothing).</exception>
    public static IEnumerable<(string Name, byte[] Encoding)> Of(byte[] der)
    {
        int at = 0;
        Node root = Parse(der, ref at, der.Length) ?? throw new ArgumentException("not a DER element", nameof(der));
        if (at != der.Length)
        {
            throw new ArgumentException("octets after the element", nameof(der));
        }

        var seen = new HashSet<string> { Convert.ToHexString(der) };
        foreach ((string path, Node node) in Walk(root, "root"))
        {
            foreach ((string change, byte[][] replacement) in Changes(node))
            {
                byte[] mutated = Encode(root, node, replacement);
                if (seen.Add(Convert.ToHexString(mutated)))
                {
                    yield return ($"{path}: {change}", mutated);
                }
            }
        }
    }

    /// <summary>Parses one element at <paramref name="at"/>, within <paramref name="end"/>.</summary>
    /// <param name="input">The octets.</param>
    /// <param name="at">Where it starts; moved past it.</param>
    /// <param name="end">Where the enclosing contents end.</param>
    /// <returns>The node, or null when no DER element (definite length) stands there.</returns>
    private static Node? Parse(byte[] input, ref int at, int end)
    {
        int p = at;
        if (end - p < 2)
        {
            return null;
        }

        int idStart = p;
        if ((input[p++] & 0x1F) == 0x1F)
        {
            while (p < end && (input[p] & 0x80) != 0)
            {
                p++;
            }

            if (p >= end)
            {
                return null;
            }

            p++;
        }

        if (p >= end)
        {
            return null;
        }

        int idEnd = p;
        int length = input[p++];
        if (length == 0x80 || length == 0xFF)
        {
            return null;                        // indefinite (not DER), or reserved
        }

        if (length > 0x80)
        {
            int k = length & 0x7F;
            if (k > 3 || end - p < k)
            {
                return null;
            }

            length = 0;
            for (int i = 0; i < k; i++)
            {
                length = (length << 8) | input[p++];
            }
        }

        if (end - p < length)
        {
            return null;
        }

        var node = new Node { Identifier = input[idStart..idEnd] };
        int contentStart = p, contentEnd = p + length;
        if ((input[idStart] & 0x20) != 0)
        {
            node.Children = [];
            int c = contentStart;
            while (c < contentEnd)
            {
                Node? child = Parse(input, ref c, contentEnd);
                if (child is null)
                {
                    return null;
                }

                node.Children.Add(child);
            }
        }
        else
        {
            node.Content = input[contentStart..contentEnd];
            // an OCTET STRING or BIT STRING holding one DER element whole: walked into too
            byte tag = input[idStart];
            int inner = tag == 0x04 ? contentStart : tag == 0x03 && length > 1 && input[contentStart] == 0 ? contentStart + 1 : -1;
            if (inner >= 0)
            {
                int i = inner;
                Node? encapsulated = Parse(input, ref i, contentEnd);
                if (encapsulated is not null && i == contentEnd && (encapsulated.Children is not null || encapsulated.Content!.Length > 0))
                {
                    node.Encapsulated = encapsulated;
                    node.AfterUnusedBits = tag == 0x03;
                }
            }
        }

        at = contentEnd;
        return node;
    }

    /// <summary>Every node with its path, the root first, children in order, encapsulated
    /// encodings entered.</summary>
    /// <param name="node">Where to start.</param>
    /// <param name="path">Its path.</param>
    /// <returns>The nodes.</returns>
    private static IEnumerable<(string Path, Node Node)> Walk(Node node, string path)
    {
        yield return (path, node);
        if (node.Children is not null)
        {
            for (int i = 0; i < node.Children.Count; i++)
            {
                foreach ((string, Node) n in Walk(node.Children[i], $"{path}/{i}"))
                {
                    yield return n;
                }
            }
        }

        if (node.Encapsulated is not null)
        {
            foreach ((string, Node) n in Walk(node.Encapsulated, $"{path}/e"))
            {
                yield return n;
            }
        }
    }

    /// <summary>The changes of one node: what its encoding is replaced by in its parent.</summary>
    /// <param name="node">The node.</param>
    /// <returns>Each change's name and its replacement encodings (none: removed).</returns>
    private static IEnumerable<(string Change, byte[][] Replacement)> Changes(Node node)
    {
        byte[] self = Encode(node, null, []);
        byte[] nul = [0x05, 0x00];
        yield return ("removed", []);
        yield return ("doubled", [self, self]);
        yield return ("followed by NULL", [self, nul]);
        yield return ("replaced by NULL", [nul]);
        byte[] otherForm = (byte[])self.Clone();
        otherForm[0] ^= 0x20;
        yield return ("the other form", [otherForm]);
        if ((self[0] & 0x1F) < 30)
        {
            byte[] nextTag = (byte[])self.Clone();
            nextTag[0]++;
            yield return ("the next tag number", [nextTag]);
        }

        // its identifier, then a length its parent's contents cannot hold
        yield return ("unreadable", [[.. node.Identifier, 0x7F]]);
        if (node.Content is { } c && node.Identifier.Length == 1)
        {
            switch (node.Identifier[0])
            {
                case 0x02:
                    yield return ("zero", [[0x02, 0x01, 0x00]]);
                    yield return ("minus one", [[0x02, 0x01, 0xFF]]);
                    yield return ("times 256", [Der(0x02, [.. c, 0x00])]);
                    yield return ("negative", [Der(0x02, [0x80, .. c])]);
                    break;
                case 0x06 when c.Length > 0:
                    yield return ("another identifier", [Der(0x06, [.. c[..^1], (byte)(c[^1] ^ 1)])]);
                    break;
                case 0x01 when c.Length == 1:
                    yield return ("the other truth", [[0x01, 0x01, (byte)(c[0] == 0 ? 0xFF : 0x00)]]);
                    break;
                case 0x03 when c.Length > 0:
                    yield return ("unused bits", [Der(0x03, [(byte)1, .. c[1..]])]);
                    break;
            }
        }
    }

    /// <summary>A DER element: the one identifier octet, the fewest length octets, the contents.</summary>
    /// <param name="tag">The identifier octet.</param>
    /// <param name="content">The contents.</param>
    /// <returns>The encoding.</returns>
    private static byte[] Der(byte tag, byte[] content) => [tag, .. LengthOf(content.Length), .. content];

    /// <summary>DER's length octets for a count.</summary>
    /// <param name="n">The contents' octets.</param>
    /// <returns>The short form below 128, else the long form in the fewest octets.</returns>
    private static byte[] LengthOf(int n)
    {
        if (n < 128)
        {
            return [(byte)n];
        }

        byte[] be = BitConverter.GetBytes(n).Reverse().SkipWhile(b => b == 0).ToArray();
        return [(byte)(0x80 | be.Length), .. be];
    }

    /// <summary>The tree's encoding with one node's encoding replaced (lengths re-encoded on the
    /// way up).</summary>
    /// <param name="node">The subtree to encode.</param>
    /// <param name="target">The node to replace (null: none).</param>
    /// <param name="replacement">What stands in its place: zero or more encodings.</param>
    /// <returns>The encoding of <paramref name="node"/>; when it is the target itself, its
    /// replacement joined (so the root can be replaced too).</returns>
    private static byte[] Encode(Node node, Node? target, byte[][] replacement)
    {
        if (ReferenceEquals(node, target))
        {
            return [.. replacement.SelectMany(r => r)];
        }

        byte[] content;
        if (node.Children is not null)
        {
            content = [.. node.Children.SelectMany(child => Encode(child, target, replacement))];
        }
        else if (node.Encapsulated is not null)
        {
            byte[] inner = Encode(node.Encapsulated, target, replacement);
            content = node.AfterUnusedBits ? [0x00, .. inner] : inner;
        }
        else
        {
            content = node.Content!;
        }

        return [.. node.Identifier, .. LengthOf(content.Length), .. content];
    }
}
