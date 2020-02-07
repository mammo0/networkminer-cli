/*
 * Copyright 2014 Twitter, Inc
 * This file is a derivative work modified by Ringo Leese and Erik Hjelmvik
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.IO;

namespace PacketParser.Utils {
	/// <summary>
	/// The HuffmanDecoder class
	/// </summary>
	public class HuffmanDecoder
	{
        private const int HUFFMAN_EOS = 256;
        private Node root = null;

        /// <summary>
		/// Appendix B: Huffman Codes
		/// </summary>
		/// <note type="rfc">http://tools.ietf.org/html/rfc7541#appendix-B</note>
		public static readonly IReadOnlyList<int> HPACK_HUFFMAN_CODES = new int[] {
            0x1ff8,
            0x7fffd8,
            0xfffffe2,
            0xfffffe3,
            0xfffffe4,
            0xfffffe5,
            0xfffffe6,
            0xfffffe7,
            0xfffffe8,
            0xffffea,
            0x3ffffffc,
            0xfffffe9,
            0xfffffea,
            0x3ffffffd,
            0xfffffeb,
            0xfffffec,
            0xfffffed,
            0xfffffee,
            0xfffffef,
            0xffffff0,
            0xffffff1,
            0xffffff2,
            0x3ffffffe,
            0xffffff3,
            0xffffff4,
            0xffffff5,
            0xffffff6,
            0xffffff7,
            0xffffff8,
            0xffffff9,
            0xffffffa,
            0xffffffb,
            0x14,
            0x3f8,
            0x3f9,
            0xffa,
            0x1ff9,
            0x15,
            0xf8,
            0x7fa,
            0x3fa,
            0x3fb,
            0xf9,
            0x7fb,
            0xfa,
            0x16,
            0x17,
            0x18,
            0x0,
            0x1,
            0x2,
            0x19,
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
            0x5c,
            0xfb,
            0x7ffc,
            0x20,
            0xffb,
            0x3fc,
            0x1ffa,
            0x21,
            0x5d,
            0x5e,
            0x5f,
            0x60,
            0x61,
            0x62,
            0x63,
            0x64,
            0x65,
            0x66,
            0x67,
            0x68,
            0x69,
            0x6a,
            0x6b,
            0x6c,
            0x6d,
            0x6e,
            0x6f,
            0x70,
            0x71,
            0x72,
            0xfc,
            0x73,
            0xfd,
            0x1ffb,
            0x7fff0,
            0x1ffc,
            0x3ffc,
            0x22,
            0x7ffd,
            0x3,
            0x23,
            0x4,
            0x24,
            0x5,
            0x25,
            0x26,
            0x27,
            0x6,
            0x74,
            0x75,
            0x28,
            0x29,
            0x2a,
            0x7,
            0x2b,
            0x76,
            0x2c,
            0x8,
            0x9,
            0x2d,
            0x77,
            0x78,
            0x79,
            0x7a,
            0x7b,
            0x7ffe,
            0x7fc,
            0x3ffd,
            0x1ffd,
            0xffffffc,
            0xfffe6,
            0x3fffd2,
            0xfffe7,
            0xfffe8,
            0x3fffd3,
            0x3fffd4,
            0x3fffd5,
            0x7fffd9,
            0x3fffd6,
            0x7fffda,
            0x7fffdb,
            0x7fffdc,
            0x7fffdd,
            0x7fffde,
            0xffffeb,
            0x7fffdf,
            0xffffec,
            0xffffed,
            0x3fffd7,
            0x7fffe0,
            0xffffee,
            0x7fffe1,
            0x7fffe2,
            0x7fffe3,
            0x7fffe4,
            0x1fffdc,
            0x3fffd8,
            0x7fffe5,
            0x3fffd9,
            0x7fffe6,
            0x7fffe7,
            0xffffef,
            0x3fffda,
            0x1fffdd,
            0xfffe9,
            0x3fffdb,
            0x3fffdc,
            0x7fffe8,
            0x7fffe9,
            0x1fffde,
            0x7fffea,
            0x3fffdd,
            0x3fffde,
            0xfffff0,
            0x1fffdf,
            0x3fffdf,
            0x7fffeb,
            0x7fffec,
            0x1fffe0,
            0x1fffe1,
            0x3fffe0,
            0x1fffe2,
            0x7fffed,
            0x3fffe1,
            0x7fffee,
            0x7fffef,
            0xfffea,
            0x3fffe2,
            0x3fffe3,
            0x3fffe4,
            0x7ffff0,
            0x3fffe5,
            0x3fffe6,
            0x7ffff1,
            0x3ffffe0,
            0x3ffffe1,
            0xfffeb,
            0x7fff1,
            0x3fffe7,
            0x7ffff2,
            0x3fffe8,
            0x1ffffec,
            0x3ffffe2,
            0x3ffffe3,
            0x3ffffe4,
            0x7ffffde,
            0x7ffffdf,
            0x3ffffe5,
            0xfffff1,
            0x1ffffed,
            0x7fff2,
            0x1fffe3,
            0x3ffffe6,
            0x7ffffe0,
            0x7ffffe1,
            0x3ffffe7,
            0x7ffffe2,
            0xfffff2,
            0x1fffe4,
            0x1fffe5,
            0x3ffffe8,
            0x3ffffe9,
            0xffffffd,
            0x7ffffe3,
            0x7ffffe4,
            0x7ffffe5,
            0xfffec,
            0xfffff3,
            0xfffed,
            0x1fffe6,
            0x3fffe9,
            0x1fffe7,
            0x1fffe8,
            0x7ffff3,
            0x3fffea,
            0x3fffeb,
            0x1ffffee,
            0x1ffffef,
            0xfffff4,
            0xfffff5,
            0x3ffffea,
            0x7ffff4,
            0x3ffffeb,
            0x7ffffe6,
            0x3ffffec,
            0x3ffffed,
            0x7ffffe7,
            0x7ffffe8,
            0x7ffffe9,
            0x7ffffea,
            0x7ffffeb,
            0xffffffe,
            0x7ffffec,
            0x7ffffed,
            0x7ffffee,
            0x7ffffef,
            0x7fffff0,
            0x3ffffee,
            0x3fffffff // EOS
		};

    /// <summary>
    /// The Huffman code lengths.
    /// </summary>
    public static readonly IReadOnlyList<byte> HPACK_HUFFMAN_CODE_LENGTHS = new byte[] {
            13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
            28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
            6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
            5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
            13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
            7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
            15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
            6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
            20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
            24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
            22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
            21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
            26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
            19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
            20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
            26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
            30 // EOS
};


        public HuffmanDecoder() : this (HPACK_HUFFMAN_CODES, HPACK_HUFFMAN_CODE_LENGTHS) {

        }
        /// <summary>
        /// Creates a new Huffman decoder with the specified Huffman coding.
        /// </summary>
        /// <param name="codes">the Huffman codes indexed by symbol</param>
        /// <param name="lengths">the length of each Huffman code</param>
        public HuffmanDecoder(IReadOnlyList<int> codes, IReadOnlyList<byte> lengths)
		{
			if (codes.Count != 257 || codes.Count != lengths.Count) {
				throw new ArgumentException("invalid Huffman coding");
			}
			this.root = BuildTree(codes, lengths);
		}

		/// <summary>
		/// Decompresses the given Huffman coded string literal.
		/// </summary>
		/// <param name="buf">the string literal to be decoded</param>
		/// <returns>the output stream for the compressed data</returns>
		/// <exception cref="IOException">throws IOException if an I/O error occurs. In particular, an <code>IOException</code> may be thrown if the output stream has been closed.</exception>
		public byte[] Decode(byte[] buf)
		{
			using(var baos = new MemoryStream()) {
				var node = this.root;
				var current = 0;
				var bits = 0;
				for(var i = 0; i < buf.Length; i++) {
					var b = buf[i] & 0xFF;
					current = (current << 8) | b;
					bits += 8;
					while(bits >= 8) {
						var c = (current >> (bits - 8)) & 0xFF;
						node = node.Children[c];
						bits -= node.Bits;
						if (node.IsTerminal()) {
							if (node.Symbol == HUFFMAN_EOS) {
								throw new IOException("EOS Decoded");
							}
							baos.Write(new byte[] { (byte)node.Symbol }, 0, 1);
							node = this.root;
						}
					}
				}

				while(bits > 0) {
					var c = (current << (8 - bits)) & 0xFF;
					node = node.Children[c];
					if (node.IsTerminal() && node.Bits <= bits) {
						bits -= node.Bits;
						baos.Write(new byte[] { (byte)node.Symbol }, 0, 1);
						node = this.root;
					} else {
						break;
					}
				}

				// Section 5.2. String Literal Representation
				// Padding not corresponding to the most significant bits of the code
				// for the EOS symbol (0xFF) MUST be treated as a decoding error.
				var mask = (1 << bits) - 1;
				if ((current & mask) != mask) {
					throw new IOException("Invalid Padding");
				}

				return baos.ToArray();
			}
		}

		/// <summary>
		/// The Node class
		/// </summary>
		public class Node
		{
			private int symbol;
			// terminal nodes have a symbol
			private int bits;
			// number of bits matched by the node
			private Node[] children;
			// internal nodes have children

			/// <summary>
			/// The Symbol.
			/// </summary>
			public int Symbol { get { return this.symbol; } }

			/// <summary>
			/// The Bits.
			/// </summary>
			public int Bits { get { return this.bits; } }

			/// <summary>
			/// The Children.
			/// </summary>
			public Node[] Children { get { return this.children; } }

			/// <summary>
			/// Initializes a new instance of the HuffmanDecoder.Node class.
			/// </summary>
			public Node()
			{
				this.symbol = 0;
				this.bits = 8;
				this.children = new Node[256];
			}

			/// <summary>
			/// Initializes a new instance of the HuffmanDecoder.Node class.
			/// </summary>
			/// <param name="symbol">the symbol the node represents</param>
			/// <param name="bits">the number of bits matched by this node</param>
			public Node(int symbol, int bits)
			{
				//assert(bits > 0 && bits <= 8);
				this.symbol = symbol;
				this.bits = bits;
				this.children = null;
			}

			public bool IsTerminal()
			{
				return (this.children == null) ? true : false;
			}
		}

		private static Node BuildTree(IReadOnlyList<int> codes, IReadOnlyList<byte> lengths)
		{
			var root = new Node();
			for(var i = 0; i < codes.Count; i++) {
				Insert(root, i, codes[i], lengths[i]);
			}
			return root;
		}

		private static void Insert(Node root, int symbol, int code, byte length)
		{
			// traverse tree using the most significant bytes of code
			var current = root;
			while(length > 8) {
				if (current.IsTerminal()) {
					throw new InvalidDataException("invalid Huffman code: prefix not unique");
				}
				length -= 8;
				var i = (code >> length) & 0xFF;
				if (current.Children[i] == null) {
					current.Children[i] = new Node();
				}
				current = current.Children[i];
			}

			var terminal = new Node(symbol, length);
			var shift = 8 - length;
			var start = (code << shift) & 0xFF;
			var end = 1 << shift;
			for(var i = start; i < start + end; i++) {
				current.Children[i] = terminal;
			}
		}
	}
}
