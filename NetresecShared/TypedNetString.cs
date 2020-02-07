using System;
using System.Collections.Generic;
using System.Text;

namespace NetresecShared {

    /**
     * Source: https://github.com/rfk/tnetstring/blob/master/README.rst
     * 
     * tnetstring:  data serialization using typed netstrings
     * ======================================================
     * 
     * 
     * This is a data serialization library. It's a lot like JSON but it uses a
     * new syntax called "typed netstrings" that Zed has proposed for use in the
     * Mongrel2 webserver.  It's designed to be simpler and easier to implement
     * than JSON, with a happy consequence of also being faster in many cases.
     * 
     * An ordinary netstring is a blob of data prefixed with its length and postfixed
     * with a sanity-checking comma.  The string "hello world" encodes like this::
     * 
     *      11:hello world,
     * 
     * Typed netstrings add other datatypes by replacing the comma with a type tag.
     * Here's the integer 12345 encoded as a tnetstring::
     * 
     *      5:12345#
     * 
     * And here's the list [12345,True,0] which mixes integers and bools::
     * 
     *      19:5:12345#4:true!1:0#]
    **/

    /**
     * Source: https://github.com/mitmproxy/mitmproxy/blob/00902e6febd32fe39ab0de02fd5bd8d44ccff8a0/mitmproxy/io/tnetstring.py
     * tnetstring:  data serialization using typed netstrings
     * ======================================================
     * 
     * This is a custom Python 3 implementation of tnetstrings.
     * Compared to other implementations, the main difference
     * is that this implementation supports a custom unicode datatype.
     * 
     * An ordinary tnetstring is a blob of data prefixed with its length and postfixed
     * with its type. Here are some examples:
     * 
     *     >>> tnetstring.dumps("hello world")
     *     11:hello world,
     *     >>> tnetstring.dumps(12345)
     *     5:12345#
     *     >>> tnetstring.dumps([12345, True, 0])
     *     19:5:12345#4:true!1:0#]
     * 
     **/
    public class TypedNetString {
        private const byte DELIM = (byte)':';
        public enum TypeSuffix : byte {
            ASCIIString = (byte)',',
            Boolean = (byte)'!',
            Dictionary = (byte)'}',
            Float = (byte)'^',
            Integer = (byte)'#',
            List = (byte)']',
            UTF8String = (byte)';',
            Null = (byte)'~'
        }

        //private byte[] valueRaw;
        //private byte[] data;
        private System.IO.Stream data;
        private long offset;
        private long valueOffset;
        private int valueLength;
        

        public TypeSuffix Type { get; }

        public TypedNetString(System.IO.Stream data) {
            this.data = data;
            lock (this.data) {
                this.offset = data.Position;
                int byteRead;
                List<byte> lengthBytes = new List<byte>();
                while ((byteRead = data.ReadByte()) != DELIM) {
                    if (byteRead == -1)
                        throw new System.IO.EndOfStreamException("Reached end of stream while reading length field");
                    lengthBytes.Add((byte)byteRead);
                }
                this.valueLength = 0;
                if (lengthBytes.Count > 0) {
                    string lengthString = System.Text.ASCIIEncoding.ASCII.GetString(lengthBytes.ToArray());
                    if (lengthString.Length > 0)
                        this.valueLength = Int32.Parse(lengthString);
                }
                this.valueOffset = data.Position;
                data.Position += this.valueLength;
                this.Type = (TypeSuffix)data.ReadByte();
            }
        }

        public byte[] GetRawValue() {
            byte[] rawValue;
            lock (this.data) {
                long entryPosition = data.Position;
                data.Position = valueOffset;
                rawValue = new byte[this.valueLength];
                this.data.Read(rawValue, 0, this.valueLength);
                data.Position = entryPosition;
            }
            return rawValue;
        }

        public object GetValue() {
            if (this.Type == TypeSuffix.ASCIIString)
                return System.Text.ASCIIEncoding.ASCII.GetString(this.GetRawValue());
            else if (this.Type == TypeSuffix.Boolean)
                return Boolean.Parse(System.Text.ASCIIEncoding.ASCII.GetString(this.GetRawValue()));
            else if (this.Type == TypeSuffix.Dictionary) {
                Dictionary<string, object> dict = new Dictionary<string, object>();
                lock (this.data) {
                    long entryPosition = data.Position;
                    this.data.Position = this.valueOffset;
                    while (this.data.Position < this.data.Length && this.data.Position < this.valueOffset + this.valueLength) {
                        TypedNetString key = new TypedNetString(this.data);
                        TypedNetString value = new TypedNetString(this.data);
                        dict.Add((string)key.GetValue(), value.GetValue());
                    }
                    data.Position = entryPosition;
                }
                return dict;
            }
            else if (this.Type == TypeSuffix.Float)
                return float.Parse(System.Text.ASCIIEncoding.ASCII.GetString(this.GetRawValue()));
            else if (this.Type == TypeSuffix.Integer)
                return Int32.Parse(System.Text.ASCIIEncoding.ASCII.GetString(this.GetRawValue()));
            else if (this.Type == TypeSuffix.List) {
                List<object> list = new List<object>();
                lock(this.data) {
                    long entryPosition = data.Position;
                    this.data.Position = this.valueOffset;
                    while (this.data.Position < this.data.Length && this.data.Position < this.valueOffset + this.valueLength) {
                        TypedNetString item = new TypedNetString(this.data);
                        list.Add(item.GetValue());
                    }
                    data.Position = entryPosition;
                }
                return list;
            }
            else if (this.Type == TypeSuffix.UTF8String)
                return System.Text.UTF8Encoding.UTF8.GetString(this.GetRawValue());
            else
                return null;
        }
    }
}
