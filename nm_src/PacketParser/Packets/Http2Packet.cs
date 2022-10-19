using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace PacketParser.Packets {

    //https://tools.ietf.org/html/rfc7540
    public class Http2Packet : AbstractPacket, ISessionPacket {

        public const string CLIENT_CONNECTION_PREFACE_STRING = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        public static readonly byte[] CLIENT_CONNECTION_PREFACE_BYTES = { 0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a };

        /**
         *   +---------------+------+--------------+
         *   | Frame Type    | Code | Section      |
         *   +---------------+------+--------------+
         *   | DATA          | 0x0  | Section 6.1  |
         *   | HEADERS       | 0x1  | Section 6.2  |
         *   | PRIORITY      | 0x2  | Section 6.3  |
         *   | RST_STREAM    | 0x3  | Section 6.4  |
         *   | SETTINGS      | 0x4  | Section 6.5  |
         *   | PUSH_PROMISE  | 0x5  | Section 6.6  |
         *   | PING          | 0x6  | Section 6.7  |
         *   | GOAWAY        | 0x7  | Section 6.8  |
         *   | WINDOW_UPDATE | 0x8  | Section 6.9  |
         *   | CONTINUATION  | 0x9  | Section 6.10 |
         *   +---------------+------+--------------+
         *   
         *   
         **/
         public enum FrameType : byte {
            DATA = 0x0,
            HEADERS = 0x1,
            PRIORITY = 0x2,
            RST_STREAM = 0x3,
            SETTINGS = 0x4,
            PUSH_PROMISE = 0x5,
            PING = 0x6,
            GOAWAY = 0x7,
            WINDOW_UPDATE = 0x8,
            CONTINUATION = 0x9
        }

        /**
         *     +-----------------------------------------------+
         *     |                 Length (24)                   |
         *     +---------------+---------------+---------------+
         *     |   Type (8)    |   Flags (8)   |
         *     +-+-------------+---------------+-------------------------------+
         *     |R|                 Stream Identifier (31)                      |
         *     +=+=============================================================+
         *     |                   Frame Payload (0...)                      ...
         *     +---------------------------------------------------------------+
         **/

        private readonly int prefaceBytes = 0;

        public int Length { get; }
        //internal int TotalLength { get { return this.prefaceBytes + 9 + this.Length; } }
        public FrameType Type { get; }
        public byte FlagsRaw { get; }
        public bool FlagEndStream { get { return (this.FlagsRaw & 0x01) == 0x01; } }
        public bool FlagEndHeaders { get { return (this.FlagsRaw & 0x04) == 0x04; } }
        public bool FlagPadded { get { return (this.FlagsRaw & 0x08) == 0x08; } }
        public bool FlagPriority { get { return (this.FlagsRaw & 0x20) == 0x20; } }

        public int StreamIdentifier { get; }
        public IEnumerable<byte> Payload { get { return this.ParentFrame.Data.Skip(this.PacketStartIndex + this.prefaceBytes + 9).Take(this.Length); } }

        public bool PacketHeaderIsComplete { get { return this.ParsedBytesCount > 0; } }

        public int ParsedBytesCount {
            get {
                if (this.ParentFrame.Data.Length >= this.PacketStartIndex + this.prefaceBytes + 9 + this.Length)
                    return this.prefaceBytes + 9 + this.Length;
                else
                    return 0;
            }
        }

        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            int index = packetStartIndex;
            int dataLength = packetEndIndex - index + 1;
            if (dataLength >= CLIENT_CONNECTION_PREFACE_BYTES.Length && CLIENT_CONNECTION_PREFACE_BYTES.SequenceEqual(parentFrame.Data.Skip(index).Take(CLIENT_CONNECTION_PREFACE_BYTES.Length))) {
                index += CLIENT_CONNECTION_PREFACE_BYTES.Length;
            }
            if (parentFrame.Data.Length < index + 9) {
                result = null;
                return false;
            }
            int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data.Skip(index).Take(3).ToArray());
            if (parentFrame.Data.Length < index + 9 + length) {
                result = null;
                return false;
            }
            if (!Enum.IsDefined(typeof(FrameType), parentFrame.Data[index + 3])) {
                result = null;
                return false;
            }
            try {
                result = new Http2Packet(parentFrame, packetStartIndex, packetEndIndex);
                return true;
            }
            catch {
                result = null;
                return false;
            }
        }

        private Http2Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "HTTP/2") {
            //this.payloadOffset = packetStartIndex + 9;
            int dataLength = packetEndIndex - packetStartIndex + 1;
            //this.http2FrameStartIndex = packetStartIndex;
            if (dataLength >= CLIENT_CONNECTION_PREFACE_BYTES.Length && CLIENT_CONNECTION_PREFACE_BYTES.SequenceEqual(parentFrame.Data.Skip(packetStartIndex).Take(CLIENT_CONNECTION_PREFACE_BYTES.Length)))
                this.prefaceBytes = CLIENT_CONNECTION_PREFACE_BYTES.Length;

            this.Length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data.Skip(this.PacketStartIndex + this.prefaceBytes).Take(3).ToArray());
            this.Type = (FrameType)parentFrame.Data[this.PacketStartIndex + this.prefaceBytes + 3];
            this.FlagsRaw = parentFrame.Data[this.PacketStartIndex + this.prefaceBytes + 4];
            this.StreamIdentifier = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data.Skip(this.PacketStartIndex + this.prefaceBytes + 5).Take(4).ToArray()) & 0x7fffffff;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            yield break;//no sub packets
        }
    }
}
