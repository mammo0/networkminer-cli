using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Packets {
    class MeterpreterPacket : AbstractPacket, ISessionPacket {

        public readonly uint PayloadLength;
        public readonly bool HasMZHeader = false;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result) {
            result = null;
            try {
                if (packetEndIndex - packetStartIndex + 1 == 4 || packetEndIndex - packetStartIndex > 2 && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex) == 0x4d5a) {
                    result = new MeterpreterPacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                else
                    return false;
            }
            catch {
                return false;
            }
        }

        public bool PacketHeaderIsComplete {
            get {
                return true;
            }
        }

        public int ParsedBytesCount {
            get {
                if (this.PayloadLength == 0)
                    return 0;
                else
                    return 4;
            }
        }

        internal MeterpreterPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "Meterpreter") {
            if (base.PacketLength == 4 && parentFrame.Data[packetStartIndex + 3] == 0x00) {
                this.PayloadLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex, 4, true);
            }
            else if (base.PacketLength > 1 && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex) == 0x4d5a) {
                //MZ header [4d 5a]
                this.HasMZHeader = true;
            }
            else throw new Exception("Packet is not Meterpreter");
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }
    }
}
