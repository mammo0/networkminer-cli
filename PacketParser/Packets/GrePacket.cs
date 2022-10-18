using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class GrePacket : AbstractPacket {

        //http://www.faqs.org/rfcs/rfc2784.html
        //http://www.faqs.org/rfcs/rfc1701.html

        private enum Flags : ushort {
            ChecksumPresent = 1<<15,
            RoutingPresent = 1<<14,
            KeyPresent = 1<<13,
            SequenceNumberPresent = 1<<12,//SequenceNumber = 0x1000
            StrictSourceRoute = 1<<11
        }

        //private const int PACKET_LENGTH = 4;//4 bytes fixed length
        private int greHeaderLength = 4;//default length is 4
        private ushort flagsAndVersion;
        private ushort etherType;
        

        internal GrePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "GRE") {
            //first 4 bytes of flag data
            this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, false);
            if ((this.etherType & (ushort)Flags.ChecksumPresent) != 0 || (this.etherType & (ushort)Flags.RoutingPresent) != 0)//sequence number
                this.greHeaderLength += 4;//rfc1701: If either the Checksum Present bit or the Routing Present bit are set, BOTH the Checksum and Offset fields are present in the GRE packet.
            if ((this.etherType & (ushort)Flags.KeyPresent) != 0)//sequence number
                this.greHeaderLength += 4;
            if ((this.etherType & (ushort)Flags.SequenceNumberPresent) != 0)//sequence number
                this.greHeaderLength += 4;
            //then etherType
            this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
            
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if (Ethernet2Packet.TryGetPacketForType(this.etherType, this.ParentFrame, this.PacketStartIndex + this.greHeaderLength, this.PacketEndIndex, out AbstractPacket packet)) {
                yield return packet;
                foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
