using System;
using System.Collections.Generic;
using System.Text;
using System.Net.NetworkInformation;

namespace PacketParser.Packets {
    public class LinuxCookedCapture2 : AbstractPacket{

        internal enum PacketTypes : ushort { LINUX_SLL_HOST=0, LINUX_SLL_BROADCAST=1, LINUX_SLL_MULTICAST=2, LINUX_SLL_OTHERHOST=3, LINUX_SLL_OUTGOING=4};

        private ushort protocol;

        private const int SLL2_HEADER_LENGTH = 20;


        public LinuxCookedCapture2(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Linux cooked capture v2 (SLL2)") {

            this.protocol = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex);

            if (!this.ParentFrame.QuickParse) {
                if (Enum.IsDefined(typeof(Ethernet2Packet.EtherTypes), this.protocol))
                    this.Attributes.Add("Ether Type", ((Ethernet2Packet.EtherTypes)this.protocol).ToString());
                else
                    this.Attributes.Add("Ether Type", this.protocol.ToString());
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //same as for Ethernet2Packet.cs

            if(includeSelfReference)
                yield return this;
            if (Ethernet2Packet.TryGetPacketForType(this.protocol, this.ParentFrame, this.PacketStartIndex + SLL2_HEADER_LENGTH, this.PacketEndIndex, out AbstractPacket packet)) {
                yield return packet;
                foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

        }
    }
}
