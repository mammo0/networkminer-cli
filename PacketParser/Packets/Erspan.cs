using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class Erspan : AbstractPacket {
        //https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-00


        private int erspanHeaderLength = 8;
        public byte Version { get; }
        public ushort? VlanID { get; }


        public Erspan(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "MPLS") {
            this.Version = (byte)(parentFrame.Data[packetStartIndex] >> 4);
            if ((parentFrame.Data[packetStartIndex] & 0x18) == 0x18)//If the En field is set to 11, the value of VLAN is undefined.
                this.VlanID = null;
            else
                this.VlanID = (ushort)(Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, false) & 0xfff);

            if (this.Version == 1)//ERSPAN Type II
                this.erspanHeaderLength = 8;
            else if (this.Version == 2) {//ERPSAN Type III
                this.erspanHeaderLength = 12;
                //check for platform specific sub-header
                if ((parentFrame.Data[packetStartIndex + 11] & 1) != 0)
                    this.erspanHeaderLength += 8;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            AbstractPacket packet = new Ethernet2Packet(this.ParentFrame, this.PacketStartIndex + this.erspanHeaderLength, this.PacketEndIndex);
            yield return packet;
            foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                yield return subPacket;
        }
    }
}
