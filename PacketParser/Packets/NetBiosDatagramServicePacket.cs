//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //NetBIOS Name Service
    //http://ubiqx.org/cifs/NetBIOS.html
    //http://www.faqs.org/rfcs/rfc1002.html
    class NetBiosDatagramServicePacket : NetBiosPacket {

        internal class Flags {
            internal enum SourceEndNodeTypeEnum : byte { B=0, P=1, M=2, NBDD=3};

            private byte flagData;
            //private static uint OpcodeMask=0x7000;

            internal SourceEndNodeTypeEnum SourceEndNodeType{get{return (SourceEndNodeTypeEnum)((flagData>>2)&0x03);}}//SNT
            internal bool ThisIsFirstFragment{get{return (flagData&0x02)==0x02;}}//FIRST flag
            internal bool MoreDatagramFragmentsFollow{get{return (flagData&0x01)==0x01;}}//MORE flag

            internal Flags(byte value) {
                this.flagData=value;
            }
        }

        internal enum MessageType : byte {
            DirectUniqueDatagram=0x10,//can contain SMB
            DirectGroupDatagram=0x11,//contains SMB
            BroadcastDatagram=0x12,
            DatagramError=0x13,
            DatagramQueryRequest=0x14,
            DatagramPositiveQueryResponse=0x15,
            DatagramNegativeQueryResponse=0x16
        };

        private byte messageType;
        private Flags flags;
        private ushort datagramID;
        private uint sourceIP;
        private ushort sourcePort;
        private ushort datagramLength;
        private ushort packetOffset;
        private int? smbPacketIndex = null;

        private string sourceName;
        private string destinationName;
        //private string userData; //this shall be replaced by an SMB packet

        internal string SourceNetBiosName{get{return this.sourceName;}}

        internal NetBiosDatagramServicePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NetBIOS Datagram Service") {
            this.messageType=parentFrame.Data[packetStartIndex];
            this.flags=new Flags(parentFrame.Data[packetStartIndex+1]);
            this.datagramID = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            this.sourceIP = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            this.sourcePort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);

            //here we have to check the messageType to know the format of the rest of the packet...
            if(messageType==(byte)MessageType.DirectUniqueDatagram || messageType==(byte)MessageType.DirectGroupDatagram || messageType==(byte)MessageType.BroadcastDatagram) {
                this.datagramLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 10);
                this.packetOffset = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12);
                int index=packetStartIndex+14;
                this.sourceName=NetBiosPacket.DecodeNetBiosName(parentFrame, ref index);
                this.destinationName=NetBiosPacket.DecodeNetBiosName(parentFrame, ref index);
                //skip user data...for now at least
                if (index + 32 <= packetStartIndex + this.datagramLength && (messageType == (byte)MessageType.DirectUniqueDatagram || messageType == (byte)MessageType.DirectGroupDatagram)) {
                    //parse SMB
                    smbPacketIndex = index;
                }

            }
            else if(messageType==(byte)MessageType.DatagramError) {
                //do nothing at this state
            }
            else if(messageType==(byte)MessageType.DatagramQueryRequest || messageType==(byte)MessageType.DatagramPositiveQueryResponse || messageType==(byte)MessageType.DatagramNegativeQueryResponse) {
                int index=packetStartIndex+10;
                this.destinationName=NetBiosPacket.DecodeNetBiosName(parentFrame, ref index);
            }
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //what to do here?? SMB packet???
            if (smbPacketIndex == null)
                yield break;
            else {
                AbstractPacket smb = null;
                if(ParentFrame.Data[this.smbPacketIndex.Value] == 0xff)//SMB
                    smb = new SmbPacket(this.ParentFrame, this.smbPacketIndex.Value, this.PacketEndIndex);
                else if (ParentFrame.Data[this.smbPacketIndex.Value] == 0xfe)//SMB2
                    smb = new Smb2Packet(this.ParentFrame, this.smbPacketIndex.Value, this.PacketEndIndex);
                else
                    yield break;

                if (smb != null)
                    foreach (AbstractPacket p in smb.GetSubPackets(true))
                        yield return p;
            }

        }
    }
}
