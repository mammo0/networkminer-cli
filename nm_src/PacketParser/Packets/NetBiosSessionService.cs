//  Copyright: Erik H7jelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    //http://ubiqx.org/cifs/SMB.html see: 2.1.2 NBT or Not NBT

    class NetBiosSessionService : NetBiosPacket, ISessionPacket {

        internal enum MessageTypes : byte { SessionMessage=0x00, SessionRequest=0x81, PositiveSessionResponse=0x82 }

        internal byte MessageType { get; }
        internal int Length { get; }


        public bool PacketHeaderIsComplete { get; } = true;

        public int ParsedBytesCount {
            get {
                return 4 + this.Length; // header + content length
            }
        }

        [System.Obsolete("use TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result)", true)]
        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            throw new System.NotImplementedException("use TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result)");
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result, bool isVirtualPacketFromTrailingDataInTcpSegment = false) {
            result = null;
            bool raw = sourcePort == 445 || destinationPort == 445;
            uint sessionServiceHeader = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
            if (sessionServiceHeader == 0x85000000) {
                //CIFS TCP session keep-alive message
                result = new NetBiosSessionService(parentFrame, packetStartIndex, packetStartIndex + 3, raw);
                return true;
            }
            else {
                uint length;
                byte[] allowedCommands = { 0x00, 0x81, 0x82, 0x83, 0x84, 0x85 };//see NetBIOS RFC 1002 http://tools.ietf.org/html/rfc1002
                //if ((sessionServiceHeader & 0xff000000) != 0) //first byte must be zero according to http://ubiqx.org/cifs/SMB.html
                if (Array.IndexOf<byte>(allowedCommands, (byte)(sessionServiceHeader & 0xff000000)) < 0) //first byte must be 0x00, 0x81, 0x82, 0x83, 0x84, 0x85 according to RFC 1002
                    return false;
                if (raw)
                    length = sessionServiceHeader & 0x00ffffff;//get the last 3 bytes (24 bits)
                else
                    length = sessionServiceHeader & 0x0001ffff;//get the last 17 bits

                if (length == packetEndIndex - packetStartIndex + 1 - 4) {
                    result = new NetBiosSessionService(parentFrame, packetStartIndex, packetEndIndex, raw);
                    return true;
                }
                else if (length < packetEndIndex - packetStartIndex + 1 - 4) {
                    //there is more data to parse after the returned result
                    byte nextPacketHeaderByte = parentFrame.Data[packetStartIndex + length + 4];
                    if (nextPacketHeaderByte == 0x00 || nextPacketHeaderByte == 0x85) {
                        result = new NetBiosSessionService(parentFrame, packetStartIndex, packetStartIndex + (int)length + 3, raw);
                        return true;
                    }
                    else
                        return false;
                }
                else {
                    //Check for EternalBlue exploit
                    //https://gist.github.com/worawit/bd04bad3cd231474763b873df081c09a
                    if(length > 0x1000 && packetEndIndex - packetStartIndex + 1 - 4 < 800 && !isVirtualPacketFromTrailingDataInTcpSegment) {
                        if (length == 0xfff7)//this is the value used in most exploits, but it can probably be any large value
                            parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetEndIndex, "EternalBlue exploit attempt, nbss size = 0x" + length.ToString("x4")));
                        else {
                            //this might lead to false positives if this is an SMB packet that has been chained after another AndX SMB packet in the same frame. Thus this is the trailing packet that has been cut off due to MSS (see PCAP "SMB File transfer 3" for details)
                            //parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetEndIndex, "Possible EternalBlue exploit attempt, nbss size = 0x" + length.ToString("x4")));
                        }
                    }
                    return false;
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="parentFrame"></param>
        /// <param name="packetStartIndex"></param>
        /// <param name="packetEndIndex"></param>
        private NetBiosSessionService(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool raw)
        //internal NetBiosSessionService(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NetBIOS Session Service") {
            this.MessageType=parentFrame.Data[packetStartIndex];

            if (this.MessageType == 0x85 && packetEndIndex-packetStartIndex == 3) {
                /**
                 * From: http://msdn.microsoft.com/en-us/library/dd327704.aspx
                 * 
                 * A CIFS TCP session keep-alive message consists of a byte with value 0x85, followed by three bytes with value zero.
                 * 
                 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 * |      0x85     |                    0                          |
                 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 * 
                 * The keep-alive message may be sent if no messages have been sent for a client-configurable interval. A server receiving such a message must discard it.
                 * */
                this.Length = 0;//will force bytesParsed to return 4
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Message", "NetBios Session Service session keep-alive");
            }
            else {
                //this.raw=raw;
                uint l = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
                if (raw)
                    this.Length = (int)(l & 0x00ffffff);//get the last 3 bytes (24 bits)
                else
                    this.Length = (int)(l & 0x0001ffff);//get the last 17 bits
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Length", Length.ToString());
                if (this.Length > 0 && this.PacketEndIndex  > this.PacketStartIndex + this.Length - 1)
                    this.PacketEndIndex = this.PacketStartIndex + this.Length - 1;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;

            if(this.MessageType==0x00 && PacketStartIndex+4<PacketEndIndex) {
                AbstractPacket packet;

                try {
                    if(this.ParentFrame.Data[this.PacketStartIndex + 4] == 0xff)
                        packet=new SmbPacket(this.ParentFrame, this.PacketStartIndex +4, this.PacketEndIndex);
                    else if(this.ParentFrame.Data[this.PacketStartIndex + 4] == 0xfe)
                        packet = new Smb2Packet(this.ParentFrame, this.PacketStartIndex + 4, this.PacketEndIndex);
                    else
                        packet = new RawPacket(this.ParentFrame, this.PacketStartIndex + 4, this.PacketEndIndex);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing packet in NetBIOS SS payload in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    packet = new RawPacket(this.ParentFrame, this.PacketStartIndex +4, this.PacketEndIndex);
                }

                yield return packet;

                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

        }


    }
}
