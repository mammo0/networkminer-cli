//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    //http://ist.marshall.edu/ist362/tcp.html
    //ftp://ftp.rfc-editor.org/in-notes/rfc1323.txt
    //http://tools.ietf.org/html/rfc793
    //http://en.wikipedia.org/wiki/Transmission_Control_Protocol
    //http://support.microsoft.com/kb/224829
    public class TcpPacket : AbstractPacket, ITransportLayerPacket {

        //http://www.it.lut.fi/kurssit/06-07/Ti5312500/luennot/Luento10.pdf
        public enum OptionKinds : byte {
            EndOfOptionList=0x00,
            NoOperation=0x01,
            MaximumSegmentSize=0x02,
            WindowScaleFactor=0x03,
            SackPermitted=0x04,
            Sack=0x05,
            Echo=0x06,//obsolete
            EchoReply=0x07,//obsolete
            Timestamp=0x08
        }

        public enum Flag : byte {
            CongestionWindowReduced = 0x80,
            ECNEcho = 0x40,
            UrgentPointer = 0x20,
            Acknowledgement = 0x10,
            Push = 0x08,
            Reset = 0x04,
            Synchronize = 0x02,
            Fin = 0x01
        }

        public class Flags{
            byte flagData;

            public bool CongestionWindowReduced { get { return (flagData&0x80)==0x80; } }
            public bool ECNEcho { get { return (flagData&0x40)==0x40; } }
            public bool UrgentPointer { get { return (flagData&0x20)==0x20; } }
            public bool Acknowledgement { get { return (flagData&0x10)==0x10; } }//needed for OS fingerprinting
            public bool Push { get { return (flagData&0x08)==0x08; } }
            public bool Reset { get { return (flagData&0x04)==0x04; } }
            public bool Synchronize { get { return (flagData&0x02)==0x02; } }//needed for OS fingerprinting
            public bool Fin { get { return (flagData&0x01)==0x01; } }

            public byte RawData {
                get { return this.flagData; }
                set { this.flagData = value; }
            }

            public Flags(byte data){
                this.flagData=data;
            }

            public bool[] GetFlagArray() {
                bool[] a = new bool[8];
                a[0] = CongestionWindowReduced;
                a[1] = ECNEcho;
                a[2] = UrgentPointer;
                a[3] = Acknowledgement;
                a[4] = Push;
                a[5] = Reset;
                a[6] = Synchronize;
                a[7] = Fin;
                return a;
            }

            public override string ToString() {
                StringBuilder sb=new StringBuilder();
                /*
                if(this.CongestionWindowReduced)
                    sb.Append("CWR ");
                if(this.ECNEcho)
                    sb.Append("ECN-Echo ");
                if(this.UrgentPointer)
                    sb.Append("Urgent ");
                if(this.Acknowledgement)
                    sb.Append("ACK ");
                if(this.Push)
                    sb.Append("Push ");
                if(this.Reset)
                    sb.Append("Reset ");
                if(this.Synchronize)
                    sb.Append("SYN ");
                if(this.Fin)
                    sb.Append("FIN ");
                return sb.ToString();
                 * */
                char c = ' ';
                if (this.CongestionWindowReduced)
                    sb.Append("C");
                else
                    sb.Append(c);
                if (this.ECNEcho)
                    sb.Append("E");
                else
                    sb.Append(c);
                if (this.UrgentPointer)
                    sb.Append("U");
                else
                    sb.Append(c);
                if (this.Acknowledgement)
                    sb.Append("A");
                else
                    sb.Append(c);
                if (this.Push)
                    sb.Append("P");
                else
                    sb.Append(c);
                if (this.Reset)
                    sb.Append("R");
                else
                    sb.Append(c);
                if (this.Synchronize)
                    sb.Append("S");
                else
                    sb.Append(c);
                if (this.Fin)
                    sb.Append("F");
                else
                    sb.Append(c);
                return sb.ToString();
            }
        }

        public static ushort CalculateChecksum(ICollection<byte> data, int tcpPacketIndex, int tcpPacketLength, System.Net.IPAddress sourceIP, System.Net.IPAddress destinationIP, IPv4Packet.RFC1700Protocols protocol = IPv4Packet.RFC1700Protocols.TCP) {
            //https://locklessinc.com/articles/tcp_checksum/
            
            List<byte> pseudoHeaderBytes = new List<byte>();
            if (sourceIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                // RFC 793
                pseudoHeaderBytes.AddRange(sourceIP.GetAddressBytes());
                pseudoHeaderBytes.AddRange(destinationIP.GetAddressBytes());
                pseudoHeaderBytes.Add(0);//padding
                pseudoHeaderBytes.Add((byte)protocol);
                pseudoHeaderBytes.AddRange(Utils.ByteConverter.ToByteArray((ushort)tcpPacketLength, false));
            }
            else if (sourceIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) {
                // RFC 2460
                pseudoHeaderBytes.AddRange(sourceIP.GetAddressBytes());
                pseudoHeaderBytes.AddRange(destinationIP.GetAddressBytes());
                pseudoHeaderBytes.AddRange(Utils.ByteConverter.ToByteArray((uint)tcpPacketLength, false));
                pseudoHeaderBytes.Add(0);//padding
                pseudoHeaderBytes.Add(0);//padding
                pseudoHeaderBytes.Add(0);//padding
                pseudoHeaderBytes.Add((byte)protocol);
            }
            else
                throw new ArgumentException("IP address must be IPv4 or IPv6");

            pseudoHeaderBytes.AddRange(data.Skip(tcpPacketIndex).Take(tcpPacketLength));

            int length = pseudoHeaderBytes.Count;
            /**
             * If a segment contains an odd number of header and text octets to be checksummed,
             * the last octet is padded on the right with zeros to form a 16-bit word
             * for checksum purposes
             */
            if (length % 2 == 1)
                pseudoHeaderBytes.Add(0);

            return Utils.ByteConverter.CalculateOnesComplement(pseudoHeaderBytes);
            /*
            int sum = 0;
            //Add all ushort values
            for (int i = 0; i < length; i += 2) {
                sum += pseudoHeaderBytes[i] << 8;
                sum += pseudoHeaderBytes[i + 1];
            }

            //Fold to get the ones complement result
            while (sum > ushort.MaxValue)
                sum = (sum & 0xffff) + (sum >> 16);

            //Invert to get the negative in ones complement arithmetic
            return (ushort)~sum;
            */
        }

        private ushort sourcePort;
        private ushort destinationPort;
        private uint sequenceNumber;
        private uint acknowledgmentNumber;
        private byte dataOffsetByteCount;
        //I'll skipp "Reserved"
        private Flags flags;
        private byte flagsRaw;
        private ushort windowSize;
        private ushort checksum;
        //I'll skipp "Urgent"
        private List<KeyValuePair<OptionKinds, byte[]>> optionList;

        public ushort SourcePort { get { return sourcePort; } }
        public ushort DestinationPort { get { return destinationPort; } }
        public uint SequenceNumber { get { return sequenceNumber; } }
        public uint AcknowledgmentNumber { get { return acknowledgmentNumber; } }
        public byte FlagsRaw { get { return this.flagsRaw; } }
        public ushort Checksum { get { return this.checksum; } }
        public FiveTuple.TransportProtocol TransportProtocol { get { return FiveTuple.TransportProtocol.TCP; } }

        public bool IsVirtualPacketFromTrailingDataInTcpSegment = false;

        /// <summary>
        /// AKA TCP Header Length
        /// </summary>
        public byte DataOffsetByteCount { get { return dataOffsetByteCount; } }
        public ushort WindowSize { get { return this.windowSize; } }//needed for OS fingerprinting
        
        public List<KeyValuePair<OptionKinds, byte[]>> OptionList {
            get {
                if(this.optionList == null)
                    this.optionList = new List<KeyValuePair<OptionKinds, byte[]>>();//lazy initialization
                return this.optionList;
                
            }
        }//needed for OS fingerprinting

        public Flags FlagBits { get { return flags; } }//needed for OS fingerprinting

        public int PayloadDataLength { get { return PacketEndIndex-PacketStartIndex-dataOffsetByteCount+1; } }

        internal TcpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "TCP") {

            this.sourcePort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source Port", sourcePort.ToString());
            this.destinationPort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination Port", destinationPort.ToString());
            this.sequenceNumber = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Sequence Number", sequenceNumber.ToString("X2"));
            this.acknowledgmentNumber = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
            this.dataOffsetByteCount=(byte)(4*(parentFrame.Data[packetStartIndex+12]>>4));
            if (!this.ParentFrame.QuickParse) {
                if (dataOffsetByteCount < 20)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 12, packetStartIndex + 12, "Too small defined TCP Data Offset : " + parentFrame.Data[packetStartIndex + 12]));
                else if (dataOffsetByteCount > 60)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 12, packetStartIndex + 12, "Too large defined TCP Data Offset : " + parentFrame.Data[packetStartIndex + 12]));
                else if (PacketEndIndex - PacketStartIndex + 1 < dataOffsetByteCount)//see this.PayloadDataLength
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 12, packetStartIndex + 12, "TCP Data offset is outside frame"));
            }
            this.flagsRaw = parentFrame.Data[packetStartIndex + 13];
            this.flags = new Flags(this.flagsRaw);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Flags", flags.ToString());
            this.windowSize = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 14);
            this.checksum = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 16);
            //kolla checksumman!?
            //kolla options
            if (dataOffsetByteCount > 20)
                optionList = GetOptionList(packetStartIndex + 20);
            else
                optionList = null;//this one will not be initialized until it is needed (lazy initialization)
                //optionList=new List<KeyValuePair<OptionKinds,byte[]>>();
        }

        private AbstractPacket GetProtocolPacket(ApplicationLayerProtocol protocol, bool clientToServer) {
            AbstractPacket packet = null;
            if (protocol == ApplicationLayerProtocol.Dns) {
                if (DnsPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, true, out DnsPacket dnsPacket))
                    return dnsPacket;
            }
            else if (protocol == ApplicationLayerProtocol.FtpControl) {
                if (FtpPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Http) {
                if (HttpPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Http2) {
                if (Http2Packet.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Irc) {
                if (IrcPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.IEC_104) {
                if (IEC_60870_5_104Packet.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Imap) {
                return new ImapPacket(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer);
            }
            else if (protocol == ApplicationLayerProtocol.Kerberos) {
                return new KerberosPacket(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, true);
            }
            else if (protocol == ApplicationLayerProtocol.ModbusTCP) {
                if (ModbusTcpPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, this.sourcePort, this.destinationPort, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.NetBiosNameService) {
                return new NetBiosNameServicePacket(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex);
            }
            else if (protocol == ApplicationLayerProtocol.NetBiosSessionService) {
                if (NetBiosSessionService.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, this.sourcePort, this.destinationPort, out packet, this.IsVirtualPacketFromTrailingDataInTcpSegment)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.OpenFlow) {
                if (OpenFlowPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Oscar) {
                if (OscarPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.OscarFileTransfer) {
                if (OscarFileTransferPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Pop3) {
                return new Pop3Packet(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer);
            }
            else if(protocol == ApplicationLayerProtocol.Sip) {
                return new SipPacket(ParentFrame, PacketStartIndex + DataOffsetByteCount, PacketEndIndex);
            }
            else if (protocol == ApplicationLayerProtocol.Smtp) {
                return new SmtpPacket(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer);
            }
            else if (protocol == ApplicationLayerProtocol.Socks) {
                if (SocksPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.SpotifyServerProtocol) {
                if (SpotifyKeyExchangePacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, clientToServer, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Ssh) {
                if (SshPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.Ssl) {
                if (SslPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, out packet)) {
                    return packet;
                }
            }
            else if (protocol == ApplicationLayerProtocol.TabularDataStream) {
                return new TabularDataStreamPacket(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex);
            }
            else if (protocol == ApplicationLayerProtocol.Tpkt) {
                if (TpktPacket.TryParse(ParentFrame, PacketStartIndex + dataOffsetByteCount, PacketEndIndex, this, out packet)) {
                    return packet;
                }
            }
            return packet;
        }

        internal IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference, ISessionProtocolFinder protocolFinder, bool clientToServer) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+dataOffsetByteCount<PacketEndIndex) {
                AbstractPacket packet=null;
                if(protocolFinder.GetConfirmedApplicationLayerProtocol() != ApplicationLayerProtocol.Unknown)
                    try {
                        packet = this.GetProtocolPacket(protocolFinder.GetConfirmedApplicationLayerProtocol(), clientToServer);
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Error parsing frame " + this.ParentFrame.FrameNumber + " as " + protocolFinder.GetConfirmedApplicationLayerProtocol() + " packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        packet = null;
                    }
                if (packet == null) {
                    foreach (ApplicationLayerProtocol protocol in protocolFinder.GetProbableApplicationLayerProtocols()) {
                        try {
                            packet = this.GetProtocolPacket(protocol, clientToServer);
                            if (packet != null) {
                                protocolFinder.SetConfirmedApplicationLayerProtocol(protocol, true);
                                break;
                            }
                        }
                        catch (Exception e) {
                            SharedUtils.Logger.Log("Unable to parse frame " + this.ParentFrame.FrameNumber + " as " + protocol + " packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                            packet = null;
                        }
                    }
                }
                if(packet == null)
                    packet = new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex);
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;



            if(PacketStartIndex+dataOffsetByteCount<PacketEndIndex) {
                AbstractPacket packet;

                //there is no point in trying to extract the application layer protocol data here
                packet=new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex);
                
                yield return packet;
                 

                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }

        public byte[] GetTcpPacketPayloadData() {
            byte[] data=new byte[PacketEndIndex-PacketStartIndex-dataOffsetByteCount+1];
            for(int i=0; i<data.Length; i++)
                data[i]=base.ParentFrame.Data[PacketStartIndex+dataOffsetByteCount+i];
            return data;
        }


        private List<KeyValuePair<OptionKinds,byte[]>> GetOptionList(int startIndex){

            List<KeyValuePair<OptionKinds, byte[]>> optionList=new List<KeyValuePair<OptionKinds, byte[]>>();
            int i=0;
            while(startIndex+i<this.PacketStartIndex+this.dataOffsetByteCount && startIndex+i<this.ParentFrame.Data.Length) {
                if(this.ParentFrame.Data[startIndex+i]>8) {
                    if (!this.ParentFrame.QuickParse)
                        ParentFrame.Errors.Add(new Frame.Error(ParentFrame, startIndex+i, startIndex+i, "TCP Option Kind is larger than 8 (it is:"+this.ParentFrame.Data[startIndex+i]+")"));
                    break;
                }
                else{
                    OptionKinds kind=(OptionKinds)this.ParentFrame.Data[startIndex+i];
                    if(kind==OptionKinds.EndOfOptionList) {
                        optionList.Add(new KeyValuePair<OptionKinds,byte[]>(kind, null));
                        i++;
                        break;
                    }
                    else if(kind==OptionKinds.NoOperation) {
                        optionList.Add(new KeyValuePair<OptionKinds,byte[]>(kind, null));
                        i++;
                    }
                    else{
                        byte optionLength=this.ParentFrame.Data[startIndex+i+1];
                        if(optionLength<2) {
                            if (!this.ParentFrame.QuickParse)
                                ParentFrame.Errors.Add(new Frame.Error(ParentFrame, startIndex+i+1, startIndex+i+1, "TCP Option Length ("+optionLength+") is shorter than 2"));
                            optionLength=2;
                        }
                        else if(startIndex+i+optionLength>this.PacketStartIndex+this.dataOffsetByteCount) {
                            if (!this.ParentFrame.QuickParse)
                                ParentFrame.Errors.Add(new Frame.Error(ParentFrame, startIndex+i+1, startIndex+i+1, "TCP Option Length ("+optionLength+") makes option end outside TCP Data Offset ("+this.dataOffsetByteCount+")"));
                            optionLength=(byte)(this.PacketStartIndex+this.dataOffsetByteCount-startIndex-i);
                        }
                        else if(optionLength>44) {
                            if (!this.ParentFrame.QuickParse)
                                ParentFrame.Errors.Add(new Frame.Error(ParentFrame, startIndex+i+1, startIndex+i+1, "TCP Option Length ("+optionLength+") is longer than 44"));
                            optionLength=44;
                        }
                        byte[] optionData=new byte[optionLength-2];
                        Array.Copy(this.ParentFrame.Data, startIndex+i+2, optionData, 0, Math.Min(this.ParentFrame.Data.Length-startIndex-i-2, optionLength-2));
                        optionList.Add(new KeyValuePair<OptionKinds,byte[]>(kind, optionData));

                        i+=optionLength;
                    }
                   
                }
                
            }
            return optionList;
        }



    }
}
