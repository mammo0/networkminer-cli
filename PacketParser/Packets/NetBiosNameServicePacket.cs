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

    //NetBIOS Name Service
    //http://gogloom.com/CowCulture?rfcnum=1002&RFCtitle=4.2.1.++GENERAL+FORMAT+OF+NAME+SERVICE+PACKETS
    //http://ubiqx.org/cifs/NetBIOS.html
    //http://www.faqs.org/rfcs/rfc1002.html
    class NetBiosNameServicePacket : NetBiosPacket {

        internal class HeaderFlags {
            internal enum OperationCodes : byte { query=0, registration=5, release=6, WACK=7, refresh=8 };

            private ushort headerData;
            //private static uint OpcodeMask=0x7000;

            internal bool Response { get { return (headerData&0x8000)==0x8000; } }
            internal byte OperationCode { get { return (byte)((headerData>>11)&0x000F); } }
            internal byte NmFlags { get { return (byte)((headerData>>4)&0x007F); } }
            internal byte ResultCode { get { return (byte)(headerData&0x000F); } }

            internal HeaderFlags(ushort value) {
                this.headerData=value;
            }
        }

        //header
        private ushort transactionID;

        
        private ushort questionCount;//Unsigned 16 bit integer specifying the number of entries in the question section of a Name
        private ushort answerCount;
        private ushort authorityCount;
        private ushort additionalCount;

        //question section
        private string questionNameDecoded;//The NetBIOS name which is queried for...
        private ushort questionType;//NB == 0x0020, NBSTAT == 0x0021
        private ushort questionClass;//Internet Class: 0x0001

        /*
        private string answerNameDecoded;
        private ushort answerType;
        private ushort answerClass;
        private uint answerTTL;
        private ushort answerDataLength;
        private ushort answerFlags;
        private System.Net.IPAddress answerAddress;
        */

        internal string QueriedNetBiosName { get { return this.questionNameDecoded; } }

        //internal System.Net.IPAddress AnsweredIpAddress { get { return this.answerAddress; } }
        //internal string AnsweredNetBiosName { get { return this.answerNameDecoded; } }
        internal List<ResourceRecord> AnswerResourceRecords { get; }
        internal List<ResourceRecord> AuthorityResourceRecords { get; }
        internal List<ResourceRecord> AdditionalResourceRecords { get; }

        internal HeaderFlags Flags { get; }


        internal class ResourceRecord {
            //very much like DnsPacket.ResourceRecord

            /**
             *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
             *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |                                                               |
             *    /                            RR_NAME                            /
             *    /                                                               /
             *    |                                                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |           RR_TYPE             |          RR_CLASS             |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |                              TTL                              |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |           RDLENGTH            |                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
             *    /                                                               /
             *    /                             RDATA                             /
             *    |                                                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             **/

            internal string Name { get; }
            internal string NameTrimmed {
                get {
                    return System.Text.RegularExpressions.Regex.Replace(this.Name, "(<[\\dA-Z]{2}>$)", "");
                }
            }
            internal ushort Type { get; }
            internal ushort Class { get; }
            internal uint TTL { get; }
            internal ArraySegment<byte> Data { get; }

            internal ResourceRecord(NetBiosNameServicePacket nbnsPacket, ref int offset) {
             
                this.Name = NetBiosPacket.DecodeNetBiosName(nbnsPacket.ParentFrame, ref offset, nbnsPacket);
                this.Type = Utils.ByteConverter.ToUInt16(nbnsPacket.ParentFrame.Data, offset);
                offset += 2;
                this.Class = Utils.ByteConverter.ToUInt16(nbnsPacket.ParentFrame.Data, offset);
                offset += 2;
                this.TTL = Utils.ByteConverter.ToUInt32(nbnsPacket.ParentFrame.Data, offset);
                offset += 4;
                ushort dataLength = Utils.ByteConverter.ToUInt16(nbnsPacket.ParentFrame.Data, offset);
                offset += 2;
                this.Data = new ArraySegment<byte>(nbnsPacket.ParentFrame.Data, offset, dataLength);
                offset += dataLength;
            }
        }


        internal NetBiosNameServicePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "NetBIOS Name Service") {

            this.AnswerResourceRecords = new List<ResourceRecord>();
            this.AuthorityResourceRecords = new List<ResourceRecord>();
            this.AdditionalResourceRecords = new List<ResourceRecord>();

            //header
            this.transactionID = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            this.Flags = new HeaderFlags(Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2));
            this.questionCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
            this.answerCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
            this.authorityCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
            this.additionalCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 10);

            int i=packetStartIndex+12;
            this.questionNameDecoded=null;
            for(int q=0; q<questionCount; q++) {//I'll just assume that there is only one question... otherwise it will be overwritten

                //get a NetBIOS name label
                this.questionNameDecoded=NetBiosPacket.DecodeNetBiosName(parentFrame, ref i, this);

                //Get Question Type
                this.questionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;

                //Get Question Class
                this.questionClass = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;
            }

            //this.answerNameDecoded=null;
            //this.answerAddress=new System.Net.IPAddress((long)0);
            //ANSWER RESOURCE RECORDS
            for(int a=0; a<answerCount;a++) {
                this.AnswerResourceRecords.Add(new ResourceRecord(this, ref i));
                /*
                this.answerNameDecoded=NetBiosPacket.DecodeNetBiosName(parentFrame, ref i, this);
                //Get Question Type
                this.answerType = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;
                //Get Question Class
                this.answerClass = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;
                //TTL
                this.answerTTL = Utils.ByteConverter.ToUInt32(parentFrame.Data, i);
                i+=4;
                //data length
                this.answerDataLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;
                //flags
                this.answerFlags = Utils.ByteConverter.ToUInt16(parentFrame.Data, i);
                i+=2;
                //addr
                byte[] ipBytes=new byte[4];//IP4...
                Array.Copy(parentFrame.Data, i, ipBytes, 0, ipBytes.Length);
                this.answerAddress=new System.Net.IPAddress(ipBytes);
                i+=4;
                */
            }
            for (int a = 0; a < authorityCount; a++) {
                this.AuthorityResourceRecords.Add(new ResourceRecord(this, ref i));
            }
            for (int a = 0; a < this.additionalCount; a++) {
                this.AdditionalResourceRecords.Add(new ResourceRecord(this, ref i));
                //var rr = this.GetResourceRecord(parentFrame, ref i);
            }

        }

        [Obsolete]
        private (string name, ushort type, ushort nbnsClass, uint ttl, byte[] data) GetResourceRecord(Frame parentFrame, ref int offset) {
            /**
             *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
             *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |                                                               |
             *    /                            RR_NAME                            /
             *    /                                                               /
             *    |                                                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |           RR_TYPE             |          RR_CLASS             |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |                              TTL                              |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *    |           RDLENGTH            |                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
             *    /                                                               /
             *    /                             RDATA                             /
             *    |                                                               |
             *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             **/
            string name = NetBiosPacket.DecodeNetBiosName(parentFrame, ref offset, this);
            ushort nbnsType = Utils.ByteConverter.ToUInt16(parentFrame.Data, offset);
            offset += 2;
            ushort nbnsClass = Utils.ByteConverter.ToUInt16(parentFrame.Data, offset);
            offset += 2;
            uint ttl = Utils.ByteConverter.ToUInt32(parentFrame.Data, offset);
            offset += 4;
            ushort dataLenght = Utils.ByteConverter.ToUInt16(parentFrame.Data, offset);
            offset += 2;
            byte[] data = new byte[dataLenght];
            Array.Copy(parentFrame.Data, offset, data, 0, dataLenght);

            offset += dataLenght;
            return (name, nbnsType, nbnsClass, ttl, data);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+8<PacketEndIndex) {
                RawPacket rawPacket=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                yield return rawPacket;
                foreach(AbstractPacket subPacket in rawPacket.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
