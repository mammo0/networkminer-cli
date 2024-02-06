//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //DNS
    //http://www.ietf.org/rfc/rfc1035.txt
    public class DnsPacket : AbstractPacket {
        public enum RRTypes : ushort {
            HostAddress = 1,//A
            CNAME = 5,
            DomainNamePointer = 12,//PTR
            AAAA = 28,
            NB = 32,
            //NBSTAT = 33,//obsolete replaced by SRV!
            //new added 2021-06-01
            A = 1, //a host address
            NS = 2, //an authoritative name server
            MD = 3, //a mail destination (Obsolete - use MX)
            MF = 4, //a mail forwarder(Obsolete - use MX)
            //CNAME = 5, //the canonical name for an alias
            SOA = 6, //marks the start of a zone of authority
            MB = 7, //a mailbox domain name(EXPERIMENTAL)
            MG = 8, //a mail group member(EXPERIMENTAL)
            MR = 9, //a mail rename domain name(EXPERIMENTAL)
            NULL = 10, //a null RR(EXPERIMENTAL)
            WKS = 11, //a well known service description
            PTR = 12, //a domain name pointer
            HINFO = 13, //host information
            MINFO = 14, //mailbox or mail list information
            MX = 15, //mail exchange
            TXT = 16, //text strings
            AXFR = 252, //A request for a transfer of an entire zone
            MAILB = 253, //A request for mailbox-related records (MB, MG or MR)
            MAILA = 254, //A request for mail agent RRs(Obsolete - see MX)
            ALL = 255,// Actually query type "*". A request for all records
            //https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
            SRV = 33 //Server Selection [RFC2782]. Same value as NBSTAT
        }



        /// <summary>
        /// Can retrieve a Name Label even when an offset pointer is used rather than a direct name label. Also handles combinations (such as CNAME's) of direct labels and referrers.
        /// </summary>
        /// <param name="data">The frame data in bytes</param>
        /// <param name="packetStartIndex">The start position in data of the DNS packet</param>
        /// <param name="labelStartOffset">The offset in the DNS packet where the label (or label referrer) is located</param>
        /// <returns>The extracted label</returns>
        public static List<NameLabel> GetNameLabelList(byte[] data, int packetStartIndex, int labelStartOffset, out int typeStartOffset) {
            const int TTL = 20;//max 20 iterations before generating an Exception
            return GetNameLabelList(data, packetStartIndex, labelStartOffset, TTL, out typeStartOffset);
        }

        public static List<NameLabel> GetNameLabelList(byte[] data, int packetStartIndex, int labelStartOffset, int ttl, out int typeStartOffset) {
            if (ttl <= 0)
                throw new Exception("DNS Name Label contains a pointer that loops");
            int qNameByteCount=0;
            typeStartOffset=labelStartOffset;
            List<NameLabel> nameLabels=new List<NameLabel>();
            while(data[packetStartIndex+labelStartOffset+qNameByteCount]!=0x00 && data[packetStartIndex+labelStartOffset+qNameByteCount]<64 && qNameByteCount<=255) {
                NameLabel label=new NameLabel(data, packetStartIndex+labelStartOffset+qNameByteCount);
                if(label.LabelByteCount>0) {//we have a label
                    qNameByteCount+=label.LabelByteCount+1;
                    nameLabels.Add(label);
                    typeStartOffset=labelStartOffset+qNameByteCount;
                }
                else {

                    break;
                }
            }
            if(data[packetStartIndex+labelStartOffset+qNameByteCount]==0x00)
                typeStartOffset++;//move past the last 0x00 terminator
            else if(data[packetStartIndex+labelStartOffset+qNameByteCount]>=192){//we should jump to another location
                ushort labelOffset = Utils.ByteConverter.ToUInt16(data, packetStartIndex + labelStartOffset + qNameByteCount);//denna kan komma utanför offseten!
                labelOffset=(ushort)(labelOffset&0x3fff);//mask the first 2 bits (they should be ones)
                int tmp;
                nameLabels.AddRange(GetNameLabelList(data, packetStartIndex, labelOffset, ttl-1, out tmp));
                typeStartOffset+=2;
            }
            return nameLabels;
        }

        private ushort questionCount;//Unsigned 16 bit integer specifying the number of entries in the question section of a Name
        private ushort answerCount;

        //question section
        private int questionSectionByteCount;
        //internal byte[] questionName;//ends with 0x00 (usually starts with 0x20)
        private string[] questionNameDecoded;
        private ushort questionType;//NB == 0x0020, NBSTAT == 0x0021, Domain Name Pointer=0x000c
        private ushort questionClass;//Internet Class: 0x0001

        public int SkippedBytes { get; } = 0;//increased when start of DNS packet isn't at offset 0, such as in DNS over TCP
        public ushort TransactionId { get; }
        public HeaderFlags Flags { get; }
        public ResourceRecord[] AnswerRecords { get; }
        public string QueriedDnsName {
            get {
                if(questionCount>0) {
                    if(questionNameDecoded!=null && questionNameDecoded.Length>0) {
                        StringBuilder sb=new StringBuilder();
                        for(int i=0; i<questionNameDecoded.Length; i++) {
                            if(i>0)
                                sb.Append(".");
                            sb.Append(questionNameDecoded[i]);
                        }
                        return sb.ToString();
                    }
                    else
                        return null;
                }
                else
                    return null;
            }
        }
        //answer

        //authority

        //additional

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool lengthPrefix, out DnsPacket dnsPacket) {
            //const int MAX_LENGTH = ushort.MaxValue;//64 kB
            dnsPacket = null;
            if(lengthPrefix) {
                ushort packetLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
                if (packetLength < 4)
                    return false;
                else if(packetStartIndex + packetLength + 1 > packetEndIndex)
                    return false;
            }
            try {
                dnsPacket = new DnsPacket(parentFrame, packetStartIndex, packetEndIndex, lengthPrefix);
                return true;
            }
            catch (Exception e) {
                SharedUtils.Logger.Log("Exception when parsing frame " + parentFrame.FrameNumber + " as DNS packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                return false;
            }
        }


        internal DnsPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool lengthPrefix = false)
            : base(parentFrame, packetStartIndex, packetEndIndex, "DNS") {
            
            if (lengthPrefix) {//Typically when parsing DNS over TCP
                ushort packetLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
                this.SkippedBytes += 2;
                packetStartIndex += 2;
                base.PacketStartIndex += 2;
                base.PacketEndIndex = Math.Min(base.PacketEndIndex, base.PacketStartIndex + packetLength - 1);
            }
            //header
            this.TransactionId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            this.Flags = new HeaderFlags(Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2));
            if (!this.ParentFrame.QuickParse) {
                if (this.Flags.Response)
                    this.Attributes.Add("Type", "Response");
                else
                    this.Attributes.Add("Type", "Request");
                if (this.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.Query)
                    this.Attributes.Add("Operation", "Standard Query");
                else if (this.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.InverseQuery)
                    this.Attributes.Add("Operation", "Inverse Query");
            }

            //NetworkMiner currently does not handle Dynamic Update (operation code 5)
            if(this.Flags.OperationCode < 5) {

                this.questionCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                if (this.questionCount > 64)
                    throw new Exception("Too many questions in DNS: " + this.questionCount);//this is probably not DNS
                this.answerCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                this.AnswerRecords=new ResourceRecord[this.answerCount];


                const int FIRST_LABEL_OFFSET = 12;

                //if(this.questionCount > 0) {
                if (this.questionCount < 1) {
                    this.questionSectionByteCount = 0;
                    this.questionNameDecoded = null;
                }
                else {
                    
                    for (int qi = 0; qi < this.questionCount; qi++) {
                        List<NameLabel> nameLabelList = GetNameLabelList(parentFrame.Data, packetStartIndex, FIRST_LABEL_OFFSET + this.questionSectionByteCount, out int typeStartOffset);
                        this.questionSectionByteCount = typeStartOffset - FIRST_LABEL_OFFSET;

                        //we have now decoded the name!
                        //only care about the first proper query
                        if (questionNameDecoded == null || questionNameDecoded.Length == 0) {
                            this.questionNameDecoded = new string[nameLabelList.Count];
                            for (int i = 0; i < nameLabelList.Count; i++)
                                this.questionNameDecoded[i] = nameLabelList[i].ToString();
                            this.questionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + typeStartOffset);
                            this.questionClass = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + typeStartOffset + 2);
                        }
                        this.questionSectionByteCount += 4;
                    }
                }
                //ANSWER RESOURCE RECORDS
                int packetPositionIndex=packetStartIndex + FIRST_LABEL_OFFSET + questionSectionByteCount;
                for(int ai=0; ai < this.AnswerRecords.Length; ai++) {
                    this.AnswerRecords[ai]=new ResourceRecord(this, packetPositionIndex);
                    packetPositionIndex+= this.AnswerRecords[ai].ByteCount;
                    if (!this.ParentFrame.QuickParse) {
                        if (this.AnswerRecords[ai].Type == (ushort)RRTypes.HostAddress) {
                            if (this.AnswerRecords[ai].IP != null)
                                this.Attributes.Add("IP", this.AnswerRecords[ai].IP.ToString());
                            if (this.AnswerRecords[ai].DNS != null)
                                this.Attributes.Add("DNS", this.AnswerRecords[ai].DNS);
                        }
                    }
                }
                //AUTHORITY RESOURCE RECORDS    
                //I'll just skip the rest of the packet!
            }

        }

   
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //Do nothing, no known sub packets...
            yield break;
        }


        public class HeaderFlags {
            internal enum OperationCodes : byte { Query=0, InverseQuery=1, ServerStatusRequest=2 };
            public enum ResultCodes : byte { NoErrorCondition=0, FormatError=1, ServerFailure=2, NameError_NXDOMAIN=3, NotImplemented=4, Refused=5 };

            private ushort headerData;
            //private static uint OpcodeMask=0x7000;

            public bool Response { get { return ((headerData>>15)==1); } }
            public byte OperationCode { get { return (byte)((headerData>>11)&0x000F); } }//nibble
            public bool Truncated { get { return (headerData>>9)==1; } }
            public bool RecursionDesired { get { return (headerData>>8)==1; } }
            //internal byte NmFlags { get { return (byte)((headerData>>4)&0x007F); } }//from netbios
            public byte ResultCode { get { return (byte)(headerData&0x000F); } }//nibble

            internal HeaderFlags(ushort value) {
                this.headerData=value;
            }

            public override string ToString() {
                return this.headerData.ToString("X4");
            }
            public string ToString(string format) {
                return this.headerData.ToString(format);
            }
        }

        public class NameLabel {
            //private byte[] sourceData;
            private int labelStartPosition;//the position
            private StringBuilder decodedName;

            internal byte LabelByteCount { get; }//if this is zero wh have a terminator
            public override string ToString() {
                return this.decodedName.ToString();
            }

            internal NameLabel(byte[] sourceData, int labelStartPosition) {
                this.labelStartPosition=labelStartPosition;
                //this.labelByteCount=0;
                this.decodedName=new StringBuilder();

                this.LabelByteCount =sourceData[labelStartPosition];//max 63
                if(this.LabelByteCount >63)
                    throw new Exception("DNS Name label is larger than 63 : "+LabelByteCount+" at position "+labelStartPosition);
                    //labelByteCount=63;//NO! of the first two bits are 1:s we will have to go somewhere else! See RFC-1035 3.1 "Name space definitions"
                
                else
                    for(byte b=0; b<LabelByteCount; b++)
                        this.decodedName.Append((char)sourceData[labelStartPosition+1+b]);
            }

        }

        public interface IDnsResponseInfo {
            DnsPacket ParentPacket { get; }
            string DNS { get; }
            TimeSpan TimeToLive { get; }
            System.Net.IPAddress IP { get; }
            string PrimaryName { get; }
            string TXT { get; }
            ushort Type { get; }
        }

        public class ResponseWithErrorCode : IDnsResponseInfo {
            public DnsPacket ParentPacket { get; }

            public string DNS {
                get { return this.ParentPacket.QueriedDnsName; }
            }

            public TimeSpan TimeToLive {
                get { return new TimeSpan(0); }
            }

            public System.Net.IPAddress IP {
                get { return null; }
            }

            public string PrimaryName {
                get { return null; }
            }

            public ushort Type {
                get { return 0; }
            }

            public string TXT {
                get { return null; }
            }

            public string GetResultCodeString() {
                return this.RCode() + " (flags 0x" + this.ParentPacket.Flags.ToString() + ")";
            }

            public string RCode() {
                //http://www.ietf.org/rfc/rfc1035.txt


                byte rcode = this.ParentPacket.Flags.ResultCode;

                if (rcode == 0) return "No error condition";
                else if (rcode == 1) return "Format error";
                else if (rcode == 2) return "SERVFAIL";//Server failure according to RFC 1035
                else if (rcode == 3) return "NXDOMAIN";//Name Error according to RFC 1035
                else if (rcode == 4) return "Not Implemented";
                else if (rcode == 5) return "Refused";
                else return "UNDEFINED RCODE";
                        
            }

            public ResponseWithErrorCode(DnsPacket parentPacket) {
                this.ParentPacket = parentPacket;
               
            }
        }

        public class ResourceRecord : IDnsResponseInfo  {//for example answers/replies
            private string[] answerRequestedNameDecoded;
            private ushort answerClass;//Internet Class: 0x0001
            private uint answerTimeToLive;//seconds
            private ushort answerDataLength;
            private string[] answerRepliedNameDecoded;

            public DnsPacket ParentPacket { get; }
            public ushort Type { get; }
            public TimeSpan TimeToLive { get { return new TimeSpan(0, 0, (int)this.answerTimeToLive); } }
            public int ByteCount { get; }
            public System.Net.IPAddress IP {
                //kolla antingen answerType eller OPCODE i headerFlags

                get {
                    //if(this.questionType
                    if(this.ParentPacket.Flags.OperationCode==(byte)HeaderFlags.OperationCodes.Query && this.Type==(ushort)RRTypes.HostAddress) {//request=IPv4
                        try {
                            byte[] ip=new byte[4];
                            for(int i=0; i<4; i++)
                                ip[i]=Convert.ToByte(answerRepliedNameDecoded[i]);//detta kan vara fel!?
                            return new System.Net.IPAddress(ip);
                        }
                        catch {
                            return null;
                        }
                    }
                    else if (this.ParentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.Query && this.Type == (ushort)RRTypes.AAAA) {//request=IPv6
                        try {
                            byte[] ip = new byte[16];
                            for (int i = 0; i < ip.Length; i++)
                                ip[i] = Convert.ToByte(answerRepliedNameDecoded[i]);//detta kan vara fel!?
                            return new System.Net.IPAddress(ip);
                        }
                        catch {
                            return null;
                        }
                    }
                    else if (this.ParentPacket.Flags.OperationCode==(byte)HeaderFlags.OperationCodes.InverseQuery) {//den har datat som typ 154.23.233.11.int-adr.arpa.net
                        try {
                            byte[] ip=new byte[4];
                            for(int i=0; i<4; i++)
                                ip[i]=Convert.ToByte(answerRequestedNameDecoded[i]);//detta kan vara fel!?
                            return new System.Net.IPAddress(ip);
                        }
                        catch {
                            return null;
                        }
                    }
                    else
                        return null;
                }
            }
            public string PrimaryName {//Instead of IP for CNAME packets
                get {
                    if(this.Type ==(ushort)RRTypes.CNAME || this.Type == (ushort)RRTypes.SRV) {
                        if(this.answerRepliedNameDecoded !=null && this.answerRepliedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i< this.answerRepliedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(this.answerRepliedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;

                    }
                    else
                        return null;
                }
            }
            public string TXT {
                get {
                    if (this.Type == (ushort)RRTypes.TXT && this.answerRepliedNameDecoded != null) {
                        return string.Concat(this.answerRepliedNameDecoded);
                    }
                    else return null;
                }
            }
            public string DNS {
                //kolla antingen answerType eller OPCODE i headerFlags
                get {
                    if(this.ParentPacket.Flags.OperationCode==(byte)HeaderFlags.OperationCodes.Query) {
                        if(this.answerRequestedNameDecoded !=null && this.answerRequestedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i< this.answerRequestedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(this.answerRequestedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;
                    }
                    else if(this.ParentPacket.Flags.OperationCode==(byte)HeaderFlags.OperationCodes.InverseQuery) {//request=IP
                        if(this.answerRepliedNameDecoded !=null && this.answerRepliedNameDecoded.Length>0) {
                            StringBuilder sb=new StringBuilder();
                            for(int i=0; i< this.answerRepliedNameDecoded.Length; i++) {
                                if(i>0)
                                    sb.Append(".");
                                sb.Append(this.answerRepliedNameDecoded[i]);
                            }
                            return sb.ToString();
                        }
                        else
                            return null;
                    }
                    else
                        return null;
                }

            }

            public ResourceRecord(DnsPacket parentPacket, int startIndex) {
                this.ParentPacket=parentPacket;
                int typeStartOffset;
                List<NameLabel> nameLabelList = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex - parentPacket.PacketStartIndex, out typeStartOffset);

                this.answerRequestedNameDecoded=new string[nameLabelList.Count];
                for(int i=0; i<nameLabelList.Count; i++)
                    this.answerRequestedNameDecoded[i]=nameLabelList[i].ToString();

                this.Type = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset);
                this.answerClass = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 2);
                this.answerTimeToLive = Utils.ByteConverter.ToUInt32(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 4);
                this.answerDataLength = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 8);

                this.ByteCount = typeStartOffset - startIndex + parentPacket.PacketStartIndex + 10 + this.answerDataLength;
                if (parentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.Query) {
                    if (this.Type == (ushort)RRTypes.CNAME) {
                        List<NameLabel> answerRepliedName = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + this.ByteCount - this.answerDataLength - parentPacket.PacketStartIndex, out typeStartOffset);

                        this.answerRepliedNameDecoded = new string[answerRepliedName.Count];
                        for (int i = 0; i < answerRepliedName.Count; i++)
                            this.answerRepliedNameDecoded[i] = answerRepliedName[i].ToString();
                    }
                    else if(this.Type == (ushort)RRTypes.TXT) {
                        List<string> txtStrings = new List<string>();
                        for(int i =0; i < this.answerDataLength; i++) {
                            //byte txtLength = parentPacket.ParentFrame.Data[parentPacket.PacketStartIndex + typeStartOffset + 10 + i];
                            byte txtLength = parentPacket.ParentFrame.Data[startIndex + this.ByteCount - this.answerDataLength + i];
                            string txtData = ASCIIEncoding.ASCII.GetString(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex + typeStartOffset + 10 + i + 1, txtLength);
                            txtStrings.Add(txtData);
                            i += txtLength;
                        }
                        this.answerRepliedNameDecoded = txtStrings.ToArray();

                        //TODO a series(?) of 1 byte length, then data TXT records
                        //List<NameLabel> txtData = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + this.ByteCount - this.answerDataLength - parentPacket.PacketStartIndex, out typeStartOffset);
                        /*
                        for (int i = 0; i < this.answerDataLength; i++) {
                            byte length = parentPacket.ParentFrame.Data[startIndex + this.ByteCount - this.answerDataLength - parentPacket.PacketStartIndex];
                            string txtData = 
                        }
                        */
                    }
                    else if(this.Type == (ushort)RRTypes.SRV) {
                        //https://datatracker.ietf.org/doc/html/rfc2782
                        ushort priority = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex + this.ByteCount - this.answerDataLength);
                        ushort weight = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex + this.ByteCount - this.answerDataLength + 2);
                        ushort port = Utils.ByteConverter.ToUInt16(parentPacket.ParentFrame.Data, startIndex + this.ByteCount - this.answerDataLength + 4);
                        var target = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + this.ByteCount - this.answerDataLength + 6 - parentPacket.PacketStartIndex, out _);
                        this.answerRepliedNameDecoded = new string[target.Count];
                        for (int i = 0; i < target.Count; i++)
                            this.answerRepliedNameDecoded[i] = target[i].ToString();
                    }
                    else {
                        this.answerRepliedNameDecoded = new string[this.answerDataLength];
                        for (int i = 0; i < this.answerDataLength; i++) {
                            this.answerRepliedNameDecoded[i] = parentPacket.ParentFrame.Data[startIndex + this.ByteCount - this.answerDataLength + i].ToString();//the answer is at the end
                        }
                    }
                }
                else if (parentPacket.Flags.OperationCode == (byte)HeaderFlags.OperationCodes.InverseQuery) {
                    nameLabelList = GetNameLabelList(parentPacket.ParentFrame.Data, parentPacket.PacketStartIndex, startIndex + 12 - parentPacket.PacketStartIndex, out typeStartOffset);

                    this.answerRepliedNameDecoded = new string[nameLabelList.Count];
                    for (int i = 0; i < nameLabelList.Count; i++)
                        this.answerRepliedNameDecoded[i] = nameLabelList[i].ToString();
                }

            }
        }
    }
}
