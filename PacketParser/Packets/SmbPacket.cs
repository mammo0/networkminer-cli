//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {


    interface ISmbCommandParent {
        /// <summary>
        /// Index where the actual SMB packet starts, not the child AndX command
        /// </summary>
        int SmbHeaderStartIndex { get; }

        bool Flags2UnicodeStrings { get; }
        bool FlagsResponse { get; }

        /// <summary>
        /// Index of the inner command of an AndX command, i.e. +1 byte compared to the index used in Wireshark
        /// </summary>
        int IndexOfNextPipelinedCommand { get; }
        byte NextCommand { get; }
        Frame ParentFrame { get; }
        ushort TreeId { get; }
        ushort MultiplexId { get; }
        ushort ProcessId { get; }
        ushort UserId { get; }
        int BufferStartIndex { get; }
        byte WordCount { get; }
        int PacketStartIndex {get;}
    }

    //Common Internet File System (CIFS) Packet
    //CIFS is an enhanced version of Microsoft's open, cross-platform Server Message Block (SMB) protocol
    //http://www.protocols.com/pbook/ibm.htm#SMB
    //http://msdn2.microsoft.com/en-us/library/aa302213.aspx
    //http://www.microsoft.com/mind/1196/cifs.asp
    //http://ubiqx.org/cifs/SMB.html  (good source!)
    //http://www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf
    //https://www.thursby.com/sites/default/files/files/CIFS-TR-1p00_FINAL.pdf

    class SmbPacket : AbstractPacket, ISmbCommandParent {
        private const uint smbProtocolIdentifier=0xff534d42;//=0xff+SMB

        internal enum CommandTypes : byte {//from http://www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf 5.1. SMB Command Codes
            SMB_COM_CREATE_DIRECTORY=0x00,
            SMB_COM_DELETE_DIRECTORY=0x01,
            SMB_COM_OPEN=0x02,
            SMB_COM_CREATE=0x03,
            SMB_COM_CLOSE=0x04,
            SMB_COM_FLUSH=0x05,
            SMB_COM_DELETE=0x06,
            SMB_COM_RENAME=0x07,
            SMB_COM_QUERY_INFORMATION=0x08,
            SMB_COM_SET_INFORMATION=0x09,
            SMB_COM_READ=0x0A,
            SMB_COM_WRITE=0x0B,
            SMB_COM_LOCK_BYTE_RANGE=0x0C,
            SMB_COM_UNLOCK_BYTE_RANGE=0x0D,
            SMB_COM_CREATE_TEMPORARY=0x0E,
            SMB_COM_CREATE_NEW=0x0F,
            SMB_COM_CHECK_DIRECTORY=0x10,
            SMB_COM_PROCESS_EXIT=0x11,
            SMB_COM_SEEK=0x12,
            SMB_COM_LOCK_AND_READ=0x13,
            SMB_COM_WRITE_AND_UNLOCK=0x14,
            SMB_COM_READ_RAW=0x1A,
            SMB_COM_READ_MPXv0x1B,
            SMB_COM_READ_MPX_SECONDARY=0x1C,
            SMB_COM_WRITE_RAW=0x1D,
            SMB_COM_WRITE_MPX=0x1E,
            SMB_COM_WRITE_MPX_SECONDARY=0x1F,
            SMB_COM_WRITE_COMPLETE=0x20,
            SMB_COM_QUERY_SERVER=0x21,
            SMB_COM_SET_INFORMATION2=0x22,
            SMB_COM_QUERY_INFORMATION2=0x23,
            SMB_COM_LOCKING_ANDX=0x24,
            SMB_COM_TRANSACTION=0x25,
            SMB_COM_TRANSACTION_SECONDARY=0x26,
            SMB_COM_IOCTL=0x27,
            SMB_COM_IOCTL_SECONDARY=0x28,
            SMB_COM_COPY=0x29,
            SMB_COM_MOVE=0x2A,
            SMB_COM_ECHO=0x2B,
            SMB_COM_WRITE_AND_CLOSE=0x2C,
            SMB_COM_OPEN_ANDX=0x2D,
            SMB_COM_READ_ANDX=0x2E,
            SMB_COM_WRITE_ANDX=0x2F,
            SMB_COM_NEW_FILE_SIZE=0x30,
            SMB_COM_CLOSE_AND_TREE_DISC=0x31,
            SMB_COM_TRANSACTION2=0x32,
            SMB_COM_TRANSACTION2_SECONDARY=0x33,
            SMB_COM_FIND_CLOSE2=0x34,
            SMB_COM_FIND_NOTIFY_CLOSE=0x35,
            /* Used by Xenix/Unix 0x60 � 0x6E */
            SMB_COM_TREE_CONNECT=0x70,
            SMB_COM_TREE_DISCONNECT=0x71,
            SMB_COM_NEGOTIATE=0x72,
            SMB_COM_SESSION_SETUP_ANDX=0x73,
            SMB_COM_LOGOFF_ANDX=0x74,
            SMB_COM_TREE_CONNECT_ANDX=0x75,
            SMB_COM_QUERY_INFORMATION_DISK=0x80,
            SMB_COM_SEARCH=0x81,
            SMB_COM_FIND=0x82,
            SMB_COM_FIND_UNIQUE=0x83,
            SMB_COM_FIND_CLOSE=0x84,
            SMB_COM_NT_TRANSACT=0xA0,
            SMB_COM_NT_TRANSACT_SECONDARY=0xA1,
            SMB_COM_NT_CREATE_ANDX=0xA2,
            SMB_COM_NT_CANCEL=0xA4,
            SMB_COM_NT_RENAME=0xA5,
            SMB_COM_OPEN_PRINT_FILE=0xC0,
            SMB_COM_WRITE_PRINT_FILE=0xC1,
            SMB_COM_CLOSE_PRINT_FILE=0xC2,
            SMB_COM_GET_PRINT_QUEUE=0xC3,
            SMB_COM_READ_BULK=0xD8,
            SMB_COM_WRITE_BULK=0xD9,
            SMB_COM_WRITE_BULK_DATA=0xDA
        }

        #region SMB Header
        private uint protocolIdentifier;//the value must be "0xFF+'SMB'"
        private byte firstCommand;
        #region status
        private byte errorClass;
        private byte reserved;
        private ushort error;
        #endregion
        private byte flags;
        

        //here there are 14 bytes of data which is used differently among different dialects.
        //I do want the flags2 however so I'll try parsing them
        private ushort flags2;

        private ushort treeId;
        private ushort processId;
        private ushort userId;
        private ushort multiplexId;
        //trans request
        private byte wordCount;//Count of parameter words defining the data portion of the packet.
        //from here it might be undefined...

        private int indexOfNextPipelinedCommand;

        private ushort byteCount;//buffer length
        private int bufferStartIndex;
        #endregion

        public byte WordCount { get { return this.wordCount; } }
        public int IndexOfNextPipelinedCommand { get { return this.indexOfNextPipelinedCommand; } }
        internal ushort ByteCount { get { return this.byteCount; } }
        public int BufferStartIndex { get { return this.bufferStartIndex; } }
        public bool FlagsResponse { get { return (this.flags&0x80)==0x80; } }
        public bool Flags2UnicodeStrings { get { return (this.flags2&0x8000)==0x8000; } }
        public ushort TreeId { get { return this.treeId; } }
        public ushort MultiplexId { get { return this.multiplexId; } }
        public ushort ProcessId { get { return this.processId; } }
        public ushort UserId { get { return this.userId; } }
        public int SmbHeaderStartIndex { get { return base.PacketStartIndex; } }
        public byte NextCommand { get { return this.firstCommand; } }

        private static readonly HashSet<byte> AndXCommandSet = new HashSet<byte> {
            (byte)CommandTypes.SMB_COM_LOCKING_ANDX,
            (byte)CommandTypes.SMB_COM_OPEN_ANDX,
            (byte)CommandTypes.SMB_COM_READ_ANDX,
            (byte)CommandTypes.SMB_COM_WRITE_ANDX,
            (byte)CommandTypes.SMB_COM_SESSION_SETUP_ANDX,
            (byte)CommandTypes.SMB_COM_LOGOFF_ANDX,
            (byte)CommandTypes.SMB_COM_TREE_CONNECT_ANDX,
            (byte)CommandTypes.SMB_COM_NT_CREATE_ANDX
        };

        static AbstractSmbCommand GetNextPipelinedCommand(ISmbCommandParent p) {
            /*
            CommandTypes[] andXCommands = {
                CommandTypes.SMB_COM_LOCKING_ANDX,
                CommandTypes.SMB_COM_OPEN_ANDX,
                CommandTypes.SMB_COM_READ_ANDX,
                CommandTypes.SMB_COM_WRITE_ANDX,
                CommandTypes.SMB_COM_SESSION_SETUP_ANDX,
                CommandTypes.SMB_COM_LOGOFF_ANDX,
                CommandTypes.SMB_COM_TREE_CONNECT_ANDX,
                CommandTypes.SMB_COM_NT_CREATE_ANDX
            };
            */

            try {
                if (p.IndexOfNextPipelinedCommand > p.PacketStartIndex && p.IndexOfNextPipelinedCommand < 32000 && p.NextCommand < 0xff) {
                    if (p.NextCommand == (byte)CommandTypes.SMB_COM_TREE_CONNECT_ANDX) {
                        if (p.FlagsResponse)
                            return new TreeConnectAndXResponse(p);
                        else
                            return new TreeConnectAndXRequest(p);
                    }
                    if (p.NextCommand == (byte)CommandTypes.SMB_COM_NT_CREATE_ANDX) {
                        if (p.FlagsResponse)
                            return new NTCreateAndXResponse(p);
                        else
                            return new NTCreateAndXRequest(p);
                    }
                    else if (p.NextCommand == (byte)CommandTypes.SMB_COM_READ_ANDX) {
                        if (p.FlagsResponse)
                            return new ReadAndXResponse(p);
                        else
                            return new ReadAndXRequest(p);
                    }
                    else if (p.NextCommand == (byte)CommandTypes.SMB_COM_WRITE_ANDX) {
                        if (p.FlagsResponse) {
                            //we probably don't need to parse the write response
                            return new BasicSmbAndXCommand(p);
                        }
                        else {
                            return new WriteAndXRequest(p);
                        }
                    }
                    else if (p.NextCommand == (byte)CommandTypes.SMB_COM_CLOSE) {
                        if (p.FlagsResponse)
                            return new BasicSmbAndXCommand(p);
                        else
                            return new CloseRequest(p);
                    }
                    else if (p.NextCommand == (byte)CommandTypes.SMB_COM_NEGOTIATE) {
                        if (p.FlagsResponse)
                            return new NegotiateProtocolResponse(p);
                        else
                            return new NegotiateProtocolRequest(p);

                    }
                    else if (p.NextCommand == (byte)CommandTypes.SMB_COM_SESSION_SETUP_ANDX) {
                        if (p.FlagsResponse)
                            return new SetupAndXResponse(p);
                        else
                            return new SetupAndXRequest(p);
                    }
                    else if(p.NextCommand == (byte)CommandTypes.SMB_COM_OPEN_ANDX) {
                        if (p.FlagsResponse)
                            return new BasicSmbAndXCommand(p);
                        else
                            return new OpenAndXRequest(p);
                    }
                    else if(p.NextCommand == (byte)CommandTypes.SMB_COM_TRANSACTION) {
                        if(!p.FlagsResponse) {
                            //TODO extract Trans Request, which porbably contains Mailslot or somethig else (like \PIPE\LANMAN)
                            return new TransactionRequest(p);
                        }
                    }
                    else {
                        //returning basic AndXCommand so that we can parse any eventual pipelined/chained commands
                        if (AndXCommandSet.Contains(p.NextCommand))
                            return new BasicSmbAndXCommand(p);
                        /*
                        foreach (CommandTypes andXCommand in andXCommands) {
                            if (p.NextCommand == (byte)andXCommand)
                                return new BasicSmbAndXCommand(p);
                        }
                        */
                    }
                }
            }
            catch (Exception e) {
                SharedUtils.Logger.Log("Exception when parsing inner packet of SmbPacket: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
#if DEBUG
                System.Diagnostics.Debugger.Break();
#endif
            }

            return null;
        }


        internal SmbPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "CIFS Server Message Block (SMB)") {
                this.protocolIdentifier = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
            if(this.protocolIdentifier!=smbProtocolIdentifier) {
                //there's no need to throw an exception since it is probably just a fragmented packet...
                throw new Exception("SMB protocol identifier is: "+protocolIdentifier.ToString("X2"));
            }
            this.firstCommand=parentFrame.Data[packetStartIndex+4];
            if (!parentFrame.QuickParse) {
                try {
                    this.Attributes.Add("Command code", ((CommandTypes)this.firstCommand).ToString() + " (0x" + this.firstCommand.ToString("X2") + ")");
                }
                catch {
                    this.Attributes.Add("Command code", "(0x" + this.firstCommand.ToString("X2") + ")");
                }
            }
            //errors (they should hepefully be all 0's (they are also known as SMB/NT status)
            this.errorClass=parentFrame.Data[packetStartIndex+5];
            this.reserved=parentFrame.Data[packetStartIndex+6];
            this.error = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 7, true);
            //flags
            this.flags=parentFrame.Data[packetStartIndex+9];
            this.flags2 = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 10, true);
            //now skip agead 14 bytes from flags (not flags2!)
            this.treeId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 24, true);// Tree identifier
            if (!parentFrame.QuickParse)
                this.Attributes.Add("Tree ID", treeId.ToString());
            this.processId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 26, true);// Caller�s process ID, opaque for client use
            if (!parentFrame.QuickParse)
                this.Attributes.Add("Process ID", processId.ToString());
            this.userId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 28, true);// User id
            if (!parentFrame.QuickParse)
                this.Attributes.Add("User ID", userId.ToString());
            this.multiplexId = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 30, true);// multiplex id
            if (!parentFrame.QuickParse)
                this.Attributes.Add("Multiplex ID", multiplexId.ToString());

            //word count of the next command
            this.wordCount=parentFrame.Data[packetStartIndex+32];

            this.indexOfNextPipelinedCommand=packetStartIndex+33;//I guess it is always the same number... This is actually the index of the next pipelined/chained command in AndX commands


            this.byteCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 33 + wordCount * 2, true);
            if (!parentFrame.QuickParse)
                this.Attributes.Add("Buffer Total Length", byteCount.ToString());


            /*
             * In all cases where a string is passed in Unicode format, the Unicode string
             * must be word-aligned with respect to the beginning of the SMB. Should the string not naturally
             * fall on a two-byte boundary, a null byte of padding will be inserted, and the Unicode string will
             * begin at the next address.
             * */

            this.bufferStartIndex=packetStartIndex+33+wordCount*2+2;//no padding

            /*
             * For type-prefixed Unicode strings, the padding byte is found after the type byte. The type byte is
             * 4 (indicating SMB_FORMAT_ASCII) independent of whether the string is ASCII or Unicode. For
             * strings whose start addresses are found using offsets within the fixed part of the SMB (as
             * opposed to simply being found at the byte following the preceding field,) it is guaranteed that the
             * offset will be properly aligned.
             * */
        }

        /*
        //change this one so that it uses ByteConverter.ReadNullTerminatedString
        internal string DecodeBufferString() {

            int dataIndex=this.bufferStartIndex;

            if(Flags2UnicodeStrings && ((bufferStartIndex-PacketStartIndex)%2==1)) {
                //must start on a word boundrary (2 bytes)
                dataIndex++;
                return Utils.ByteConverter.ReadString(ParentFrame.Data, ref dataIndex, this.byteCount - 1, this.Flags2UnicodeStrings, true, true);
            }
            else
                return Utils.ByteConverter.ReadString(ParentFrame.Data, ref dataIndex, this.byteCount, this.Flags2UnicodeStrings, true, true);
        }
        */


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;

            AbstractSmbCommand cmd = GetNextPipelinedCommand(this);
            if (cmd != null) {
                foreach (AbstractPacket p in cmd.GetSubPackets(true))
                    yield return p;
            }
        }

        

        internal class BasicSmbAndXCommand : AbstractSmbCommand, ISmbCommandParent {

            /**
            * 2.4.4 The AndX Mutation
            * http://ubiqx.org/cifs/SMB.html
            * 
            * AndX messages work something like a linked list.
            * The AndXCommand field provides the SMB command code for the next AndX block in the list
            * (not the current one).
            * The AndXOffset contains the byte index, relative to the start of the SMB header,
            * of that next AndX block--think of it as a pointer. Since the AndXOffset value is
            * independent of the SMB_PARAMETERS.WordCount and SMB_DATA.ByteCount values,
            * it is possible to provide padding between the AndX blocks as shown in figure 2.5. 
            * 
            * Eddi Blenkers calls this "pipelining", where mutliple AndX requests can be sent before receiving a response
            **/

            private byte nextCommand;
            private ushort nextCommandOffset;
            private byte wordCount;
            //private ISmbCommandParent parentSmbCommand;
            private ushort byteCount;//bufferByteCount

            //Frame ParentFrame { get { return parentSmbCommand.ParentFrame; } }
            public int IndexOfNextPipelinedCommand { get { return this.SmbHeaderStartIndex + this.nextCommandOffset + 1; } }//index of the next chained/pipelined command (if AndX)
            public int SmbHeaderStartIndex { get { return base.ParentCifsPacket.SmbHeaderStartIndex; } }
            public byte WordCount { get { return this.wordCount; } }
            public bool Flags2UnicodeStrings { get { return this.ParentCifsPacket.Flags2UnicodeStrings; } }
            public bool FlagsResponse { get { return this.ParentCifsPacket.FlagsResponse; } }
            public ushort TreeId { get { return this.ParentCifsPacket.TreeId; } }
            public ushort MultiplexId { get { return this.ParentCifsPacket.MultiplexId; } }
            public ushort ProcessId { get { return this.ParentCifsPacket.ProcessId; } }
            public ushort UserId { get { return this.ParentCifsPacket.UserId; } }
            public ushort BufferByteCount { get { return this.byteCount; } }
            public int BufferStartIndex { get { return base.PacketStartIndex + this.wordCount * 2 + 2; } }
            public byte NextCommand { get { return this.nextCommand; } }

            //public int BufferStartIndex { get { return base.PacketStartIndex + this.wordCount * 2 + 3; } }

            //public new int PacketStartIndex { get { return 1; } }

            internal BasicSmbAndXCommand(ISmbCommandParent parentCifsPacket)
                : this(parentCifsPacket, "CIFS Unknown SMB AndX Command") { }

            internal BasicSmbAndXCommand(ISmbCommandParent parentCifsPacket, string packetTypeDescription)
                : base(parentCifsPacket, packetTypeDescription) {
                //TODO - extract:
                // * SMB command code for the next AndX block in the list (not the current one)
                // * AndXOffset = the byte index, relative to the start of the SMB header, of that next AndX block
                this.wordCount = parentCifsPacket.ParentFrame.Data[parentCifsPacket.IndexOfNextPipelinedCommand - 1];//not very pretty, but this is where the WordCount is for this command

                //this.nextCommand = parentCifsPacket.ParentFrame.Data[parentCifsPacket.IndexOfNextPipelinedCommand];
                this.nextCommand = base.ParentFrame.Data[this.PacketStartIndex];
                this.nextCommandOffset = Utils.ByteConverter.ToUInt16(ParentFrame.Data, this.PacketStartIndex + 2, true);

                this.byteCount = Utils.ByteConverter.ToUInt16(ParentFrame.Data, PacketStartIndex + this.wordCount * 2, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                //Note that the AndXCommand field in the final AndX block is given a value of 0xFF.
                //This, in addition to the zero offset in the AndXOffset field, indicates the end of the AndX list. 
                foreach (AbstractPacket p in base.GetSubPackets(includeSelfReference))
                    yield return p;
                if(this.nextCommand != 0xff && this.nextCommandOffset > 0) {
                    AbstractSmbCommand nextCommand = GetNextPipelinedCommand(this);
                    if (nextCommand != null) {
                        foreach (AbstractPacket p in nextCommand.GetSubPackets(true))
                            yield return p;
                    }
                }
            }

            /*
            internal string DecodeBufferString() {

                int dataIndex = this.BufferStartIndex;

                if (Flags2UnicodeStrings && ((this.BufferStartIndex - this.SmbHeaderStartIndex) % 2 == 1)) {
                    //must start on a word boundrary (2 bytes)
                    dataIndex++;
                    return Utils.ByteConverter.ReadString(ParentFrame.Data, ref dataIndex, this.byteCount - 1, this.Flags2UnicodeStrings, true, true);
                }
                else
                    return Utils.ByteConverter.ReadString(ParentFrame.Data, ref dataIndex, this.byteCount, this.Flags2UnicodeStrings, true, true);
            }*/
        }

        #region internal command classes
        internal abstract class AbstractSmbCommand : AbstractPacket{

            private ISmbCommandParent parentCifsPacket;
            private int? securityBlobIndex;
            private ushort securityBlobLength;


            internal ISmbCommandParent ParentCifsPacket { get { return this.parentCifsPacket; } }
            internal int? SecurityBlobIndex {
                get { return this.securityBlobIndex; }
                set { this.securityBlobIndex=value; }
            }
            internal ushort SecurityBlobLength {
                get { return this.securityBlobLength; }
                set { this.securityBlobLength=value; }
            }



            internal AbstractSmbCommand(ISmbCommandParent parentCifsPacket, string packetTypeDescription)
                : base(parentCifsPacket.ParentFrame, parentCifsPacket.IndexOfNextPipelinedCommand, parentCifsPacket.ParentFrame.Data.Length-1, packetTypeDescription) {

                this.parentCifsPacket=parentCifsPacket;
                this.securityBlobIndex=null;
                this.securityBlobLength=0;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
            {
                if(includeSelfReference)
                    yield return this;
                if(this.securityBlobIndex!=null) {

                    AbstractPacket securityBlobPacket=new SecurityBlob(ParentFrame, securityBlobIndex.Value, securityBlobIndex.Value+securityBlobLength-1);
                    yield return securityBlobPacket;
                    foreach(AbstractPacket subPacket in securityBlobPacket.GetSubPackets(false))
                        yield return subPacket;

                }
                else
                    yield break;//no sub packets
            }

           

        }


        //https://msdn.microsoft.com/en-us/library/ee441892.aspx
        internal class TreeConnectAndXRequest : BasicSmbAndXCommand {
            private string shareName;

            /// <summary>
            /// A null-terminated string that represents the server and share name of the resource to which the client attempts to connect.
            /// </summary>
            internal string ShareName { get { return this.shareName; } }

            //internal TreeConnectAndXRequest(SmbPacket parentCifsPacket)
            internal TreeConnectAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Tree Connect AndX Request") {
                //ushort passwordLength = Utils.ByteConverter.ToUInt16(ParentFrame.Data, parentCifsPacket.indexOfNextPipelinedCommand + 6, true);
                ushort passwordLength = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 6, true);
                int shareNameIndex = this.PacketStartIndex + 10 + passwordLength;//same thing as base.BufferStartIndex + passwordLength
                System.Diagnostics.Debug.Assert(shareNameIndex == base.BufferStartIndex + passwordLength);
                if (parentCifsPacket.Flags2UnicodeStrings && ((shareNameIndex - base.SmbHeaderStartIndex) % 2 == 1))
                    shareNameIndex++;//padding to align on an even word boundary

                this.shareName = Utils.ByteConverter.ReadNullTerminatedString(ParentFrame.Data, ref shareNameIndex, parentCifsPacket.Flags2UnicodeStrings, true);
            }
        }

        internal class TreeConnectAndXResponse : BasicSmbAndXCommand {
            internal TreeConnectAndXResponse(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Tree Connect AndX Response") {
                //do nothing, we might wanna read smb.native_fs but it's not always set
            }
        }

        internal class NTCreateAndXRequest : BasicSmbAndXCommand {
            private string filename;
            //private string fileId;

            internal string Filename{get{return this.filename;}}
            //internal string FileId { get { return this.fileId; } }

            internal NTCreateAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS NT Create AndX Request") {


                if(base.WordCount==24) {
                    //int nameLength=ParentFrame.Data[parentCifsPacket.IndexOfNextPipelinedCommand+5];
                    int nameLength = ParentFrame.Data[this.PacketStartIndex + 5];
                    int fileNameIndex = base.BufferStartIndex;//this value must be adjusted to a 16-bit word boundary -- it is probably not aligned at the moment
                    //int fileNameIndex = base.PacketStartIndex + base.WordCount * 2 + 2;//this value must be adjusted to a 16-bit word boundary -- it is probably not aligned at the moment
                    ushort fileNameLength = base.BufferByteCount;//This field MUST be the total length of the Name field, plus any padding added for alignment.

                    //https://msdn.microsoft.com/en-us/library/ee442175.aspx
                    // If the FileName string consists of Unicode characters, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB Header.
                    if (base.Flags2UnicodeStrings && ((fileNameIndex - base.SmbHeaderStartIndex) % 2 == 1)) {
                        fileNameIndex++;
                        fileNameLength--;
                    }

                    this.filename = Utils.ByteConverter.ReadString(ParentFrame.Data, ref fileNameIndex, fileNameLength, this.Flags2UnicodeStrings, true, true);

                    //this.filename= base.DecodeBufferString();
                    //NetBiosPacket.DecodeNetBiosName(ParentFrame, ref fileNameIndex);
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Filename", this.filename);
                }
                else
                    throw new Exception("Word Cound is not 24 ("+base.WordCount.ToString()+")");
            }
        }
        internal class NTCreateAndXResponse : AbstractSmbCommand {
            private ushort fileId;//FID
            private ulong endOfFile;//File length in bytes

            /// <summary>
            /// File length in bytes
            /// </summary>
            internal ulong EndOfFile { get { return this.endOfFile; } }
            internal ushort FileId { get { return this.fileId; } }

            internal NTCreateAndXResponse(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "NT Create AndX Response") {
                //this.fileId = Utils.ByteConverter.ToUInt16(ParentFrame.Data, parentCifsPacket.indexOfNextPipelinedCommand + 5, true);
                this.fileId = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 5, true);
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("File ID", "0x"+fileId.ToString("X2"));
                //this.endOfFile = Utils.ByteConverter.ToUInt64(ParentFrame.Data, parentCifsPacket.indexOfNextPipelinedCommand + 55, true);
                this.endOfFile = Utils.ByteConverter.ToUInt64(ParentFrame.Data, base.PacketStartIndex + 55, true);
            }
        }
        internal class WriteAndXRequest : AbstractSmbCommand {

            private ushort fileId;
            private long writeOffset;
            private int dataLength;
            private ushort dataOffset;

            internal ushort FileId { get { return this.fileId; } }
            internal int DataLength { get { return this.dataLength; } }
            internal ushort DataOffset { get { return this.dataOffset; } }
            internal long WriteOffset { get { return this.writeOffset; } }

            internal WriteAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Write AndX Request") {

                this.fileId = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 4, true);
                this.writeOffset = (long)Utils.ByteConverter.ToUInt32(ParentFrame.Data, base.PacketStartIndex + 6, 4, true);
                ushort dataLengthHigh = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 18, true);
                ushort dataLengthLow = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 20, true);
                this.dataLength = dataLengthHigh;
                this.dataLength <<= 16;
                this.dataLength += dataLengthLow;
                this.dataOffset = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 22, true);

                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("File ID", "0x" + fileId.ToString("X2"));
            }

            internal byte[] GetFileData() {
                //if(this.dataLenght != ParentFrame.Data.Length-(ParentCifsPacket.PacketStartIndex+this.DataOffset)) do nothing?;
                //System.Diagnostics.Debug.Assert(this.dataLength == ParentFrame.Data.Length - (ParentCifsPacket.PacketStartIndex + this.DataOffset), "CIFS frame is not complete in frame " + ParentFrame.FrameNumber.ToString() + "!");

                int packetDataLength = Math.Min(this.dataLength, ParentFrame.Data.Length - (ParentCifsPacket.SmbHeaderStartIndex + this.DataOffset));
                byte[] returnArray = new byte[packetDataLength];
                Array.Copy(ParentFrame.Data, ParentCifsPacket.SmbHeaderStartIndex + this.DataOffset, returnArray, 0, packetDataLength);
                return returnArray;
            }

        }
        internal class ReadAndXRequest : AbstractSmbCommand {

            private ushort fileId;

            internal ushort FileId { get { return this.fileId; } }

            internal ReadAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Read AndX Request") {

                this.fileId = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 4, true);

                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("File ID", "0x"+fileId.ToString("X2"));
            }
        }
        internal class ReadAndXResponse : BasicSmbAndXCommand {
            private ushort dataLength;
            private ushort dataOffset;

            internal ushort DataLength { get { return this.dataLength; } }
            internal ushort DataOffset { get { return this.dataOffset; } }

            internal ReadAndXResponse(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Read AndX Response") {

                    this.dataLength = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 10, true);
                    this.dataOffset = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 12, true);
            }

            internal byte[] GetFileData() {
                //if(this.dataLenght != ParentFrame.Data.Length-(ParentCifsPacket.PacketStartIndex+this.DataOffset)) do nothing?;
                //System.Diagnostics.Debug.Assert(this.dataLength == ParentFrame.Data.Length - (ParentCifsPacket.PacketStartIndex + this.DataOffset), "CIFS frame is not complete in frame "+ ParentFrame.FrameNumber.ToString() + "!");

                int packetDataLength=Math.Min(this.dataLength, ParentFrame.Data.Length-(ParentCifsPacket.SmbHeaderStartIndex+this.DataOffset));
                byte[] returnArray=new byte[packetDataLength];
                Array.Copy(ParentFrame.Data, ParentCifsPacket.SmbHeaderStartIndex+this.DataOffset, returnArray, 0, packetDataLength);
                return returnArray;
            }
        }
        internal class CloseRequest : AbstractSmbCommand {
            private ushort fileId;

            internal ushort FileId { get { return this.fileId; } }

            internal CloseRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "Close Request") {
                this.fileId = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex, true);
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("File ID", "0x"+fileId.ToString("X2"));
            }
        }

        //See 4.1.2. SESSION_SETUP_ANDX: Session Setup in CIFS-TR-1p00_FINAL.pdf
        //internal class SetupAndXRequest : AbstractSmbCommand {//It would be cool to use this one in order to extract some extra information!
        internal class SetupAndXRequest : BasicSmbAndXCommand {//It would be cool to use this one in order to extract some extra information!
            private string nativeOs;
            private string nativeLanManager;//LAN Man
            //Username and password is transmitted Pre NT LM 0.12
            private string accountName;
            private string primaryDomain;
            private string accountPassword;



            internal string AccountName { get { return this.accountName; } }
            internal string AccountPassword { get { return this.accountPassword; } }
            internal string NativeOs { get { return this.nativeOs; } }
            internal string NativeLanManager { get { return this.nativeLanManager; } }
            internal string PrimaryDomain { get { return this.primaryDomain; } }

            internal SetupAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Setup AndX Request") {

                this.nativeOs=null;
                this.nativeLanManager=null;
                this.accountName=null;
                this.primaryDomain=null;
                this.accountPassword=null;

                

                //OK, a big problem here is that I don't at this level know which protocol has been negotiated for the SMB session...
                //A good way to solve that problem is to look at the WordCount (number of parameters)
                if(base.WordCount==10){//If wordCount is 10 then the dialect is prior to "NT LM 0.12"
                    ushort passwordLength = Utils.ByteConverter.ToUInt16(base.ParentFrame.Data, base.PacketStartIndex + 14, true);
                    int packetIndex = base.PacketStartIndex + 22;
                    this.accountPassword = Utils.ByteConverter.ReadString(base.ParentFrame.Data, ref packetIndex, passwordLength, false, true);
                    this.accountName = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    //I currently don't care about the primary domain...
                    this.primaryDomain = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                }
                else if(base.WordCount==12) {//If wordCount is 12 then the dialect is "NT LM 0.12" or later
                    base.SecurityBlobLength = Utils.ByteConverter.ToUInt16(base.ParentFrame.Data, base.PacketStartIndex + 14, true);
                    int packetIndex = base.PacketStartIndex + 26+base.SecurityBlobLength;
                    if(parentCifsPacket.Flags2UnicodeStrings && ((packetIndex-parentCifsPacket.SmbHeaderStartIndex)%2==1))
                        packetIndex++;//must start on a word boundrary (2 bytes)
                    this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                }
                else if(base.WordCount==13) {//smb.wct == 13
                    //ushort ansiPasswordLength = Utils.ByteConverter.ToUInt16(parentCifsPacket.ParentFrame.Data, base.IndexOfNextPipelinedCommand + 14, true);
                    //ushort unicodePasswordLength = Utils.ByteConverter.ToUInt16(parentCifsPacket.ParentFrame.Data, base.IndexOfNextPipelinedCommand + 16, true);
                    ushort ansiPasswordLength = Utils.ByteConverter.ToUInt16(base.ParentFrame.Data, base.PacketStartIndex + 14, true);
                    ushort unicodePasswordLength = Utils.ByteConverter.ToUInt16(base.ParentFrame.Data, base.PacketStartIndex + 16, true);
                    if (ansiPasswordLength>0) {
                        //this.accountPassword=ByteConverter.ReadString(parentCifsPacket.ParentFrame.Data, parentCifsPacket.parametersStartIndex+28, ansiPasswordLength);
                        this.accountPassword = Utils.ByteConverter.ReadHexString(base.ParentFrame.Data, ansiPasswordLength, base.PacketStartIndex + 28);
                    }
                    if(unicodePasswordLength>0) {
                        string decodedPassword = accountPassword = Utils.ByteConverter.ReadString(base.ParentFrame.Data, base.PacketStartIndex + 28 + ansiPasswordLength, unicodePasswordLength, true, false);
                        string hexPassword = accountPassword = Utils.ByteConverter.ReadHexString(base.ParentFrame.Data, unicodePasswordLength, base.PacketStartIndex + 28 + ansiPasswordLength);
                        //this.accountPassword=decodedPassword+" (HEX: "+hexPassword+")";
                        this.accountPassword=hexPassword;
                    }
                    int packetIndex = base.PacketStartIndex + 28+ansiPasswordLength+unicodePasswordLength;
                    //I think we need an even word boundary (stupid SMB spec!)
                    if(parentCifsPacket.Flags2UnicodeStrings && ((packetIndex-parentCifsPacket.SmbHeaderStartIndex)%2==1))
                        packetIndex++;
                    if(unicodePasswordLength>0) {
                        this.accountName = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                        this.primaryDomain = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                        this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                        this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    }
                    else {
                        this.accountName = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, false, true);

                        this.primaryDomain = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, false, true);
                        this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, false, true);
                        this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, false, true);
                    }
                }

                if(base.SecurityBlobLength>0)
                    base.SecurityBlobIndex = base.PacketStartIndex + 2+base.WordCount*2;

                if (!this.ParentFrame.QuickParse) {
                    if (accountName != null && accountName.Length > 0)
                        this.Attributes.Add("Account Name", accountName);
                    if (primaryDomain != null && primaryDomain.Length > 0)
                        this.Attributes.Add("Primary Domain", primaryDomain);
                    if (nativeOs != null && nativeOs.Length > 0)
                        this.Attributes.Add("Native OS", nativeOs);
                    if (nativeLanManager != null && nativeLanManager.Length > 0)
                        this.Attributes.Add("Native LAN Manager", nativeLanManager);
                }

                //note: if an older dialect is used then the securityBlobLength will contain the value for PasswordLength (Account password size)
            }
        }


        //See 4.1.2. SESSION_SETUP_ANDX: Session Setup in CIFS-TR-1p00_FINAL.pdf
        internal class SetupAndXResponse : BasicSmbAndXCommand {//It would be cool to use this one in order to extract some extra information!
            private string nativeOs;
            private string nativeLanManager;//LAN Man
            private string primaryDomain;


            internal string NativeOs { get { return this.nativeOs; } }
            internal string NativeLanManager { get { return this.nativeLanManager; } }

            internal SetupAndXResponse(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Setup AndX Response") {

                this.nativeOs=null;
                this.nativeLanManager=null;
                this.primaryDomain=null;

                

                //OK, a big problem here is that I don't at this level know which protocol has been negotiated for the SMB session...
                //A good way to solve that problem is to look at the WordCount (number of parameters)
                if(base.WordCount==3) {//If wordCount is 3 then the dialect is prior to "NT LM 0.12"
                    //int packetIndex= base.PacketStartIndex + 9;
                    int packetIndex = base.PacketStartIndex + 8;//StartIndex is AFTER word_count in this implementation!
                    if (parentCifsPacket.Flags2UnicodeStrings && ((packetIndex - base.SmbHeaderStartIndex) % 2 == 1))
                        packetIndex++;//must start on a word boundrary (2 bytes)
                    this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.primaryDomain = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                }
                else if(base.WordCount==4) {//If wordCount is 4 then the dialect is "NT LM 0.12" or later
                    base.SecurityBlobLength = Utils.ByteConverter.ToUInt16(base.ParentFrame.Data, base.PacketStartIndex + 6, true);

                    int packetIndex= base.PacketStartIndex + 10+base.SecurityBlobLength;
                    //if(parentCifsPacket.Flags2UnicodeStrings && ((packetIndex-parentCifsPacket.PacketStartIndex)%2==1))
                    if (parentCifsPacket.Flags2UnicodeStrings && ((packetIndex - base.SmbHeaderStartIndex) % 2 == 1))
                        packetIndex++;//must start on a word boundrary (2 bytes)
                    this.nativeOs = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.nativeLanManager = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                    this.primaryDomain = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref packetIndex, parentCifsPacket.Flags2UnicodeStrings, true);
                }

                if(base.SecurityBlobLength>0)
                    base.SecurityBlobIndex= base.PacketStartIndex + 2+parentCifsPacket.WordCount*2;
            }
        }

        //useful in order to find remotely executed files, such powershell in this example:
        //https://401trg.pw/an-introduction-to-smb-for-network-security-analysts/
        internal class OpenAndXRequest : BasicSmbAndXCommand {
            /**
             * Transmits the name of the file, relative to Tid, the client wants to open.
             * Successful server response includes a file id (Fid) the client should supply for subsequent operations on this file.
             **/
            internal string FileName { get; }

            internal OpenAndXRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Open AndX Request") {
                ushort length = Utils.ByteConverter.ToUInt16(ParentFrame.Data, base.PacketStartIndex + 30, true);
                int index = base.PacketStartIndex + 32;
                this.FileName = Utils.ByteConverter.ReadNullTerminatedString(base.ParentFrame.Data, ref index, parentCifsPacket.Flags2UnicodeStrings, true, length);
                //this.FileName = Utils.ByteConverter.ReadLengthValueString(base.ParentFrame.Data, ref index, length);
            }
        }

        //3.15.2. SMB_COM_NT_TRANSACTION Formats 
        internal class TransactionRequest : AbstractSmbCommand {

            internal const string BROWSER_PROTOCOL_NAME = "\\MAILSLOT\\BROWSE";

            internal byte WordCount { get; }
            internal ushort ByteCount { get; }
            internal int BufferStartIndex { get { return base.PacketStartIndex + this.WordCount * 2 + 2; } }
            internal string TransactionName { get; }
            internal ushort ParameterCount { get; }
            internal ushort ParameterOffset { get; }
            internal int InnerPacketIndex { get; }

            /**
             * 3.15.4.1. Mail Slot Transaction Protocol
             * The only transaction allowed to a mailslot is a mailslot write.  The following table shows the interpretation of parameters for a mailslot transaction: 
             * 
             * Name             Value               Description 
             * -------------------------------------------------------------------------
             * Command          SMB_COM_TRANSACTION 
             * Name             \MAILSLOT\<name>    STRING Name of mail slot to write 
             * SetupCount       3
             * Setup[0]         1                   Command code == write mailslot 
             * Setup[1]                             Ignored
             * Setup[2]                             Ignored 
             * TotalDataCount   n                   Size of data to write to the mailslot 
             * Data[ n ]                            The data to write to the mailslot 
             **/

            internal TransactionRequest(ISmbCommandParent parentCifsPacket) : base(parentCifsPacket, "CIFS Trans Request") {
                this.WordCount = parentCifsPacket.ParentFrame.Data[parentCifsPacket.IndexOfNextPipelinedCommand - 1];//not very pretty, but this is where the WordCount is for this command

                //this.nextCommand = parentCifsPacket.ParentFrame.Data[parentCifsPacket.IndexOfNextPipelinedCommand];
                //this.nextCommand = base.ParentFrame.Data[this.PacketStartIndex];
                //this.nextCommandOffset = Utils.ByteConverter.ToUInt16(ParentFrame.Data, this.PacketStartIndex + 2, true);

                this.ByteCount = Utils.ByteConverter.ToUInt16(ParentFrame.Data, PacketStartIndex + this.WordCount * 2, true);

                //Same as filename string extraction in NTCreateAndXRequest
                int index = BufferStartIndex;//this value must be adjusted to a 16-bit word boundary -- it is probably not aligned at the moment
                ushort transactionaNameLength = this.ByteCount;//This field MUST be the total length of the Name field, plus any padding added for alignment.

                //https://msdn.microsoft.com/en-us/library/ee442175.aspx
                // If the TransactionName string consists of Unicode characters, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB Header.
                if (base.ParentCifsPacket.Flags2UnicodeStrings && ((index - base.ParentCifsPacket.SmbHeaderStartIndex) % 2 == 1)) {
                    index++;
                    transactionaNameLength--;
                }

                this.TransactionName = Utils.ByteConverter.ReadString(ParentFrame.Data, ref index, transactionaNameLength, base.ParentCifsPacket.Flags2UnicodeStrings, true, true);
                while (index < ParentFrame.Data.Length && ParentFrame.Data[index] == 0)
                    index++;
                this.InnerPacketIndex = index;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
                if (this.TransactionName == BROWSER_PROTOCOL_NAME) {
                    //return MS Win Browser Protocol Packet
                    CifsBrowserPacket browser = new CifsBrowserPacket(this.ParentFrame, this.InnerPacketIndex, this.PacketEndIndex);
                    foreach (AbstractPacket subPacket in browser.GetSubPackets(true))
                        yield return subPacket;
                }
                else
                    yield break;
            }
        }

        //4.1.1. NEGOTIATE: Negotiate Protocol
        internal class NegotiateProtocolRequest : AbstractSmbCommand {
            private List<string> dialectList;

            internal List<string> DialectList { get { return this.dialectList; } }

            internal NegotiateProtocolRequest(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Negotiate Protocol Request") {
                this.dialectList=new List<string>();
                ushort byteCount = Utils.ByteConverter.ToUInt16(parentCifsPacket.ParentFrame.Data, base.PacketStartIndex, true);


                //int packetIndex=parentCifsPacket.IndexOfNextPipelinedCommand+2;//It now points to the first BufferFormat in Dialects[]
                int packetIndex = this.PacketStartIndex + 2;//It now points to the first BufferFormat in Dialects[]
                int dialectsStartIndex=packetIndex;
                packetIndex++;//I've now skipped pased the first 0x02 (buffer format)
                while(packetIndex-dialectsStartIndex<byteCount && packetIndex<parentCifsPacket.ParentFrame.Data.Length) {
                    string dialectName = Utils.ByteConverter.ReadNullTerminatedString(parentCifsPacket.ParentFrame.Data, ref packetIndex);
                    this.dialectList.Add(dialectName);
                    packetIndex++;//skip the next 0x02 buffer format
                }
            }
        }
        internal class NegotiateProtocolResponse : AbstractSmbCommand {
            private ushort dialectIndex;

            internal ushort DialectIndex { get { return this.dialectIndex; } }

            internal NegotiateProtocolResponse(ISmbCommandParent parentCifsPacket)
                : base(parentCifsPacket, "CIFS Negotiate Protocol Response") {
                    this.dialectIndex = Utils.ByteConverter.ToUInt16(parentCifsPacket.ParentFrame.Data, base.PacketStartIndex, true);
            }

        }
        #endregion

        #region Security Blob, SPNEGO and NTLMSSP
        internal class SecurityBlob : AbstractPacket {

            //SPNEGO: http://tools.ietf.org/html/rfc4559
            //SPNEGO: http://msdn.microsoft.com/en-us/library/ms995330.aspx
            //GSS-API: http://tools.ietf.org/html/rfc4178
            //NTLMSSP: http://davenport.sourceforge.net/ntlm.html

            private int? spnegoIndex;
            private int? ntlmsspIndex;

            internal SecurityBlob(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, "Security Blob") {

                this.spnegoIndex=null;
                this.ntlmsspIndex=null;

                if(parentFrame.Data[PacketStartIndex]==0x60) {
                    int gssApiIndex = packetStartIndex + 1;
                    int gssApiLength = Utils.ByteConverter.GetAsn1Length(parentFrame.Data, ref gssApiIndex);
                    if(parentFrame.Data[gssApiIndex] == 6) {
                        gssApiIndex++;
                        int oidLength = Utils.ByteConverter.GetAsn1Length(parentFrame.Data, ref gssApiIndex);
                        this.spnegoIndex = gssApiIndex + oidLength;
                    }
                    // 60, xx, 06, 06, [SPNEGO OID], [SPNEGO]   ||    60 82 05 da 06 06 [OID] [SPNEGO]
                    //this.spnegoIndex=packetStartIndex+10;
                }
                else if(parentFrame.Data[PacketStartIndex]==0x4e) {
                    this.ntlmsspIndex=packetStartIndex;
                }
                else if(parentFrame.Data[PacketStartIndex]==0xA0) {
                    this.spnegoIndex=packetStartIndex;
                }
                else if(parentFrame.Data[PacketStartIndex]==0xA1) {
                    this.spnegoIndex=packetStartIndex;
                }

            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if(includeSelfReference)
                    yield return this;
                AbstractPacket packet=null;
                try {
                    if(this.spnegoIndex!=null)
                        packet=new SimpleAndProtectedGssapiNegotiation(ParentFrame, spnegoIndex.Value, PacketEndIndex);
                    else if(this.ntlmsspIndex!=null)
                        packet=new Packets.NtlmSspPacket(ParentFrame, ntlmsspIndex.Value, PacketEndIndex);
                }
                catch(Exception e){
                    SharedUtils.Logger.Log("Error parsing packet in SMB payload in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                }
                if(packet!=null) {
                    yield return packet;
                    foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
                else
                    yield break;
                    
            }
        }

        /// <summary>
        /// SPNEGO = Simple and Protected GSSAPI Negotiation Mechanism.
        /// </summary>
        internal class SimpleAndProtectedGssapiNegotiation : AbstractPacket {
            //http://msdn.microsoft.com/en-us/library/ms995330.aspx

            internal enum BasicTokenTypes : byte { NegTokenInit=0xa0, NegTokenTarg=0xa1 }

            private byte basicTokenType;
            private int? ntlmsspIndex;
            private int ntlmsspLength;
            private int? kerberos5Index;

            internal SimpleAndProtectedGssapiNegotiation(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, "SPNEGO") {
                this.basicTokenType=parentFrame.Data[packetStartIndex];
                this.ntlmsspIndex=null;
                this.ntlmsspLength=0;
                this.kerberos5Index = null;

                int packetIndex=packetStartIndex;
                int packetLength=GetSequenceElementLength(parentFrame.Data, ref packetIndex);

                if(parentFrame.Data[packetIndex]!=0x30)
                    throw new Exception("Not a valid SPNEGO packet format");
                //packetIndex++;
                int constructedSequenceLength=GetSequenceElementLength(parentFrame.Data, ref packetIndex);
                if(constructedSequenceLength>=packetLength)
                    throw new Exception("SPNEGO Packet length is not larger than Constructed Sequence length");
                while(packetIndex<packetEndIndex && packetIndex<packetStartIndex+packetLength) {
                    //read sequence elements...
                    byte sequenceElementIdentifier=parentFrame.Data[packetIndex];
                    int sequenceElementLength=GetSequenceElementLength(parentFrame.Data, ref packetIndex);
                    if((sequenceElementIdentifier&0xf0)==0xa0) {//SPNEGO sequence element
                        int sequenceElementNumber=sequenceElementIdentifier&0x0f;
                        if (!this.ParentFrame.QuickParse)
                            base.Attributes.Add("SPNEGO Element "+sequenceElementNumber+" length", sequenceElementLength.ToString());
                        byte[] kerberosV5OID = Utils.ByteConverter.ToByteArrayFromHexString("0x2a864886f712010202");//Kerberos V5 OID { 1 2 840 113554 1 2 2} https://tools.ietf.org/html/rfc4178

                        int kerberosOIDIndex = packetIndex;
                        do {
                            kerberosOIDIndex = Utils.BoyerMoore.IndexOf(parentFrame.Data, kerberosV5OID, kerberosOIDIndex + 1);
                            if (kerberosOIDIndex > packetIndex && kerberosOIDIndex + kerberosV5OID.Length < packetEndIndex) {
                                ushort krb5oidToken = Utils.ByteConverter.ToUInt16(parentFrame.Data, kerberosOIDIndex + kerberosV5OID.Length, true);
                                if (krb5oidToken == 1 || krb5oidToken == 2) { //req or rep
                                    this.kerberos5Index = kerberosOIDIndex + kerberosV5OID.Length + 2;
                                    break;
                                }
                            }
                        }
                        while (kerberosOIDIndex > packetIndex && kerberosOIDIndex < PacketEndIndex);
                        
                        
                    }
                    else if(sequenceElementIdentifier==0x04) {//NTLMSSP identifier
                        if(parentFrame.Data[packetIndex]==(byte)0x4e) {//make sure it is NTLMSSP and not for example Kerberos
                            //Get the NTLMSSP packet
                            this.ntlmsspIndex=packetIndex;
                            this.ntlmsspLength=sequenceElementLength;
                        }
                        packetIndex+=sequenceElementLength;
                        break;//there is no point in looping any more once we have the NTLMSSP
                    }
                    else
                        packetIndex += sequenceElementLength;
                }

            }

            /// <summary>
            /// Gets the sequence element length (in number of bytes) and advances the index value to the first byte after the length data
            /// </summary>
            /// <param name="data">The raw data</param>
            /// <param name="index">The index should point to the 0xA? position in data. The index will be moved to the first position after the lenght parameter after the function is executed.</param>
            /// <returns>Seq. Element length</returns>
            private int GetSequenceElementLength(byte[] data, ref int index) {
                index++;
                return Utils.ByteConverter.GetAsn1Length(data, ref index);

            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if(includeSelfReference)
                    yield return this;
                if(this.ntlmsspIndex!=null && this.ntlmsspLength>0){
                    Packets.NtlmSspPacket ntlmSspPacket=null;
                    try {
                         ntlmSspPacket=new Packets.NtlmSspPacket(this.ParentFrame, this.ntlmsspIndex.Value, this.ntlmsspIndex.Value+ this.ntlmsspLength -1);
                    }
                    catch(Exception ex) {
                        SharedUtils.Logger.Log("Error parsing NtlmSspPacket packet in SMB payload in " + this.ParentFrame.ToString() + ". " + ex.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(this.ParentFrame, this.ntlmsspIndex.Value, this.ntlmsspIndex.Value+ this.ntlmsspLength -1, ex.Message));
                        yield break;
                    }
                    yield return ntlmSspPacket;
                }
                else if(this.kerberos5Index != null) {
                    yield return new Packets.KerberosPacket(this.ParentFrame, this.kerberos5Index.Value, this.PacketEndIndex, false);
                }
                else
                    yield break;
            }
        }

        #endregion
    }
}
