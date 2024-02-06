using PacketParser.PacketHandlers;
using PacketParser.Utils;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.PacketHandlers.NjRatPacketHandler.C2Message;

namespace PacketParser.Packets {
    internal class NjRatPacket : AbstractPacket, ISessionPacket {
        //There isn't any good publibly available protocol spec for njRAT, but here's some info:
        //https://github.com/csieteco/njRatActiveDefense/blob/master/njdetector.py
        //https://cybergeeks.tech/just-another-analysis-of-the-njrat-malware-a-step-by-step-approach/
        //https://faculty.cc.gatech.edu/~pearce/papers/rats_usenix_2018.pdf
        //Approach of an Active Defense Protocol to Deal with RAT Malware - A Colombian Case Study Against njRAT Campaigns (Quinterno et al)
        //https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Modules/Class7.vb
        //File Manager?: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Forms/Manager.vb

        #region Static

        /**
        * 00000000 6c 76 7c 27 7c 27 7c 53 47 46 6a 53 32 56 6b 58 |lv|’|’|SGFjS2VkX| # <NI>: lv
        * 00000010 7a 68 46 4d 54 46 43 51 55 4d 34 7c 27 7c 27 7c |zhFMTFCQUM4|’|’|| # <NS>: |’|’|
        * 00000020 74 65 73 74 2d 50 43 7c 27 7c 27 7c 61 64 6d 69 |test-PC|’|’|admi| # <B>: SGFjS2VkXz... -> base64(HacKed_8E11BAC8)
        * 00000030 6e 7c 27 7c 27 7c 32 30 31 35 2d 30 35 2d 31 32 |n|’|’|2015-05-12| # <CAMPAIGN_ID>: HacKed
        * 00000040 7c 27 7c 27 7c 7c 27 7c 27 7c 57 69 6e 20 37 20 ||’|’||’|’|Win 7 | # <VSN>: 8E11BAC8
        * 00000050 50 72 6f 66 65 73 73 69 6f 6e 6e 65 6c 20 53 50 |Professionnel SP| # <PC_NAME>: test-PC
        * 00000060 31 20 78 36 34 7c 27 7c 27 7c 4e 6f 7c 27 7c 27 |1 x64|’|’|No|’|’| # <PC_USERNAME>: admin
        * 00000070 7c 30 2e 36 2e 34 7c 27 7c 27 7c 2e 2e 7c 27 7c ||0.6.4|’|’|..|’|| # <INSTALL_DATE>: 2015-05-12
        * 00000080 27 7c 53 57 35 7a 64 47 46 73 62 43 42 68 62 6d |’|SW5zdGFsbCBhbm| # <OS>: Win 7 Professionnel SP1 x64
        * 00000090 51 67 64 58 4e 6c 49 47 35 71 55 6b 46 55 49 45 |QgdXNlIG5qUkFUIE| # <WEBCAM_FLAG>: No
        * 000000a0 5a 56 52 43 42 30 62 79 42 6f 59 57 4e 72 49 46 |ZVRCB0byBoYWNrIF| # <RAT_VERSION>: 0.6.4
        * 000000b0 42 44 49 43 30 67 57 57 39 31 56 48 56 69 5a 53 |BDIC0gWW91VHViZS| # <ACTIVE_WINDOW>: SW5zdGFsbCBhbmQgdXNlIG5qU...
        * 000000c0 41 74 49 45 64 76 62 32 64 73 5a 53 42 44 61 48 |AtIEdvb2dsZSBDaH| # -> base64(Install and use njRAT FUD to hack
        * 000000d0 4a 76 62 57 55 3d 7c 27 7c 27 7c 5b 65 6e 64 6f |JvbWU=|’|’|[endo| # PC - YouTube - Google Chrome)
        * 000000e0 66 5d |f]| # <NT>: [endof]
       */

        private static readonly string[] DELIMITERS = {

        };

        private static readonly HashSet<string> KnownCommandsAndResponses = new HashSet<string> { 
                "~" ,
                "act",
                "bla",
                "CAM",
                "CAP",//Screen Capture
                "CH",
                "ER",
                "Ex",//Execute Tool
                "FM",
                "get",
                "inf",//Get volume serial, C2 server, process name etc.
                "infn",
                "info",
                "INS",
                "inv",//?? invoke module
                "kla",
                "kl",//Get Key Logger data
                "li",
                "ll",
                "llv",
                "lv",
                "lvv",
                "MIC",
                "MSG",
                "pl",
                "PLG",
                "post",
                "post+",
                "P",//PING or just an empty message if length fields are used
                "proc",
                "prof",//?? Create registry key
                "ret",//Get Passwords (runs assembly pw.dll?)
                "RG",//Reads, writes or deletes registry keys
                "rn",//Run command
                "rs",
                "rsc",
                "rss",
                "sc~",
                "scPK",
                "srv",
                "STP",
                "tcp",
                "un",//Uninstall, kill or restart njRAT"
                "up",//?? Update njRAT from URL or archive data
                "WT"
            };

        private static readonly int MAX_COMMAND_LENGTH = 5;
        private static readonly HashSet<char> CommandChars;

        //private static readonly byte[] JPEG_HEADER = { 0xFF, 0xD8, 0xFF };

        static NjRatPacket() {//default static constructor
            //Add additional commands/responses in case there is any we missed
            foreach (string command in NjRatPacketHandler.C2Message.ServerMsgDict.Keys) {
                if (!KnownCommandsAndResponses.Contains(command))
                    KnownCommandsAndResponses.Add(command);
            }
            foreach (string response in NjRatPacketHandler.C2Message.BotMsgDict.Keys) {
                if (!KnownCommandsAndResponses.Contains(response))
                    KnownCommandsAndResponses.Add(response);
            }

            CommandChars = new HashSet<char>();
            foreach (string cmd in KnownCommandsAndResponses) {
                foreach (char c in cmd)
                    if (!CommandChars.Contains(c))
                        CommandChars.Add(c);
            }
            MAX_COMMAND_LENGTH = Math.Max(MAX_COMMAND_LENGTH, KnownCommandsAndResponses.OrderByDescending(c => c.Length).First().Length);
        }

        private static bool TryParseLengthField(byte[] data, ref int offset, int length, out int parsedMessageLength) {
            if (data.Length - offset > 1) {
                //check if the message starts with <$length><NULL><command> or a command
                if (data[offset] >= 0x30 && data[offset] <= 0x39) {
                    //first character is a digit
                    //read the null terminated length field
                    string lengthString = Utils.ByteConverter.ReadNullTerminatedString(data, ref offset, false, false, Math.Min(length, 9));
                    if (!string.IsNullOrEmpty(lengthString) && Int32.TryParse(lengthString, out int messageLength)) {
                        parsedMessageLength = messageLength;
                        return true;
                    }
                }
            }
            parsedMessageLength = 0;
            return false;
        }

        private static bool TryParseLength(byte[] data, int startIndex, int length, out int messageStartIndex, out int messageLength, out int totalLength) {
            int offset = startIndex;

            if(TryParseLengthField(data, ref offset, length, out messageLength)) {
                //Length is null terminated ASCII string, followed by the message
                messageStartIndex = offset;
                totalLength = offset + messageLength - startIndex;
                return true;
            }
            else {
                //read until end of frame or index of [endof]
                byte[] endofSequence = ASCIIEncoding.ASCII.GetBytes("[endof]");//5b 65 6e 64 6f 66 5d
                int endofIndex = Utils.BoyerMoore.IndexOf(data, endofSequence, startIndex);
                if (endofIndex > startIndex) {
                    messageStartIndex = startIndex;
                    messageLength = endofIndex - startIndex;
                    totalLength = messageLength + endofSequence.Length;
                    return true;
                }
            }
            messageStartIndex = startIndex;
            messageLength = -1;
            totalLength = -1;
            return false;
        }

        [Obsolete("Use TryParseLength and TryParseCommand instead")]
        private static bool TryParseMessage(byte[] data, int startOffset, int length, out string command, out int parsedBytes, out string possibleDelimiter, out int delimiterIndex) {
            /*
            int offset = startOffset;

            if (TryParseLengthField(data, ref offset, out int commandLength)) {
                return TryParseMessage(data, startOffset, offset, length, commandLength, out command, out parsedBytes, out possibleDelimiter, out delimiterIndex);
            }
            else {
                //read until end of frame or index of [endof]
                byte[] endofSequence = ASCIIEncoding.ASCII.GetBytes("[endof]");//5b 65 6e 64 6f 66 5d
                int endofIndex = Utils.BoyerMoore.IndexOf(data, endofSequence, startOffset);
                if(endofIndex > startOffset) {
                    return TryParseMessage(data, startOffset, startOffset, length, endofIndex - startOffset + endofSequence.Length, out command, out parsedBytes, out possibleDelimiter, out delimiterIndex);
                }
            }
            */
            command = null;
            parsedBytes = 0;
            possibleDelimiter = null;
            delimiterIndex = -1;
            return false;

        }

        //private static bool TryParseCommandAndDelimiter(byte[] data, int messageOffset, int messageLength, out string command, out string possibleDelimiter, out int delimiterIndex) {
        private static bool TryParseCommand(byte[] data, int commandOffset, int messageLength, out string command) {
            if (messageLength < 0) {
                command = null;
                return false;
            }
            if (messageLength == 0) {
                command = String.Empty;//same as 'P' or PING
                return true;
            }
            else {
                StringBuilder commandBuilder = new StringBuilder();
                for (int i = 0; i < messageLength && i <= MAX_COMMAND_LENGTH; i++) {
                    byte b = data[commandOffset + i];
                    char c = (char)b;
                    if (char.IsLetter(c) || CommandChars.Contains(c))
                        commandBuilder.Append(c);
                    else
                        break;
                }
                if (commandBuilder.Length > 0) {
                    command = commandBuilder.ToString();
                    //reduce the command if it is not known but the first part of the string is a valid command
                    if (!KnownCommandsAndResponses.Contains(command)) {
                        for (int i = command.Length - 1; i >= 1; i--) {
                            if (KnownCommandsAndResponses.Contains(command.Substring(0, i))) {
                                command = command.Substring(0, i);
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
            command = null;
            return false;
        }

        private static bool TryParseSplitter(byte[] data, int splitterIndex, int messageEndIndex,  out string splitterCandidate) {
            //==Examples of known delimiters==
            //|'|'| <-- original
            //|
            //|Kiler|
            //|Coringa|  <--this one triggers an AV alert if included as a string in the code!
            //|Hassan|
            //@!#&^%$
            //Y262SUCZ4UJJ

            //after the command is most likely a delimiter
            StringBuilder splitterBuilder = new StringBuilder();
            const int MAX_DELIMITER_LENGTH = 15;//I don't expect the delimiter to be more than 12 bytes (one known delimiter is "Y262SUCZ4UJJ")
            for (int i = 0; i < MAX_DELIMITER_LENGTH; i++) {
                if (splitterIndex + i > messageEndIndex || splitterIndex + i >= data.Length)
                    break;
                byte b = data[splitterIndex + i];
                if (b < 32)
                    break;
                if (b > 126)
                    break;
                char c = (char)b;
                if (char.IsControl(c))
                    break;
                splitterBuilder.Append(c);
            }
            splitterCandidate = splitterBuilder.ToString();
            return true;
        }


        [Obsolete("Use TryParseCommand instead")]
        private static bool TryParseMessage(byte[] data, int startOffset, int commandOffset, int length, int commandLength, out string command, out int parsedBytes, out string possibleDelimiter, out int delimiterIndex) {
            if (commandLength == 0 && commandOffset == startOffset + length) {
                command = String.Empty;//same as 'P' or PING
                parsedBytes = commandOffset - startOffset;//same as commandLength + 2?
                possibleDelimiter = null;
                delimiterIndex = -1;
                return true;
            }
            else if(commandOffset + commandLength > data.Length) {
                command = null;
                parsedBytes = 0;
                possibleDelimiter = null;
                delimiterIndex = -1;
                return false;
            }
            else {
                StringBuilder commandBuilder = new StringBuilder();
                for (int i = 0; i < commandLength && i < 6; i++) {
                    byte b = data[commandOffset + i];
                    if (char.IsLetter((char)b))
                        commandBuilder.Append((char)b);
                    else {
                        if (b == (byte)'~' || b == (byte)'+')//commands might end with these chars
                            commandBuilder.Append((char)b);
                        break;
                    }

                }
                if (commandBuilder.Length > 0) {
                    command = commandBuilder.ToString();
                    //reduce the command if it is not known but the first part of the string is a valid command
                    if (!KnownCommandsAndResponses.Contains(command)) {
                        for (int i = command.Length - 1; i >= 2; i--) {
                            if (KnownCommandsAndResponses.Contains(command.Substring(0, i))) {
                                command = command.Substring(0, i);
                                commandBuilder = new StringBuilder(command);
                                break;
                            }
                        }
                    }

                    parsedBytes = commandOffset - startOffset + commandLength;
                    if (parsedBytes > length)
                        parsedBytes = 0;

                    //after the command is most likely a delimiter
                    delimiterIndex = commandOffset + commandBuilder.Length;
                    StringBuilder delimiterBuilder = new StringBuilder();
                    for (int i = 0; i < 12; i++) {//I don't expect the delimiter to be more than 12 bytes (one known delimiter is "Y262SUCZ4UJJ")
                        if (delimiterIndex + i > startOffset + length)
                            break;
                        byte b = data[delimiterIndex + i];
                        if (b < 32)
                            break;
                        if (b > 126)
                            break;
                        char c = (char)b;
                        if (char.IsControl(c))
                            break;
                        delimiterBuilder.Append(c);
                    }
                    possibleDelimiter = delimiterBuilder.ToString();
                    return true;
                }
            }
            command = null;
            parsedBytes = 0;
            possibleDelimiter = null;
            delimiterIndex = -1;
            return false;
        }

        #endregion

        private readonly int totalLength;//The full length of the njRAT packet data, including length fields or "[endof]" trailer

        public string CommandString { get; } = null;
        //public string Response { get; } = null;
        
        public readonly int MessageStartIndex;//index in Frame where the command is (after <len><NULL>)
        public readonly int MessageLength;//NOT including the <len><NULL> bytes
        public readonly string SplitterCandidate;
        public readonly int SplitterIndex = -1;
        //public string Delimiter { get; }
        //public string[] Fields { get; }
        public bool PacketHeaderIsComplete {
            get {
                throw new NotImplementedException();
            }
        }

        public int ParsedBytesCount { get; } = 0;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out NjRatPacket njRatPacket) {
            if (TryParseLength(parentFrame.Data, packetStartIndex, packetEndIndex - packetStartIndex + 1, out _, out _, out _)) {
                try {
                    njRatPacket = new NjRatPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    return true;
                }
                catch { }
            }
            njRatPacket = null;
            return false;
        }

        public NjRatPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "njRAT") {

            if (TryParseLength(parentFrame.Data, packetStartIndex, base.PacketLength, out this.MessageStartIndex, out this.MessageLength, out this.totalLength)) {
                if (this.totalLength <= base.PacketLength) {
                    this.ParsedBytesCount = this.totalLength;
                    if (this.totalLength < base.PacketLength)
                        this.PacketEndIndex = this.MessageStartIndex + this.totalLength - 1;
                }
                if (this.MessageLength >= 0) {
                    if (TryParseCommand(parentFrame.Data, this.MessageStartIndex, this.MessageLength, out string command)) {
                        this.CommandString = command;
                        if (this.MessageLength > command.Length) {
                            if (TryParseSplitter(parentFrame.Data, this.MessageStartIndex + command.Length, this.PacketEndIndex, out this.SplitterCandidate)) {
                                //avoid splitters at the end of the frame because they might be truncated
                                if(this.MessageStartIndex + command.Length + this.SplitterCandidate.Length > this.PacketEndIndex) {
                                    this.SplitterCandidate = null;
                                }
                                this.SplitterIndex = this.MessageStartIndex + command.Length;
                            }
                        }
                    }
                }
            }
            else
                throw new Exception("Invalid njRAT packet");
            /*
            if(TryParseMessage(parentFrame.Data, packetStartIndex, packetEndIndex - packetStartIndex + 1, out string command, out int parsedBytes, out this.SplitterCandidate, out this.SplitterIndex)) {
                this.CommandOrResponseString = command;
                this.ParsedBytesCount = parsedBytes;
                if(this.PacketEndIndex >= packetStartIndex + this.ParsedBytesCount)
                    this.PacketEndIndex = packetStartIndex + this.ParsedBytesCount - 1;
            }
            */
        }


        

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }

       


    }
}
