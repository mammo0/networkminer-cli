using PacketParser.PacketHandlers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Packets {

    //https://tools.ietf.org/html/rfc1179
    //https://web.archive.org/web/20010815102143/http://www.astart.com:80/lprng/LPRng-HOWTO.html
    abstract class LpdPacket : AbstractPacket, ISessionPacket {

        //If there are other operands to the command,
        //they are separated from the printer queue name with white space
        //(ASCII space, horizontal tab, vertical tab, and form feed)
        private static readonly char[] WHITE_SPACE_CHARS = new[] { ' ', '\t', (char)0x0b, (char)0x0c };

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {
            result = null;
            try {
                if (clientToServer) {
                    if (LpdRequestPacket.TryParseCommandLine(parentFrame.Data, packetStartIndex, packetEndIndex, out _, out _, out _))
                        result = new LpdRequestPacket(parentFrame, packetStartIndex, packetEndIndex);
                    else
                        return LpdControlFilePacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, out result);
                }
                else if (packetStartIndex == packetEndIndex)
                    result = new LpdResponsePacket(parentFrame, packetStartIndex);
            }
            catch { }
            return result != null;
        }

        public bool PacketHeaderIsComplete {
            get {
                return true;
            }
        }

        public abstract int ParsedBytesCount { get; }

        private LpdPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "LPD") {
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            yield break;
        }

        internal class LpdRequestPacket : LpdPacket {
            

            internal enum DaemonCommandCode : byte {
                PrintWaitingJobs = 1,
                ReceiveJob = 2,
                SendQueueStateShort = 3,
                SendQueueStateLong = 4,
                RemoveJobs = 5
            }

            internal enum ReceiveJobSubcommandCode : byte {
                AbortJob = 1,
                ReceiveControlFile = 2,
                ReceiveDataFile = 3
            }

            internal static bool TryParseCommandLine(byte[] data, int startIndex, int endIndex, out byte commandCode, out string[] operands, out int bytesRead) {
                commandCode = data[startIndex];
                if (!Enum.IsDefined(typeof(DaemonCommandCode), commandCode)) {
                    bytesRead = 0;
                    operands = Array.Empty<string>();
                    return false;
                }
                int index = startIndex + 1;
                try {
                    string line = Utils.ByteConverter.ReadLine(data, ref index, true);
                    bytesRead = index - startIndex;
                    operands = line.Split(WHITE_SPACE_CHARS);
                    return index <= endIndex + 1 && data[index - 1] == 0x0a;
                }
                catch {
                    bytesRead = 0;
                    operands = Array.Empty<string>();
                    return false;
                }
            }

            internal byte CommandCode;
            internal string[] Operands;
            private readonly int parsedBytesCount;

            public override int ParsedBytesCount {
                get {
                    return this.parsedBytesCount;
                }
            }

            internal LpdRequestPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex) {
                if (!TryParseCommandLine(parentFrame.Data, packetStartIndex, packetEndIndex, out this.CommandCode, out this.Operands, out this.parsedBytesCount))
                    throw new Exception("Invalid LPD client command");
            }

            internal bool TryGetCommand(out DaemonCommandCode command) {
                if (Enum.IsDefined(typeof(DaemonCommandCode), this.CommandCode)) {
                    command = (DaemonCommandCode)this.CommandCode;
                    return true;
                }
                else {
                    command = DaemonCommandCode.PrintWaitingJobs;
                    return false;
                }
            }

            internal bool TryGetSubCommand(out ReceiveJobSubcommandCode subCommand) {
                if (Enum.IsDefined(typeof(ReceiveJobSubcommandCode), this.CommandCode)) {
                    subCommand = (ReceiveJobSubcommandCode)this.CommandCode;
                    return true;
                }
                else {
                    subCommand = ReceiveJobSubcommandCode.AbortJob;
                    return false;
                }
            }

        }

        internal class LpdResponsePacket : LpdPacket {
            internal byte ResponseCode { get; }

            public override int ParsedBytesCount { get { return 1; } }

            internal LpdResponsePacket(Frame parentFrame, int packetStartIndex)
            : base(parentFrame, packetStartIndex, packetStartIndex) {
                this.ResponseCode = parentFrame.Data[packetStartIndex];
            }

        }

        internal class LpdControlFilePacket : LpdPacket {

            internal enum Command : byte {
                Class = (byte)'C',
                Host = (byte)'H',
                Indent = (byte)'I',
                JobName = (byte)'J',
                PrintBanner = (byte)'L',
                Mail = (byte)'M',
                NameOfSourceFile = (byte)'N',
                UserID = (byte)'P',
                SymbolicLink = (byte)'S',
                Title = (byte)'T',
                Unlink = (byte)'U',
                Width = (byte)'W',
                FontFileR = (byte)'1',
                FontFileI = (byte)'2',
                FontFileB = (byte)'3',
                FontFileS = (byte)'4',
                PlotCifFile = (byte)'c',
                PrintDviFile = (byte)'d',
                PrintFormattedFile = (byte)'f',
                PlotFile = (byte)'g',
                Kerberos = (byte)'k',
                LeaveControlChars = (byte)'l',
                PrintDitroffFile = (byte)'n',
                PrintPostscriptFile = (byte)'o',
                PrintPrFormat = (byte)'p',
                PrintFortran = (byte)'r',
                PrintTroffFile = (byte)'t',
                PrintRasterFile = (byte)'v'
            }

            
            public override int ParsedBytesCount {
                get {
                    throw new NotImplementedException();
                }
            }

            

            public new static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
                /**
                    The control file must be an ASCII stream with the ends of lines
                    indicated by ASCII LF.
                    [...]
                    Once all of the contents have
                    been delivered, an octet of zero bits is sent as an indication that
                    the file being sent is complete.
                */
                result = null;
                if (parentFrame.Data[packetEndIndex] != 0x00)
                    return false;
                if (packetEndIndex > packetStartIndex && parentFrame.Data[packetEndIndex-1] != 0x0a)
                    return false;
                for(int i = packetStartIndex; i < packetEndIndex - 1; i++) {
                    if (parentFrame.Data[i] > 126)
                        return false;
                    if (parentFrame.Data[i] != 0x0a && char.IsControl((char)parentFrame.Data[i]) && !WHITE_SPACE_CHARS.Contains((char)parentFrame.Data[i]))
                        return false;
                }
                try {
                    result = new LpdControlFilePacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                catch {
                    return false;
                }
            }

            internal List<(Command cmd, string arg)> CommandList;

            private LpdControlFilePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex) {
                this.CommandList = new List<(Command, string)>();
                int index = packetStartIndex;
                while(index < packetEndIndex -1) {
                    string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                    if (string.IsNullOrEmpty(line))
                        throw new Exception("Invalid LPD Control File Command Line");
                    Command command = (Command)line[0];
                    this.CommandList.Add((command, line.Substring(1)));
                }
                
            }
        }
    }
}
