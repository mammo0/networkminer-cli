using Microsoft.SqlServer.Server;
using PacketParser.FileTransfer;
using PacketParser.Packets;
using PacketParser.Utils;
using SharedUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI.WebControls.WebParts;
using static PacketParser.PacketHandlers.SmtpPacketHandler;

namespace PacketParser.PacketHandlers
{
    internal class BackConnectPacketHandler : RfbPacketHandler {
        public override ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.BackConnect;
            }
        }
        public override Type[] ParsedTypes { get; } = typeof(BackConnectPacket).GetNestedTypes().Where(t => t.IsClass).Append(typeof(BackConnectPacket)).ToArray();

        private readonly PopularityList<uint, BackConnectPacket.Command> recentCommands;
        private readonly PopularityList<NetworkTcpSession, string> lastFileManagerCommand;
        private readonly PopularityList<NetworkTcpSession, string> putFilename;
        //private PopularityList<NetworkTcpSession, RfbPacket.VncPixelFormat> pixelFormat;

        public BackConnectPacketHandler(PacketHandler mainPacketHandler, byte maxFramesPerSecond) : base(mainPacketHandler, maxFramesPerSecond) {
            this.recentCommands = new PopularityList<uint, BackConnectPacket.Command>(100);
            this.lastFileManagerCommand = new PopularityList<NetworkTcpSession, string>(100);
            this.putFilename = new PopularityList<NetworkTcpSession, string>(100);
        }


        public override int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            BackConnectPacket backConnectPacket = null;
            BackConnectPacket.ReverseVncPacket backConnectReverseVncPacket = null;
            BackConnectPacket.ReverseSocksPacket backConnectReverseSocksPacket = null;
            BackConnectPacket.FileManagerPacket backConnectFileManagerPacket = null;
            BackConnectPacket.ReverseShellPacket backConnectReverseShellPacket = null;
            
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                Type pType = p.GetType();
                if (pType == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (pType == typeof(BackConnectPacket))
                    backConnectPacket = (BackConnectPacket)p;
                else if (pType == typeof(BackConnectPacket.ReverseSocksPacket))
                    backConnectReverseSocksPacket = (BackConnectPacket.ReverseSocksPacket)p;
                else if (p is BackConnectPacket.ReverseVncPacket)
                    backConnectReverseVncPacket = (BackConnectPacket.ReverseVncPacket)p;
                else if(pType == typeof(BackConnectPacket.FileManagerPacket))
                    backConnectFileManagerPacket = (BackConnectPacket.FileManagerPacket)p;
                else if (pType == typeof(BackConnectPacket.ReverseShellPacket))
                    backConnectReverseShellPacket = (BackConnectPacket.ReverseShellPacket)p;

            }
            if (backConnectPacket != null && tcpPacket != null) {
                if (backConnectPacket.PacketHeaderIsComplete) {

                    BackConnectPacket.Command cmd = BackConnectPacket.Command.UNKNOWN;

                    if (transferIsClientToServer) {
                        //bot to C2
                        uint commandId = Utils.ByteConverter.ToUInt32(backConnectPacket.ID);
                        if (recentCommands.ContainsKey(commandId))
                            cmd = recentCommands[commandId];
                        else if (Enum.IsDefined(typeof(BackConnectPacket.Command), backConnectPacket.C2Command)) {
                            cmd = (BackConnectPacket.Command)backConnectPacket.C2Command;
                        }
                    }
                    else {
                        //C2 to bot
                        if (Enum.IsDefined(typeof(BackConnectPacket.Command), backConnectPacket.C2Command)) {
                            cmd = (BackConnectPacket.Command)backConnectPacket.C2Command;
                            if (cmd != BackConnectPacket.Command.SLEEP && cmd != BackConnectPacket.Command.UNKNOWN) {
                                uint commandId = Utils.ByteConverter.ToUInt32(backConnectPacket.ID);
                                this.recentCommands[commandId] = cmd;
                            }
                        }
                        else {
                            Logger.Log("Unknown BackConnect command: 0x" + backConnectPacket.C2Command.ToString("X2"), Logger.EventLogEntryType.Warning);
#if DEBUG
                            System.Diagnostics.Debugger.Break();//Unknown command!
#endif
                        }
                    }


                    System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();


                    tcpSession.ServerHost.AddNumberedExtraDetail("BackConnect Auth", ByteConverter.ToHexString(backConnectPacket.Auth, 4, true, true));

                    if(cmd == BackConnectPacket.Command.UNKNOWN) {
                        //this might be a SOCKS, reverse shell or file manager session. Let's make a guess that it's file manger, since that's probably the most interesting one
                        if(BackConnectPacket.FileManagerPacket.TryParse(backConnectPacket.ParentFrame, backConnectPacket.PacketStartIndex, backConnectPacket.PacketEndIndex, transferIsClientToServer, out BackConnectPacket.FileManagerPacket newFileManagerPacket)) {
                            cmd = BackConnectPacket.Command.FILE_MANAGER_2;
                        }
                    }

                    if (cmd != BackConnectPacket.Command.UNKNOWN) {

                        if(backConnectPacket.C2Command == (byte)cmd)
                            parms.Add("C2 command", cmd.ToString() + " (0x" + backConnectPacket.C2Command.ToString("x2") + ")");
                        else
                            parms.Add("C2 command", cmd.ToString());

                        if (cmd == BackConnectPacket.Command.SLEEP)
                            parms.Add(cmd.ToString() + " Time", "" + Utils.ByteConverter.ToUInt32(backConnectPacket.Params, 0, 4, true) + " seconds");
                        else
                            parms.Add(cmd.ToString() + " Params", "" + Utils.ByteConverter.ToUInt32(backConnectPacket.Params, 0, 4, true));
                        byte[] zero = { 0, 0, 0, 0 };
                        if (!backConnectPacket.ID.SequenceEqual(zero))
                            parms.Add(cmd.ToString() + " ID", "" + BitConverter.ToString(backConnectPacket.ID).Replace('-', ' '));
                        if (transferIsClientToServer && tcpSession.Flow.BytesSentServer == 0) {
                            //we might have a new BackConnect session, let's figure out which module that is running
                            int expectedPacketLengthShort = BackConnectPacket.C2_PACKET_LENGTH + (backConnectPacket.Encrypted ? 4 : 0);
                            int expectedPacketLengthLong = BackConnectPacket.MODULE_START_PACKET_LENGTH + (backConnectPacket.Encrypted ? 4 : 0);

                            if (tcpSession.Flow.BytesSentClient == expectedPacketLengthShort || tcpSession.Flow.BytesSentClient == expectedPacketLengthLong) {
                                if (cmd == BackConnectPacket.Command.SOCKS)
                                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.BackConnectReverseSocks, false);
                                else if (cmd == BackConnectPacket.Command.VNC || cmd == BackConnectPacket.Command.VNC_2)
                                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.BackConnectReverseVNC, false);
                                else if (cmd == BackConnectPacket.Command.FILE_MANAGER_2)
                                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.BackConnectFileManager, false);
                                else if (cmd == BackConnectPacket.Command.REVERSE_SHELL_2)
                                    tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.BackConnectReverseShell, false);
                            }


                        }
                    }
                    if (parms.Count > 0)
                        this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(backConnectPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, backConnectPacket.ParentFrame.Timestamp, "BackConnect C2"));
                }
                return backConnectPacket.ParsedBytesCount;
            }
            else if (backConnectReverseSocksPacket != null) {
                return backConnectReverseSocksPacket.PacketLength;
            }
            else if (backConnectReverseVncPacket != null) {
                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                int skippedBytes = 0;

                if (backConnectReverseVncPacket.PixelFormat.HasValue)
                    base.SetPixelFormat(backConnectReverseVncPacket.PixelFormat.Value, tcpSession, tcpSession.ClientHost, parms);
                if (backConnectReverseVncPacket.ScreenSize.HasValue)
                    base.SetScreenSize(backConnectReverseVncPacket.ScreenSize.Value, parms, tcpSession, tcpSession.ClientHost);
                if (!string.IsNullOrEmpty(backConnectReverseVncPacket.VncDesktopName))
                    base.SetVncDesktopName(backConnectReverseVncPacket.VncDesktopName, parms, tcpSession, tcpSession.ClientHost);
                if (backConnectReverseVncPacket.CommandPacket != null) {
                    base.ExtractCommandPacketDetails(backConnectReverseVncPacket.CommandPacket, tcpSession, tcpSession.ClientHost, parms);
                }
                else if (backConnectReverseVncPacket.ResponsePacket != null) {
                    var responsePacket = backConnectReverseVncPacket.ResponsePacket;
                    //base.ExtractResponsePacketDetails(responsePacket, tcpSession, parms, transferIsClientToServer, ref skippedBytes);
                    base.ExtractResponsePacketDetails(responsePacket, tcpSession, parms, transferIsClientToServer);
                }

                if (parms.Count > 0)
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(backConnectReverseVncPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, backConnectReverseVncPacket.ParentFrame.Timestamp, "BackConnect VNC"));

                return backConnectReverseVncPacket.PacketLength + skippedBytes;
            }
            else if (backConnectFileManagerPacket != null) {
                //Packet #1: Client->Server, tcp.len == 245, starts with KNOWN_AUTH_VALUES
                //Packet #2: Server->Client, 1 byte: 0x0a
                //Packet #3: Client->Server, 4 bytes: +ok[0x0a] (tcp.payload == 2b:6f:6b:0a)
                //Packet #4: Server->Client, [Command][0x0a]
                //Packet #5: Client->Server, "*[lenght]" or "+accept"
                //Packet #6: Client->Server, [DATA] (length as specified with *[lenght])
                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                int parsedBytes = backConnectFileManagerPacket.PacketLength;
                if (transferIsClientToServer) {
                    if (this.lastFileManagerCommand.ContainsKey(tcpSession)) {
                        string lastCommand = this.lastFileManagerCommand[tcpSession];
                        //TODO check if command is DISK, CDDIR, DIR etc
                        byte[] clientData = backConnectFileManagerPacket.GetPacketData();
                        if (clientData.Length > 2 && clientData[0] == 0x2a) {
                            //'*' + length + \n
                            int index = 1;
                            string line = Utils.ByteConverter.ReadLine(clientData, ref index, true);
                            if (Int32.TryParse(line, out int payloadLength)) {
                                if (clientData.Length >= payloadLength + index) {
                                    int payloadStartIndex = index;
                                    line = Utils.ByteConverter.ReadLine(clientData, ref index, true);
                                    char separator = '|';
                                    while (!string.IsNullOrEmpty(line) && index < payloadStartIndex + payloadLength) {
                                        if (line.Contains(separator)) {
                                            string pName = line.Substring(0, line.IndexOf(separator)).Trim();
                                            string pValue = line.Substring(line.IndexOf(separator) + 1).Trim();
                                            //special handling of CDDIR command
                                            if (lastCommand == "CDDIR" || lastCommand == "DIR") {
                                                //[size]|[epoch]|[something?]
                                                string[] valueArray = pValue.Split('|');
                                                if (valueArray.Length == 3) {
                                                    if (UInt32.TryParse(valueArray[1], out uint epochTime)) {
                                                        DateTime timestamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(epochTime);
                                                        string timestampString = timestamp.ToString("yyyy-MM-dd");
                                                        string fileSizeString = "";
                                                        if (Int32.TryParse(valueArray[0], out int fileSize)) {

                                                            fileSizeString = " " + Utils.StringManglerUtil.ToFileSizeText(fileSize);
                                                        }
                                                        pValue = timestampString + fileSizeString;

                                                    }
                                                }
                                            }
                                            else if (lastCommand == "DISK") {
                                                //[size]|[free/used?]|[?]|[?]
                                                string[] valueArray = pValue.Split('|');
                                                if (valueArray.Length == 4) {
                                                    if (long.TryParse(valueArray[0], out long diskSize)) {
                                                        if (long.TryParse(valueArray[1], out long diskUsedOrFree)) {
                                                            int percent = (int)((100.0 * diskUsedOrFree) / diskSize);
                                                            pValue = Utils.StringManglerUtil.ToFileSizeText(diskSize) + " (" + percent + "%)";
                                                        }
                                                    }
                                                }
                                            }
                                            parms.Add(pName, pValue);
                                        }
                                        line = Utils.ByteConverter.ReadLine(clientData, ref index, true);
                                    }
                                    parsedBytes = payloadStartIndex + payloadLength;
                                }
                                else
                                    parsedBytes = 0;
                            }
                        }
                    }
                }
                else {
                    //server to client
                    if (this.lastFileManagerCommand.ContainsKey(tcpSession) && lastFileManagerCommand[tcpSession] == "PUT" && this.putFilename.ContainsKey(tcpSession) && backConnectFileManagerPacket.PacketLength > 2 && backConnectFileManagerPacket.PacketLength < 11 && backConnectFileManagerPacket.GetPacketData().Take(backConnectFileManagerPacket.PacketLength - 1).All(b => b >= 0x30 && b <= 0x39)) {
                        string filePath = this.putFilename[tcpSession];
                        //upload of file. here comes the file size
                        int index = 0;
                        string fileSizeString = Utils.ByteConverter.ReadLine(backConnectFileManagerPacket.GetPacketData(), ref index, true);
                        if (long.TryParse(fileSizeString, out long fileSize)) {
                            parsedBytes = index;
                            //TODO: Set up file handler!
                            FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.BackConnect, filePath, "/", "BackConnect File Upload", tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, FileStreamAssembler.FileAssmeblyRootLocation.destination);
                            assembler.FileContentLength = fileSize;
                            assembler.FileSegmentRemainingBytes = fileSize;
                            if (assembler.TryActivate())
                                this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                        }
                    }
                    else if (!string.IsNullOrEmpty(backConnectFileManagerPacket.ServerCommand)) {
                        this.lastFileManagerCommand[tcpSession] = backConnectFileManagerPacket.ServerCommand;
                        parms.Add("File Manager Command", backConnectFileManagerPacket.ServerCommand);
                        if (!string.IsNullOrEmpty(backConnectFileManagerPacket.CommandArgument)) {
                            parms.Add(backConnectFileManagerPacket.ServerCommand, backConnectFileManagerPacket.CommandArgument);
                            if (backConnectFileManagerPacket.ServerCommand == "PUT") {
                                this.putFilename[tcpSession] = backConnectFileManagerPacket.CommandArgument;
                            }
                        }
                    }
                }
                if (parms.Count > 0)
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(backConnectFileManagerPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, backConnectFileManagerPacket.ParentFrame.Timestamp, "BackConnect File Manager"));
                return parsedBytes;
            }
            else if (backConnectReverseShellPacket != null) {
                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                int parsedBytes = backConnectReverseShellPacket.PacketLength;
                if(!string.IsNullOrEmpty(backConnectReverseShellPacket.CommandOrResponse)) {
                    if (transferIsClientToServer)
                        parms.Add("Shell response", backConnectReverseShellPacket.CommandOrResponse);
                    else
                        parms.Add("Shell command", backConnectReverseShellPacket.CommandOrResponse);
                }
                if (parms.Count > 0)
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(backConnectReverseShellPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, backConnectReverseShellPacket.ParentFrame.Timestamp, "BackConnect Reverse Shell"));
                return parsedBytes;
            }
            return 0;
        }

        public override void Reset() {
            this.lastFileManagerCommand.Clear();
            this.putFilename.Clear();
        }
    }
}
