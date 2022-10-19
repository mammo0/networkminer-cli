using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class LpdPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //rfc1179 : A new connection must be made for each command to be given to the daemon.
        private PopularityList<NetworkTcpSession, (Packets.LpdPacket.LpdRequestPacket.DaemonCommandCode command, LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode? subCommand, string[] operands, string filename)> sessionCommandCodeList;
        private System.Text.RegularExpressions.Regex controlOrDataFileHostnameRegex;//"dfA" or "cfA" + [three digit job number] + [hostname]

        public LpdPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.sessionCommandCodeList = new PopularityList<NetworkTcpSession, (LpdPacket.LpdRequestPacket.DaemonCommandCode command, LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode? subCommand, string[] operands, string)>(100);
            this.controlOrDataFileHostnameRegex = new System.Text.RegularExpressions.Regex("^[cd]fA\\d{3}([\\w\\.\\-]+)$");
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Lpd;
            }
        }

        public override Type ParsedType {
            get {
                return typeof(Packets.LpdPacket);
            }
        }
        public override bool CanParse(HashSet<Type> packetTypeSet) {
            return packetTypeSet.Contains(this.ParsedType)
                || packetTypeSet.Contains(typeof(LpdPacket.LpdRequestPacket))
                || packetTypeSet.Contains(typeof(LpdPacket.LpdResponsePacket))
                || packetTypeSet.Contains(typeof(LpdPacket.LpdControlFilePacket));
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {

            if (transferIsClientToServer) {
                if (this.sessionCommandCodeList.ContainsKey(tcpSession)) {
                    var (lastCommand, lastSubCommand, lastOperands, lastFilename) = this.sessionCommandCodeList[tcpSession];

                    if (lastCommand == LpdPacket.LpdRequestPacket.DaemonCommandCode.ReceiveJob) {
                        if (lastSubCommand == null) {
                            //new sub command
                            if (packetList.Where(p => p is LpdPacket.LpdRequestPacket).FirstOrDefault() is LpdPacket.LpdRequestPacket request) {
                                if (request.TryGetSubCommand(out var newSubCommand)) {
                                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                                    parameters.Add("subcommand", Enum.GetName(typeof(LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode), newSubCommand));
                                    if (newSubCommand == LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode.ReceiveDataFile) {
                                        if (!Int32.TryParse(request.Operands[0], out int dataFileLength))
                                            dataFileLength = -1;
                                        parameters.Add("length", request.Operands[0]);
                                        string filename = request.Operands[1];
                                        parameters.Add("filename", filename);
                                        foreach (System.Text.RegularExpressions.Match match in this.controlOrDataFileHostnameRegex.Matches(filename)) {
                                            tcpSession.ClientHost.AddHostName(match.Groups[1].Value, request.PacketTypeDescription);
                                        }
                                        FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.LPD, filename + ".prn", "", "", request.ParentFrame.FrameNumber, request.ParentFrame.Timestamp, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination) {
                                            FileContentLength = dataFileLength,
                                            FileSegmentRemainingBytes = dataFileLength
                                        };
                                        if(!string.IsNullOrEmpty(lastFilename)) {
                                            if (lastFilename.EndsWith(".prn", StringComparison.InvariantCultureIgnoreCase))
                                                assembler.Filename = lastFilename;
                                            else
                                                assembler.Filename = lastFilename + ".prn";
                                        }
                                        base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                        assembler.TryActivate();
                                    }
                                    else if (newSubCommand == LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode.ReceiveControlFile) {
                                        foreach (System.Text.RegularExpressions.Match match in this.controlOrDataFileHostnameRegex.Matches(request.Operands[1])) {
                                            tcpSession.ClientHost.AddHostName(match.Groups[1].Value, request.PacketTypeDescription);
                                        }
                                        if (request.Operands.Length > 1) {
                                            parameters.Add("length", request.Operands[0]);
                                            parameters.Add("filename", request.Operands[1]);
                                        }
                                    }
                                    if (parameters.Count > 0) {
                                        Events.ParametersEventArgs p = new Events.ParametersEventArgs(request.ParentFrame.FrameNumber, tcpSession.ClientHost, tcpSession.ServerHost, tcpSession.Flow.FiveTuple.Transport, tcpSession.Flow.FiveTuple.ClientPort, tcpSession.Flow.FiveTuple.ServerPort, parameters, request.ParentFrame.Timestamp, "LPD");
                                        this.MainPacketHandler.OnParametersDetected(p);
                                    }
                                    this.sessionCommandCodeList[tcpSession] = (lastCommand, newSubCommand, request.Operands, null);
                                    return request.ParsedBytesCount;
                                }
                                
                            }
                        }
                        else if (lastSubCommand == LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode.ReceiveControlFile) {
                            if (packetList.Where(p => p is LpdPacket.LpdControlFilePacket).FirstOrDefault() is LpdPacket.LpdControlFilePacket controlFile) {
                                int controlFileLength = Int32.Parse(lastOperands[0]);
                                //assuming the control file fits in one TCP packet
                                if (controlFile.PacketLength == controlFileLength + 1) {

                                    this.sessionCommandCodeList[tcpSession] = (lastCommand, null, new string[0], lastFilename);

                                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                                    foreach(var (cmd, arg) in controlFile.CommandList) {
                                        parameters.Add(Enum.GetName(cmd.GetType(), cmd), arg);
                                        if(cmd == LpdPacket.LpdControlFilePacket.Command.UserID) {
                                            //tcpSession.ClientHost.AddNumberedExtraDetail("Username", arg);
                                            this.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "LPD", arg, "N/A", controlFile.ParentFrame.Timestamp));
                                        }
                                        else if(cmd == LpdPacket.LpdControlFilePacket.Command.Host) {
                                            tcpSession.ClientHost.AddHostName(arg, controlFile.PacketTypeDescription);
                                        }
                                        else if(cmd == LpdPacket.LpdControlFilePacket.Command.NameOfSourceFile) {
                                            this.sessionCommandCodeList[tcpSession] = (lastCommand, null, new string[0], arg);
                                        }
                                        foreach(System.Text.RegularExpressions.Match match in this.controlOrDataFileHostnameRegex.Matches(arg)) {
                                            tcpSession.ClientHost.AddHostName(match.Groups[1].Value, controlFile.PacketTypeDescription);
                                        }
                                    }
                                    if (parameters.Count > 0) {
                                        Events.ParametersEventArgs p = new Events.ParametersEventArgs(controlFile.ParentFrame.FrameNumber, tcpSession.ClientHost, tcpSession.ServerHost, tcpSession.Flow.FiveTuple.Transport, tcpSession.Flow.FiveTuple.ClientPort, tcpSession.Flow.FiveTuple.ServerPort, parameters, controlFile.ParentFrame.Timestamp, "LPD Control File");
                                        this.MainPacketHandler.OnParametersDetected(p);
                                    }
                                    return controlFileLength + 1;
                                }
                            }
                        }
                        else if (lastSubCommand == LpdPacket.LpdRequestPacket.ReceiveJobSubcommandCode.ReceiveDataFile) {
                            //this data should be handled by the file stream assembler, then we come back here for the trailing zero
                            //rfc1179: Once all of the contents have
                            //been delivered, an octet of zero bits is sent as an indication that
                            //the file being sent is complete.
                            this.sessionCommandCodeList[tcpSession] = (lastCommand, null, new string[0], lastFilename);
                            return 1;
                        }
                    }
                    else {
                        
                    }
                }
                else if (packetList.Where(p => p is LpdPacket.LpdRequestPacket).FirstOrDefault() is LpdPacket.LpdRequestPacket request) {
                    //We have a new session
                    if (request.TryGetCommand(out var command)) {
                        //first command in a session
                        this.sessionCommandCodeList.Add(tcpSession, (command, null, new string[0], null));
                        System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                        parameters.Add("Command", Enum.GetName(typeof(LpdPacket.LpdRequestPacket.DaemonCommandCode), command) + " (" + ((byte)command).ToString("x2") + ")");
                        if (request.Operands.Length > 0)
                            parameters.Add("Queue", request.Operands[0]);
                        if(command == LpdPacket.LpdRequestPacket.DaemonCommandCode.SendQueueStateShort ||
                            command == LpdPacket.LpdRequestPacket.DaemonCommandCode.SendQueueStateLong) {
                            if (request.Operands.Length > 1)
                                parameters.Add("Job", request.Operands[1]);
                        }
                        else if(command == LpdPacket.LpdRequestPacket.DaemonCommandCode.RemoveJobs) {
                            if (request.Operands.Length > 1) {
                                parameters.Add("User", request.Operands[1]);
                            }
                            foreach (string job in request.Operands.Skip(2))
                                parameters.Add("Job", job);
                        }
                        Events.ParametersEventArgs p = new Events.ParametersEventArgs(request.ParentFrame.FrameNumber, tcpSession.ClientHost, tcpSession.ServerHost, tcpSession.Flow.FiveTuple.Transport, tcpSession.Flow.FiveTuple.ClientPort, tcpSession.Flow.FiveTuple.ServerPort, parameters, request.ParentFrame.Timestamp, "LPD");
                        this.MainPacketHandler.OnParametersDetected(p);
                        return request.ParsedBytesCount;
                    }
                }
            }
            else {
                //server to client
                if (packetList.Where(p => p is LpdPacket.LpdResponsePacket).FirstOrDefault() is LpdPacket.LpdResponsePacket response)
                    return response.ParsedBytesCount;
            }
            return 0;
        }

        public void Reset() {
            this.sessionCommandCodeList.Clear();
        }
    }
}
