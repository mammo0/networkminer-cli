﻿using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class ImapPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private PopularityList<NetworkTcpSession, (string tag, ImapPacket.ClientCommand command, string fullRequestOrResponseLine)> lastCommand;
        private PopularityList<NetworkTcpSession, (System.IO.MemoryStream emailStream, uint? messageSequenceNumber)> serverToClientEmailReassemblers, clientToServerEmailReassemblers;

        //private PopularityList<(NetworkTcpSession session, uint messageSequenceNumber), Mime.Email> sessionMessages;


        public override Type ParsedType { get { return typeof(Packets.ImapPacket); } }
        public override bool CanParse(HashSet<Type> packetTypeSet) {
            return true;//we might need to add non-parsed segments to an email
        }

        public ApplicationLayerProtocol HandledProtocol
        {
            get
            {
                return ApplicationLayerProtocol.Imap;
            }
        }

        public ImapPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.lastCommand = new PopularityList<NetworkTcpSession, (string tag, ImapPacket.ClientCommand command, string fullRequestOrResponseLine)>(100);
            //this.lastCommand = new PopularityList<NetworkTcpSession, ImapPacket.ClientCommand>(100);
            this.serverToClientEmailReassemblers = new PopularityList<NetworkTcpSession, (System.IO.MemoryStream emailStream, uint? messageSequenceNumber)>(100);
            this.clientToServerEmailReassemblers = new PopularityList<NetworkTcpSession, (System.IO.MemoryStream emailStream, uint? messageSequenceNumber)>(100);
            //this.sessionMessages = new PopularityList<(NetworkTcpSession session, uint messageSequenceNumber), Mime.Email>(1000);
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            Packets.ImapPacket imapPacket = null;
            Packets.TcpPacket tcpPacket = null;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.TcpPacket))
                    tcpPacket = (Packets.TcpPacket)p;
                else if (p.GetType() == typeof(Packets.ImapPacket))
                    imapPacket = (Packets.ImapPacket)p;
            }
            if (tcpPacket != null &&
                (tcpPacket.SourcePort == 220 || tcpPacket.SourcePort == 143) &&
                this.lastCommand.ContainsKey(tcpSession) &&
                (this.lastCommand[tcpSession].command == ImapPacket.ClientCommand.UID || this.lastCommand[tcpSession].command == ImapPacket.ClientCommand.FETCH) &&
                this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {

                return this.ExtractEmail(tcpSession, tcpPacket, tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount, tcpPacket.PayloadDataLength);
            }
            else if (tcpPacket != null && (tcpPacket.DestinationPort == 220 || tcpPacket.DestinationPort == 143) && this.lastCommand.ContainsKey(tcpSession) && this.lastCommand[tcpSession].command == ImapPacket.ClientCommand.APPEND && this.clientToServerEmailReassemblers.ContainsKey(tcpSession)) {
                return this.ExtractEmail(tcpSession, tcpPacket, tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount, tcpPacket.PayloadDataLength);
            }
            else if (tcpPacket != null && imapPacket != null) {
                if (imapPacket.ClientToServer) {
                    if (imapPacket.Command != null) {
                        if (lastCommand.ContainsKey(tcpSession))
                            lastCommand[tcpSession] = (imapPacket.Tag, imapPacket.Command.Value, imapPacket.FullRequestOrResponseLine);
                        else
                            lastCommand.Add(tcpSession, (imapPacket.Tag, imapPacket.Command.Value, imapPacket.FullRequestOrResponseLine));

                        if (imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            parameters.Add(imapPacket.Command.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Client Command"));
                        }

                        //remove any old email reassemblers since we have now received a new command
                        if (this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {
                            this.serverToClientEmailReassemblers[tcpSession].emailStream.Close();
                            this.serverToClientEmailReassemblers.Remove(tcpSession);//we will need to create a new reassembler
                        }

                        if (imapPacket.Command == ImapPacket.ClientCommand.APPEND) {
                            //an email is being uploaded to the server
                            if (imapPacket.BodyLength > 0) {
                                int emailBytes = this.ExtractEmail(tcpSession, tcpPacket, imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount, imapPacket.PacketLength - imapPacket.ParsedBytesCount, imapPacket.BodyLength, imapPacket.MessageSequenceNumber, true);
                                imapPacket.ParsedBytesCount += emailBytes;
                            }
                        }
                        else if (imapPacket.Command == ImapPacket.ClientCommand.LOGIN) {
                            string[] args = imapPacket.FullRequestOrResponseLine.Split(new char[] { ' ' });
                            char[] quoteChars = new char[] { '\'', '"' };
                            //a001 LOGIN SMITH SESAME
                            if (args.Length > 3) {
                                string username = args[2].Trim(quoteChars);
                                string password = args[3].Trim(quoteChars);
                                NetworkCredential cred = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "IMAP", username, password, imapPacket.ParentFrame.Timestamp);
                                //base.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                base.MainPacketHandler.AddCredential(cred);
                            }
                        }
                    }
                    else if (lastCommand.ContainsKey(tcpSession) && lastCommand[tcpSession].command == ImapPacket.ClientCommand.AUTHENTICATE) {
                        if (imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            string base64 = imapPacket.FullRequestOrResponseLine;
                            NetworkCredential cred = SmtpPacketHandler.ExtractBase64EncodedAuthPlainCredential(base64, imapPacket.ParentFrame, tcpSession, ApplicationLayerProtocol.Imap);
                            if (cred != null) {
                                //base.MainPacketHandler.OnCredentialDetected(new Events.CredentialEventArgs(cred));
                                base.MainPacketHandler.AddCredential(cred);

                                if (imapPacket.ParsedBytesCount == 0)
                                    imapPacket.ParsedBytesCount = base64.Length + 2;//add CRLF
                            }
                        }
                    }

                }
                else {//server to client
                    if (imapPacket.Result != null && imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                        System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                        parameters.Add(imapPacket.Result.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Server Response"));


                        if (lastCommand.ContainsKey(tcpSession)) {
                            //"<TAG> OK [READ-WRITE] <COMMAND> completed"
                            
                            string tag = lastCommand[tcpSession].tag;
                            if(imapPacket.FullRequestOrResponseLine.StartsWith(tag + " "))
                                this.lastCommand.Remove(tcpSession);

                            /*
                            string command = Enum.GetName(lastCommand[tcpSession].command.GetType(), lastCommand[tcpSession].command);
                            if (imapPacket.FullRequestOrResponseLine.EndsWith("OK " + command + " completed", StringComparison.InvariantCultureIgnoreCase)) {
                                this.lastCommand.Remove(tcpSession);
                            }
                            */
                        }
                    }

                    if (lastCommand.ContainsKey(tcpSession) && (lastCommand[tcpSession].command == ImapPacket.ClientCommand.FETCH || lastCommand[tcpSession].command == ImapPacket.ClientCommand.UID)) {
                        if (imapPacket.Command != null && imapPacket.FullRequestOrResponseLine != null && imapPacket.FullRequestOrResponseLine.Length > 0) {
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            parameters.Add(imapPacket.Command.Value.ToString(), imapPacket.FullRequestOrResponseLine);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(imapPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, imapPacket.ParentFrame.Timestamp, "IMAP Untagged Response"));
                        }
                        //the server might push an email here
                        if (imapPacket.BodyLength > 0) {
                            if (this.lastCommand[tcpSession].fullRequestOrResponseLine != null) {

                                string lastCommandLine = this.lastCommand[tcpSession].fullRequestOrResponseLine;

                                if (!lastCommandLine.Contains("BODY.PEEK") || imapPacket.FullRequestOrResponseLine.Contains("HEADER")) {
                                    int emailBytes = this.ExtractEmail(tcpSession, tcpPacket, imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount, imapPacket.PacketLength - imapPacket.ParsedBytesCount, imapPacket.BodyLength, imapPacket.MessageSequenceNumber, false);
                                    if (imapPacket.ParenthesesDiff > 0 && imapPacket.ParsedBytesCount + emailBytes < imapPacket.PacketLength) {
                                        //we might have a trailing line that closes the parenthesis, let's read that one too
                                        int index = imapPacket.PacketStartIndex + imapPacket.ParsedBytesCount + emailBytes;
                                        string trailingLine = Utils.ByteConverter.ReadLine(imapPacket.ParentFrame.Data, ref index);
                                        int trailingParenthesesDiff = trailingLine.Split('(').Length - trailingLine.Split(')').Length;
                                        if (imapPacket.ParenthesesDiff + trailingParenthesesDiff == 0)
                                            return index - imapPacket.PacketStartIndex;
                                        else
                                            return imapPacket.ParsedBytesCount + emailBytes;
                                    }
                                    else
                                        return imapPacket.ParsedBytesCount + emailBytes;
                                }
                                /*
                                else if(imapPacket.FullRequestOrResponseLine.Contains("BODY[TEXT]") && imapPacket.MessageSequenceNumber != null && imapPacket.BodyLength > 0) {
                                    //email body (ASCII?)
                                    var key = (tcpSession, imapPacket.MessageSequenceNumber.Value);
                                    lock (this.sessionMessages) {
                                        if (this.sessionMessages.ContainsKey(key)) {
                                            var email = this.sessionMessages[key];
                                            string messageId = email.MessageID;
                                            if (messageId == null && email.RootAttributes != null)
                                                messageId = Mime.Email.GetMessageId(email.RootAttributes);
                                        }
                                    }
                                }
                                else if(imapPacket.FullRequestOrResponseLine.Contains("BODY[2]")) {
                                    //HTML formated email, treat as attachment
                                }
                                */
                            }
                        }
                    }
                    else if (lastCommand.ContainsKey(tcpSession) && (lastCommand[tcpSession].command == ImapPacket.ClientCommand.STARTTLS)) {
                        if (imapPacket.Result == ImapPacket.ServerResult.OK) {
                            //1 OK Begin TLS negotiation now
                            //do the same protocol switch trick as in SocksPacketHandler
                            //tcpSession.ProtocolFinder = new TcpPortProtocolFinder(tcpSession.ClientHost, tcpSession.ServerHost, tcpSession.ClientTcpPort, tcpSession.ServerTcpPort, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, base.MainPacketHandler);
                            tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Ssl, false);
                        }
                    }
                }
                return imapPacket.ParsedBytesCount;
            }
            else
                return 0;
        }

        public void Reset() {
            this.lastCommand.Clear();
            this.serverToClientEmailReassemblers.Clear();
            this.clientToServerEmailReassemblers.Clear();
        }

        private int ExtractEmail(NetworkTcpSession tcpSession, TcpPacket tcpPacket, int emailStartIndex, int length, int totalLength = 0, uint? messageSequenceNumber = null, bool clientToServer = false) {
            SharedUtils.Logger.Log("Extracting IMAP email from " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            System.IO.MemoryStream reassembler;
            if (this.serverToClientEmailReassemblers.ContainsKey(tcpSession)) {
                (reassembler, messageSequenceNumber) = this.serverToClientEmailReassemblers[tcpSession];
                clientToServer = false;
            }
            else if (this.clientToServerEmailReassemblers.ContainsKey(tcpSession)) {
                (reassembler, messageSequenceNumber) = this.clientToServerEmailReassemblers[tcpSession];
                clientToServer = true;
            }
            else if (totalLength > 0) {
                //reassembler = new Utils.StreamReassembler(Pop3Packet.MULTILINE_RESPONSE_TERMINATOR, 2);//include the first 2 bytes of the terminator to get a CR-LF at the end of the extracted data
                reassembler = new System.IO.MemoryStream(totalLength);
                if (clientToServer)
                    this.clientToServerEmailReassemblers.Add(tcpSession, (reassembler, messageSequenceNumber));
                else
                    this.serverToClientEmailReassemblers.Add(tcpSession, (reassembler, messageSequenceNumber));
            }
            else
                return 0;

            if (reassembler.Capacity < reassembler.Position + length)
                length = (int)(reassembler.Capacity - reassembler.Position);

            reassembler.Write(tcpPacket.ParentFrame.Data, emailStartIndex, length);
            if(reassembler.Position == reassembler.Capacity) {
                FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation assemblyLocation;
                if (clientToServer) {
                    assemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination;
                    this.clientToServerEmailReassemblers.Remove(tcpSession);
                }
                else {
                    assemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source;
                    /*
                    //remove the last command since we don't wanna reassemble any more for this command
                    if (this.lastCommand.ContainsKey(tcpSession))
                        this.lastCommand.Remove(tcpSession);
                        */
                    this.serverToClientEmailReassemblers.Remove(tcpSession);
                }

                Mime.Email email = new Mime.Email(reassembler, base.MainPacketHandler, tcpPacket, clientToServer, tcpSession, ApplicationLayerProtocol.Imap, assemblyLocation);
                /*
                if(messageSequenceNumber.HasValue) {
                    string messageId = email.MessageID;
                    if (messageId == null && email.RootAttributes != null)
                        messageId = Mime.Email.GetMessageId(email.RootAttributes);
                    lock (this.sessionMessages) {
                        var key = (tcpSession, messageSequenceNumber.Value);
                        if (!this.sessionMessages.ContainsKey(key)) {
                            this.sessionMessages.Add(key, email);
                        }
                        else {
                            SharedUtils.Logger.Log("Multiple emails extracted with message sequence number " + messageSequenceNumber.Value + " in session " + tcpSession.GetFlowID(), SharedUtils.Logger.EventLogEntryType.Information);
                        }
                        //look for attachments and other MIME parts beloning to the same email
                        //assembler.FileReconstructed += MainPacketHandler.OnMessageAttachmentDetected;
                        //assembler.FileReconstructed += Assembler_FileReconstructed;
                    }
                }*/

                

            }
            return length;
        }
    }
}
