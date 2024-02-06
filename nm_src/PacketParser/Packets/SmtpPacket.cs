using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace PacketParser.Packets {
    class SmtpPacket : AbstractPacket {
        //http://tools.ietf.org/html/rfc821 SIMPLE MAIL TRANSFER PROTOCOL (1982)
        //http://tools.ietf.org/html/rfc1870 SMTP Service Extension for Message Size Declaration (1995)
        //http://tools.ietf.org/html/rfc5321 Simple Mail Transfer Protocol (2008)
        //http://tools.ietf.org/html/rfc2554 SMTP Service Extension for Authentication
        //http://www.fehcom.de/qmail/smtpauth.html

        

        /**
         * RFC 821
         * Simple Mail Transfer Protocol
         * 
         * The following are the SMTP commands:
         * HELO <SP> <domain> <CRLF>
         * MAIL <SP> FROM:<reverse-path> <CRLF>
         * RCPT <SP> TO:<forward-path> <CRLF>
         * DATA <CRLF>
         * RSET <CRLF>
         * SEND <SP> FROM:<reverse-path> <CRLF>
         * SOML <SP> FROM:<reverse-path> <CRLF>
         * SAML <SP> FROM:<reverse-path> <CRLF>
         * VRFY <SP> <string> <CRLF>
         * EXPN <SP> <string> <CRLF>
         * HELP [<SP> <string>] <CRLF>
         * NOOP <CRLF>
         * QUIT <CRLF>
         * TURN <CRLF>
         * 
         * ehlo           = "EHLO" SP ( Domain / address-literal ) CRLF
         */
        public enum ClientCommands {
            HELO,
            MAIL,
            RCPT,
            DATA,
            RSET,
            SEND,
            SOML,
            SAML,
            VRFY,
            EXPN,
            HELP,
            NOOP,
            QUIT,
            TURN,
            EHLO,
            AUTH,
            STARTTLS
        }

        private bool clientToServer;

        //private string requestCommand;
        //private string requestArgument;

        private List<KeyValuePair<string, string>> requestCommandAndArgumentList;//key=command, value=argument


        //private int replyCode;
        //private string replyArgument;
        private List<KeyValuePair<int, string>> replyList;


        internal bool ClientToServer { get { return this.clientToServer; } }//could also be named "IsRequest"
        internal IEnumerable<KeyValuePair<string, string>> RequestCommandsAndArguments { get { return this.requestCommandAndArgumentList; } }
        internal IEnumerable<KeyValuePair<int, string>> Replies { get { return this.replyList; } }
        internal System.Collections.Generic.List<int> ReplyCodes {
            get {
                System.Collections.Generic.List<int> replyCodes=new List<int>();
                foreach(KeyValuePair<int, string> codeAndArgument in this.Replies)
                    replyCodes.Add(codeAndArgument.Key);
                return replyCodes;
            }
        }
        
        internal static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, ushort sourcePort, out SmtpPacket smtpPacket) {
            if(clientToServer) {
                if (packetEndIndex - packetStartIndex > 80) {
                    int index = packetStartIndex;
                    string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                    if (line == null) {
                        smtpPacket = null;
                        return false;
                    }
                }
            }
            else {//server->client
                int index = packetStartIndex;
                string firstLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                string line = firstLine;
                while (!string.IsNullOrEmpty(line)) {
                    string lowerLine = line.ToLower();
                    if (lowerLine.Contains("smtp") || lowerLine.Contains("mail")) {
                        smtpPacket = new SmtpPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        return true;
                    }
                    else if (lowerLine.StartsWith("220") && lowerLine.Contains("ftp")) {
                        smtpPacket = null;
                        return false;//avoid parsing FTP as SMTP
                    }
                    line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                }
                
                if (firstLine?.StartsWith("220") == true && sourcePort == 21) {
                    smtpPacket = null;
                    return false;//avoid parsing FTP as SMTP
                }
            }
            //null terminated strings are not used in SMTP
            if (parentFrame.Data[packetEndIndex] == 0 && packetEndIndex - packetStartIndex >= 3) {
                //lets see if we have 7-bit ASCII of len 3 or more, terminated with null
                for (int i = packetStartIndex; i <= packetEndIndex; i++) {
                    if (parentFrame.Data[i] == 0) {
                        if (i >= 3) {
                            smtpPacket = null;
                            return false;
                        }
                        else
                            break;
                    }
                    else if (parentFrame.Data[i] < 0x20)
                        break;
                    else if (parentFrame.Data[i] > 0x7e)
                        break;
                }
            }
            smtpPacket = new SmtpPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
            return true;
        }


        private SmtpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SMTP") {

            this.clientToServer = clientToServer;
            this.requestCommandAndArgumentList = new List<KeyValuePair<string, string>>();
            this.replyList = new List<KeyValuePair<int, string>>();

            if(clientToServer) {
                int index= this.PacketStartIndex;

                while(index < packetEndIndex && this.requestCommandAndArgumentList.Count < 1000) {

                    string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);//RFC says use CR LF, but some clients only use LF
                    if (string.IsNullOrEmpty(line))
                        break;

                    string requestCommand = null;
                    string requestArgument = null;

                    if(line.Contains(" ")) {
                        requestCommand=line.Substring(0, line.IndexOf(' '));
                        if(line.Length>line.IndexOf(' ')+1) {
                            requestArgument=line.Substring(line.IndexOf(' ')+1);
                        }
                        else {
                            requestArgument="";
                        }
                    }
                    else if(line.Length == 4) {
                        requestCommand = line;
                        requestArgument = "";
                    }
                    else if(Enum.IsDefined(typeof(ClientCommands), line)) {
                        requestCommand = line;
                        requestArgument = "";
                    }

                    if(requestCommand != null) {
                        KeyValuePair<string, string> requestComandAndArgument = new KeyValuePair<string, string>(requestCommand, requestArgument);
                        this.requestCommandAndArgumentList.Add(requestComandAndArgument);
                    }
                    else
                        break;
                }

            }
            else {//server to client
                //Get the Reply Code
                int index=PacketStartIndex;
                while(index < packetEndIndex && this.replyList.Count < 1000) {
                    string replyArgument;
                    string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);//I'll only look in the first line
                    if (string.IsNullOrEmpty(line))
                        break;
                    else if (replyList.Count == 0 && line.StartsWith("220") && line.ToLower().Contains("ftp") && !line.ToLower().Contains("smtp") && !line.ToLower().Contains("mail"))
                        throw new Exception("Aborting attempt to parse FTP packet as SMTP");
                    string first3bytes=line.Substring(0, 3);
                    if(!Int32.TryParse(first3bytes, out int replyCode))
                        break;
                    else if(line.Length>4)
                        replyArgument=line.Substring(4);
                    else
                        replyArgument="";
                    this.replyList.Add(new KeyValuePair<int,string>(replyCode, replyArgument));
                }
            }
        }

        internal string ReadLine() {
            int index=PacketStartIndex;
            return Utils.ByteConverter.ReadLine(base.ParentFrame.Data, ref index);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
