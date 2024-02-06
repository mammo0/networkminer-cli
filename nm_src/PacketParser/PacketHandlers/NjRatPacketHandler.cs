using PacketParser.FileTransfer;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.ModelBinding;
using System.Web.UI.WebControls.WebParts;

namespace PacketParser.PacketHandlers {
    internal class NjRatPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        //There isn't any good publibly available protocol spec for njRAT, but here's some info:
        //https://github.com/csieteco/njRatActiveDefense/blob/master/njdetector.py
        //https://cybergeeks.tech/just-another-analysis-of-the-njrat-malware-a-step-by-step-approach/
        //https://faculty.cc.gatech.edu/~pearce/papers/rats_usenix_2018.pdf
        //Approach of an Active Defense Protocol to Deal with RAT Malware - A Colombian Case Study Against njRAT Campaigns (Quinterno et al)
        //Command Handler: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Modules/Class7.vb
        //File Manager?: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Forms/Manager.vb
        //Great analysis of the "old" protocol (no length fields) published in June 28, 2013!! https://web.archive.org/web/20180710040949/http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered-1.pdf
        //njRAT decoder for Zeek (Spicy) https://github.com/keithjjones/zeek-njrat-detector
        //Other delimiters: |kiler|
        //
        //https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ claims that njRAT 0.7NC with "@!#&^%$" splitter and "NYAN CAT" victim name is LimeRAT !?

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
        public override Type[] ParsedTypes { get; } = { typeof(NjRatPacket) };

        private PopularityList<IPEndPoint, C2ServerInfo> c2ServerInfo;
        

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.njRAT;
            }
        }

        public NjRatPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
            this.c2ServerInfo = new PopularityList<IPEndPoint, C2ServerInfo>(100);
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            NjRatPacket njRatPacket = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                Type pType = p.GetType();
                if (pType == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (pType == typeof(NjRatPacket))
                    njRatPacket = (NjRatPacket)p;
            }
            if (njRatPacket != null) {
                NameValueCollection parms = new NameValueCollection();
                int parsedBytes = njRatPacket.ParsedBytesCount;

                if (!string.IsNullOrEmpty(njRatPacket.CommandString)) {
                    if(transferIsClientToServer)
                        parms.Add("njRAT bot command", njRatPacket.CommandString);
                    else
                        parms.Add("njRAT server command", njRatPacket.CommandString);
                }
                IPEndPoint serverEndPoint = new IPEndPoint(tcpSession.ServerHost.IPAddress, tcpSession.ServerTcpPort);
                if (!this.c2ServerInfo.ContainsKey(serverEndPoint)) {
                    this.c2ServerInfo.Add(serverEndPoint, new C2ServerInfo(serverEndPoint));
                }
                C2ServerInfo c2ServerInfo = this.c2ServerInfo[serverEndPoint];
                c2ServerInfo.TryAddSplitterCandidate(njRatPacket.SplitterCandidate);

                string splitter = null;
                if (njRatPacket.MessageLength > 4000 && njRatPacket.ParsedBytesCount == 0) {
                    //reassemble data after last splitter to disk

                    string filename = "njRAT-UNKNOWN";
                    string fileDetails = "njRAT";
                    if (!string.IsNullOrEmpty(njRatPacket.CommandString)) {
                        filename = "njRAT-" + njRatPacket.CommandString;
                        //fileDetails += " " + njRatPacket.CommandString;
                    }

                    splitter = c2ServerInfo.GetLikelySplitter();
                    byte[] splitterBytes = Encoding.ASCII.GetBytes(splitter);
                    int lastDataFieldOffset = Utils.BoyerMoore.LastIndexOf(njRatPacket.ParentFrame.Data, splitterBytes, njRatPacket.MessageStartIndex) + splitterBytes.Length;

                    
                    if (lastDataFieldOffset > 0 && !string.IsNullOrEmpty(splitter)) {
                        try {
                            string s = ASCIIEncoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.MessageStartIndex, lastDataFieldOffset - njRatPacket.MessageStartIndex);
                            string[] sa = s.Split(new string[] { splitter }, StringSplitOptions.RemoveEmptyEntries);
                            foreach(string p in sa) {
                                if (p.Length < 20)
                                    fileDetails += " " + p;
                            }
                        }
                        catch { }
                    }
                    int fileSize = njRatPacket.MessageStartIndex + njRatPacket.MessageLength - lastDataFieldOffset;
                    if (fileSize > 1) {
                        FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                        if (assembler.TryActivate()) {
                            base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                            assembler.FileContentLength = fileSize;
                            assembler.FileSegmentRemainingBytes = fileSize;
                            assembler.AddData(njRatPacket.ParentFrame.Data.Skip(lastDataFieldOffset).ToArray(), tcpPacket.SequenceNumber);
                            if (njRatPacket.PacketLength > parsedBytes)
                                parsedBytes = njRatPacket.PacketLength;
                        }
                    }
                }
                else if (C2Message.TryParse(njRatPacket, transferIsClientToServer, c2ServerInfo, out C2Message c2Message)) {
                    splitter = c2Message.SplitterCandidate;
                    foreach ((string name, string value) in c2Message.KnownFields) {
                        parms.Add(name, value);
                        if (name == C2Message.HOSTNAME)
                            tcpSession.ClientHost.AddHostName(value, "njRAT");
                        else if (name == C2Message.OS)
                            tcpSession.ClientHost.AddNumberedExtraDetail(name, value);
                        else if (name == C2Message.USER)
                            tcpSession.ClientHost.AddNumberedExtraDetail(name, value);
                        else if (name == C2Message.BOTNET_BOTID) {
                            tcpSession.ClientHost.AddNumberedExtraDetail("njRAT bot ID", value);
                            if (value.Contains('_'))
                                tcpSession.ServerHost.AddNumberedExtraDetail("njRAT botnet", value.Split('_').First());
                        }
                        else if(name == C2Message.VERSION)
                            tcpSession.ServerHost.AddNumberedExtraDetail("njRAT version", value);
                        else if (name == C2Message.INSTALL_DATE)
                            tcpSession.ClientHost.AddNumberedExtraDetail("njRAT install date", value);
                    }
                    foreach((string username, string password, string site) in c2Message.Credentials) {
                        NetworkCredential networkCredential = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, site, username, password, njRatPacket.ParentFrame.Timestamp);
                        base.MainPacketHandler.AddCredential(networkCredential);
                    }

                    if (c2Message.MessageTypeBot == C2Message.BotMessageType.post) {
                        string filename = c2Message.KnownFields.Where(f => f.name == C2Message.FILENAME)?.First().value;
                        string lengthString = c2Message.KnownFields.Where(f => f.name == C2Message.SIZE)?.First().value;
                        if (!string.IsNullOrEmpty(filename) && !string.IsNullOrEmpty(lengthString) && Int32.TryParse(lengthString, out int fileSize)) {
                            if (fileSize > 1) {
                                string fileDetails = "njRAT post " + filename;
                                FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);

                                if (assembler.TryActivate()) {
                                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                }
                            }
                        }
                    }
                    else if (c2Message.MessageTypeBot == C2Message.BotMessageType.get) {
                        string filename = c2Message.KnownFields.Where(f => f.name == C2Message.FILENAME)?.First().value;
                        //string ipColonPort = c2Message.KnownFields.Where(f => f.name == C2Message.IP_COLON_PORT)?.First().value;
                        if (c2ServerInfo.requestedFileSizes.ContainsKey(filename)) {
                            int fileSize = c2ServerInfo.requestedFileSizes[filename];
                            if (!string.IsNullOrEmpty(filename) && fileSize > 1) {
                                string fileDetails = "njRAT get " + filename;
                                FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, !transferIsClientToServer, FileStreamTypes.njRAT, filename, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);

                                if (assembler.TryActivate()) {
                                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                }
                            }
                        }
                    }
                    else if (c2Message.MessageTypeBot == C2Message.BotMessageType.kl) {
                        //KeyLog data
                        string fileDetails = "njRAT";
                        if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                            fileDetails += " " + njRatPacket.CommandString;

                        byte[] splitterBytes = Encoding.ASCII.GetBytes(splitter);
                        int lastDataFieldOffset = Utils.BoyerMoore.LastIndexOf(njRatPacket.ParentFrame.Data, splitterBytes, njRatPacket.MessageStartIndex) + splitterBytes.Length;

                        if (lastDataFieldOffset > 0 && !string.IsNullOrEmpty(splitter)) {
                            
                            int fileSize = njRatPacket.MessageStartIndex + njRatPacket.MessageLength - lastDataFieldOffset;
                            if (fileSize > 1) {
                                FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, "njRAT-" + njRatPacket.CommandString + ".keylog", "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                                assembler.ContentEncoding = HttpPacket.ContentEncodings.Base64;
                            
                                if (assembler.TryActivate()) {
                                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                    assembler.FileContentLength = fileSize;
                                    assembler.FileSegmentRemainingBytes = fileSize;
                                    assembler.AddData(njRatPacket.ParentFrame.Data.Skip(lastDataFieldOffset).ToArray(), tcpPacket.SequenceNumber);
                                    if (njRatPacket.PacketLength > parsedBytes)
                                        parsedBytes = njRatPacket.PacketLength;
                                }
                            }
                        }
                    }
                    else if (c2Message.RawFieldData?.Length > 0 && c2Message.RawFieldDataTotalLength > 1) {
                        //write raw data to disk
                        
                        string fileDetails = "njRAT";
                        if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                            fileDetails += " " + njRatPacket.CommandString;
                        fileDetails += string.Join(" ", c2Message.KnownFields.Where(f => f.value.Length < 20).Select(f => f.value));
                        FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.njRAT, "njRAT-" + njRatPacket.CommandString, "/", fileDetails, njRatPacket.ParentFrame.FrameNumber, njRatPacket.ParentFrame.Timestamp);
                        if (assembler.TryActivate()) {
                            base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                            assembler.FileContentLength = c2Message.RawFieldDataTotalLength;
                            assembler.FileSegmentRemainingBytes = c2Message.RawFieldDataTotalLength;
                            assembler.AddData(c2Message.RawFieldData, tcpPacket.SequenceNumber);
                            if(njRatPacket.PacketLength > parsedBytes)
                                parsedBytes = njRatPacket.PacketLength;
                        }
                        
                    }
                }

                if(!string.IsNullOrEmpty(splitter)) {
                    tcpSession.ServerHost.AddNumberedExtraDetail("njRAT splitter", splitter);
                }
                

                if (parms.Count > 0) {
                    NetworkHost sourceHost, destinationHost;
                    ushort sourcePort, destinationPort;
                    if (transferIsClientToServer) {
                        sourceHost = tcpSession.ClientHost;
                        sourcePort = tcpSession.ClientTcpPort;
                        destinationHost = tcpSession.ServerHost;
                        destinationPort = tcpSession.ServerTcpPort;
                    }
                    else {
                        sourceHost = tcpSession.ServerHost;
                        sourcePort = tcpSession.ServerTcpPort;
                        destinationHost = tcpSession.ClientHost;
                        destinationPort = tcpSession.ClientTcpPort;
                    }

                    string details = "njRAT";
                    if (!string.IsNullOrEmpty(njRatPacket.CommandString))
                        details += " " + njRatPacket.CommandString;
                    Events.ParametersEventArgs parametersEA = new Events.ParametersEventArgs(njRatPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parms, njRatPacket.ParentFrame.Timestamp, details);
                    base.MainPacketHandler.OnParametersDetected(parametersEA);
                }
                return parsedBytes;
            }
            else
                return 0;
        }

        public void Reset() {
            this.c2ServerInfo.Clear();
        }

        internal class C2Message {

            private enum FieldEncoding {
                plaintext,
                base64,
                raw
            }
            private enum Tools {
                rs,//Reverse Shell
                rsc,//kill reverse shell
                proc,//Process List
                tcp,//TCP connectino request
                srv,//Services request
                fm//File Manager
            }

            private enum ProcActions {
                //'~' (tilde) => retrieve information about the current process and the other running processes
                //'!'
                k, //kill process
                kd,//kill and delete files
                re,//restart process
                rss,//run shell session
            }

            private enum FileManagerActions {
                dw,//Download
                up,//Upload
                cp,//Copy
                rn,//Run
                fl,//Run From Link
                rd//Read? Read and Delete?
            }

            internal enum BotMessageType {
                ll,//Victim checkin. Can be any of: lv, llv, lvv or ll
                li,//alternativ to ll with base64 encoded hostnames and usernames
                act,//active window
                inf,//Get volume serial, C2 server, process name etc.
                infn,//Get volume serial, C2 server, process name etc.
                CAP,//followed by [delimiter][JPEG]
                pl,
                PLG,
                sc_tilde,
                scPK,//delivers screenshot
                CH,//chat message
                FM,//File Manager
                rs,//Reverse Shell
                fun,
                sitel,
                WT,
                INS,//installed software
                STP,//list startup/autorun keys in registry
                proc,//process info
                srv,//service info
                tcp,//netstat info
                post,//file/data sent to C2 server
                get,//file downloaded from C2 server
                ret,//send credentials to C2 server
                kl,//keylogger
            }

            internal static readonly Dictionary<string,BotMessageType> BotMsgDict = new Dictionary<string, BotMessageType> {
                { "lv", BotMessageType.ll },//Victim checkin
                { "llv", BotMessageType.ll },//Victim checkin (alternative)
                { "lvv", BotMessageType.ll },//Victim checkin (alternative #2)
                { "ll", BotMessageType.ll },//Victim checkin (alternative #3), typically <LEN><NULL>ll
                { "li", BotMessageType.li },//Victim checkin (alternative #4)
                { "act", BotMessageType.act },//active window
                { "inf", BotMessageType.inf },//Get volume serial, C2 server, process name etc.
                { "infn", BotMessageType.infn },//Get volume serial, C2 server, process name etc.
                { "CAP", BotMessageType.CAP },//followed by [delimiter][JPEG]
                { "pl", BotMessageType.pl },
                { "PLG", BotMessageType.PLG },
                { "sc~", BotMessageType.sc_tilde },//shows screen resolution
                { "scPK", BotMessageType.scPK },//Screen shot
                { "CH", BotMessageType.CH },//chat message
                { "FM", BotMessageType.FM },//File Manger
                { "rs", BotMessageType.rs },//output from Reverse Shell
                { "fun", BotMessageType.fun },
                { "site", BotMessageType.sitel },
                { "WT", BotMessageType.WT },
                { "INS", BotMessageType.INS },//installed software
                { "STP", BotMessageType.STP },//list startup/autorun keys in registry
                { "proc", BotMessageType.proc },//process info
                { "srv", BotMessageType.srv },//process info
                { "tcp", BotMessageType.tcp },//netstat info
                { "post", BotMessageType.post },//file sent to C2 server
                { "get", BotMessageType.get },//file downloaded from C2 server
                { "ret", BotMessageType.ret },//retrieve credentials
                { "kl", BotMessageType.kl }//keylogger
            };

            internal const string HOSTNAME = "Hostname";
            internal const string BOTNET_BOTID = "Botnet_BotID";
            internal const string OS = "OS";
            internal const string USER = "User";
            internal const string VERSION = "Version";
            internal const string FOREGROUND_WINDOW = "Foreground Window";//Retrieved through call to GetForegroundWindow()
            internal const string INSTALL_DATE = "Install Date";
            internal const string FILENAME = "Filename";//used in post
            internal const string SIZE = "Size";//used in post
            internal const string IP_COLON_PORT = "IP:port";
            internal const string CREDENTIALS = "Credentials";

            /**
             * ll|'|'|SGFjS2VkX0M0QkEzNjQ3|'|'|USER-PC|'|'|admin|'|'|21-05-19|'|'||'|'|Win 7 Professional SP1 x86|'|'|No|'|'|im523|'|'|..|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==|'|'|
             * inf|'|'|SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
            */
            private static readonly Dictionary<BotMessageType,(string name, FieldEncoding encoding)[]> BotMessageFieldInfo = new Dictionary<BotMessageType, (string name, FieldEncoding encoding)[]> {
                {
                    BotMessageType.ll, new[] {
                        (BOTNET_BOTID, FieldEncoding.base64),
                        (HOSTNAME, FieldEncoding.plaintext),
                        (USER, FieldEncoding.plaintext),
                        (INSTALL_DATE, FieldEncoding.plaintext),
                        ("Flag", FieldEncoding.plaintext),//""
                        (OS, FieldEncoding.plaintext),
                        ("Camera", FieldEncoding.plaintext),//No
                        (VERSION, FieldEncoding.plaintext),//im523 or 0.7NC
                        ("?", FieldEncoding.plaintext),//..
                        (FOREGROUND_WINDOW, FieldEncoding.base64),
                        ("?", FieldEncoding.plaintext)//"" (empty)
                    }
                },
                {
                    BotMessageType.li, new[] {
                        (BOTNET_BOTID, FieldEncoding.base64),
                        (HOSTNAME, FieldEncoding.base64),
                        (USER, FieldEncoding.base64),
                        (INSTALL_DATE, FieldEncoding.plaintext),
                        ("Flag", FieldEncoding.plaintext),//""
                        (OS, FieldEncoding.plaintext),
                        ("Camera", FieldEncoding.plaintext),//No
                        (VERSION, FieldEncoding.plaintext),//im523 or 0.7NC
                        ("?", FieldEncoding.plaintext),//..
                        (FOREGROUND_WINDOW, FieldEncoding.base64),
                        ("?", FieldEncoding.plaintext)//"" (empty)
                    }
                },
                {
                    BotMessageType.act, new[] {
                        (FOREGROUND_WINDOW, FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.inf, new[] {
                        ("Info Multiline", FieldEncoding.base64)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    BotMessageType.infn, new[] {
                        ("Info CSV", FieldEncoding.base64)//bG9ncyxsb2dzN3dhLmRkbnMubmV0OjExNzcsQWxsVXNlcnNQcm9maWxlLGR3bS5leGUsVHJ1ZSxUcnVlLFRydWUsVHJ1ZSxUcnVlLFRydWUs
                    }
                },
                {
                    BotMessageType.CAP, new[] {
                        ("Screenshot", FieldEncoding.raw)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    //45.pl|'|'|2681e81bb4c4b3e6338ce2a456fb93a7|'|'|0
                    BotMessageType.pl, new[] {
                        ("?", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.sc_tilde, new[] {
                        ("IP:port", FieldEncoding.plaintext),
                        ("width", FieldEncoding.plaintext),
                        ("height", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.scPK, new[] {
                        ("IP:port", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext),
                        ("Screenshot", FieldEncoding.raw)
                    }
                },
                {
                    //CH|'|'|46.244.28.106:49374|'|'|!
                    //CH|'|'|46.244.28.106:49374|'|'|@|'|'|eW91IGdleQ==
                    BotMessageType.CH, new[] {
                        (IP_COLON_PORT, FieldEncoding.plaintext),
                        ("Type", FieldEncoding.plaintext)//'~', '!' or '@'
                        //("Message", FieldEncoding.base64)//when Type is @
                    }
                },
                {
                    BotMessageType.PLG, new (string name, FieldEncoding encoding)[0]
                },
                {
                    BotMessageType.rs, new[] {
                        ("Reverse Shell", FieldEncoding.base64)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    BotMessageType.WT, new[] {
                        ("?", FieldEncoding.plaintext),//!
                        ("WT", FieldEncoding.base64),
                        ("nr", FieldEncoding.plaintext)//9912
                    }
                },
                {
                    BotMessageType.INS, new[] {
                        ("Installed", FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.STP, new[] {
                        ("?", FieldEncoding.plaintext),//!
                        ("Autorun keys", FieldEncoding.base64),
                        ("?", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.proc, new[] {
                        ("Type", FieldEncoding.plaintext),//!
                        ("Process Info", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.srv, new[] {
                        ("Type", FieldEncoding.plaintext),//!
                        ("Service Info", FieldEncoding.plaintext)
                    }
                }
                ,
                {
                    BotMessageType.tcp, new[] {
                        ("Type", FieldEncoding.plaintext),//~
                        ("Netstat Info", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.post, new[] {
                        (FILENAME, FieldEncoding.base64),
                        (SIZE, FieldEncoding.plaintext),
                        (IP_COLON_PORT, FieldEncoding.plaintext)
                    }
                }
                ,
                {
                    BotMessageType.get, new[] {
                        (IP_COLON_PORT, FieldEncoding.plaintext),
                        (FILENAME, FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.kl, new[] {
                        ("KeyLog Data", FieldEncoding.base64)
                    }
                }
                /*
                ,
                {
                    BotMessageType.ret, new[] {
                        ("ID", FieldEncoding.plaintext),
                        (CREDENTIALS, FieldEncoding.base64)
                    }
                }
                */
            };

            
            internal enum ServerMessageType {
                CAP,
                Ex,
                inv,
                kl,
                MIC,
                MSG,
                P,
                PLG,
                proc,
                ret,
                rn,
                ErorrMsg,
                OpenSite
            }

            internal static readonly Dictionary<string, ServerMessageType?> ServerMsgDict = new Dictionary<string, ServerMessageType?> {
                { "~", null },
                { "!", null },
                { "act", null },
                { "bla", null },
                { "CAM", null },
                { "CAP", ServerMessageType.CAP },//Screen Capture
                { "CH", null },
                { "ER", null },
                { "Ex", ServerMessageType.Ex },//Execute Tool
                { "FM", null },
                { "fun", null },
                { "get", null },
                { "inf", null },//Get volume serial, C2 server, process name etc.
                
                { "inv", ServerMessageType.inv },//?? invoke module
                { "kla", null },
                { "kl", ServerMessageType.kl },//Get Key Logger data
                { "ll", null },
                { "lv", null },
                { "MIC", ServerMessageType.MIC },
                { "MSG", ServerMessageType.MSG },
                { "pl", null },
                { "PLG", ServerMessageType.PLG },
                { "post", null },
                { "post+", null },
                { "P", ServerMessageType.P },//PING or just an empty message if length fields are used
                { "proc", ServerMessageType.proc },
                { "prof", null },//?? Create registry key
                { "ret", ServerMessageType.ret },//Get Passwords (runs assembly pw.dll?)
                { "RG", null },//Reads, writes or deletes registry keys
                { "rn", ServerMessageType.rn },//Run command
                { "rs", null },
                { "rsc", null },
                { "rss", null },
                { "sc~", null },
                { "scPK", null },
                { "site", null },
                { "srv", null },
                { "tcp", null },
                { "un", null },//Uninstall, kill or restart njRAT"
                { "up", null },//?? Update njRAT from URL or archive data
                { "ErorrMsg", ServerMessageType.ErorrMsg },
                { "OpenSite", ServerMessageType.OpenSite },
            };

            private static readonly Dictionary<ServerMessageType, (string name, FieldEncoding encoding)[]> ServerMessageFieldInfo = new Dictionary<ServerMessageType, (string name, FieldEncoding encoding)[]> {
                {
                    //“inv|’|’|<RegistryValue>|’|’|<String1>|’|’|<String2>” command – njRAT has plugins that can be downloaded, saved in registry keys, and then executed
                    ServerMessageType.inv, new[] {
                        ("RegistryValue", FieldEncoding.plaintext),
                        ("param1", FieldEncoding.plaintext),
                        ("param2", FieldEncoding.raw)
                    }
                },
                {
                    //17.CAP|'|'|35|'|'|23
                    ServerMessageType.CAP, new[] {
                        ("width", FieldEncoding.plaintext),
                        ("height", FieldEncoding.plaintext)
                    }
                },
                {
                    ServerMessageType.PLG, new[] {
                        ("file", FieldEncoding.raw),
                    }
                }
                ,
                {
                    ServerMessageType.ErorrMsg, new[] {
                        ("?", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext),
                        ("Message", FieldEncoding.plaintext)
                    }
                },
                {
                    ServerMessageType.OpenSite, new[] {
                        ("URL", FieldEncoding.plaintext)
                    }
                }
            };

            //internal List<string> DecodedFieldValues { get; }
            internal List<(string name, string value)> KnownFields { get; }
            internal List<(string username, string password, string site)> Credentials { get; }
            internal string SplitterCandidate { get; private set; }
            internal ServerMessageType? MessageTypeServer { get; }
            internal BotMessageType? MessageTypeBot { get; }

            internal byte[] RawFieldData { get; private set; } = null;
            internal int RawFieldDataTotalLength = 0;

            private C2ServerInfo c2ServerInfo;

            internal static bool TryParse(NjRatPacket njRatPacket, bool clientToServer, C2ServerInfo c2ServerInfo, out C2Message c2Message) {
                
                if(!string.IsNullOrEmpty(njRatPacket.CommandString)) {
                    if(clientToServer) {
                        if (BotMsgDict.ContainsKey(njRatPacket.CommandString)) {
                            c2Message = new C2Message(njRatPacket, BotMsgDict[njRatPacket.CommandString], c2ServerInfo);
                            return true;
      
                        }
                        /*
#if DEBUG
                        else
                            Debugger.Break();//unknown command!
#endif
                        */
                        
                    }
                    else {//server -> client
                        if (ServerMsgDict.ContainsKey(njRatPacket.CommandString)) {
                            ServerMessageType? msgOrNull = ServerMsgDict[njRatPacket.CommandString];
                            if (msgOrNull != null) {
                                c2Message = new C2Message(njRatPacket, msgOrNull.Value, c2ServerInfo);
                                return true;
                            }
                            
                        }
                        /*
#if DEBUG
                        else
                            Debugger.Break();//unknown command!
#endif
                        */
                    }
                }
                c2Message = null;
                return false;
            }


            //client->server
            internal C2Message(NjRatPacket njRatPacket, BotMessageType messageTypeBot, C2ServerInfo c2ServerInfo) : this(c2ServerInfo) {
                this.MessageTypeBot = messageTypeBot;
                this.MessageTypeServer = null;

                if (BotMessageFieldInfo.ContainsKey(messageTypeBot)) {
                    (string name, FieldEncoding encoding)[] fieldInfo = BotMessageFieldInfo[messageTypeBot];
                    this.ParseFields(njRatPacket, fieldInfo);
                }
                else if (messageTypeBot == BotMessageType.ret) {
                    //retrieve credentials
                    string[] retArgs = this.GetFields(njRatPacket).ToArray();
                    if (retArgs.Length >= 2) {
                        char[] credentialSeparators = new char[] { ' ', '*', '\n', '\r' };
                        if (Utils.StringManglerUtil.TryReadFromBase64(retArgs[1], out string credentials)) {
                            string[] creds = credentials.Split(credentialSeparators).Where(c => c.Trim().Length > 0).ToArray();
                            for(int i  = 0; i < creds.Length; i++) { 
                                if (creds[i].Contains(':')) {
                                    string[] credParts = creds[i].Split(':');
                                    if (credParts.Length == 3) {
                                        string credNumber = " " + (i + 1);
                                        if (Utils.StringManglerUtil.TryReadFromBase64(credParts[0], out string site))
                                            this.KnownFields.Add(("Site" + credNumber, site));
                                        if (Utils.StringManglerUtil.TryReadFromBase64(credParts[1], out string user)) {
                                            this.KnownFields.Add((USER + credNumber, user));
                                            if (Utils.StringManglerUtil.TryReadFromBase64(credParts[2], out string pass)) {
                                                this.KnownFields.Add(("Password" + credNumber, pass));
                                                this.Credentials.Add((user, pass, site));
                                            }
                                        }
                                        else
                                            this.KnownFields.Add((USER + credNumber, credParts[0]));
                                    }

                                }
                                else
                                    this.KnownFields.Add(("Credential " + (i+1), creds[i]));
                            }
                        }
                    }
                }
            }

            //server->client
            internal C2Message(NjRatPacket njRatPacket, ServerMessageType messageTypeServer, C2ServerInfo c2ServerInfo) : this(c2ServerInfo) {
                this.MessageTypeBot = null;
                this.MessageTypeServer = messageTypeServer;

                if (ServerMessageFieldInfo.ContainsKey(messageTypeServer)) {
                    (string name, FieldEncoding encoding)[] fieldInfo = ServerMessageFieldInfo[messageTypeServer];
                    this.ParseFields(njRatPacket, fieldInfo);
                }
                else if(messageTypeServer == ServerMessageType.Ex) {
                    string[] exArgs = this.GetFields(njRatPacket).ToArray();
                    if (exArgs.Length > 0 && Enum.TryParse(exArgs[0], out Tools tool)) {
                        this.KnownFields.Add(("Ex Tool", exArgs[0]));
                        if (tool == Tools.rs) {
                            if (exArgs.Length == 3 && exArgs[1] == "!") {
                                //base64 decode remote shell command
                                this.KnownFields.Add(("Type", exArgs[1]));
                                if(Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string decodedCommand))
                                    this.KnownFields.Add(("Command", decodedCommand));
                            }
                            else
                                this.AddUnknownFields(exArgs.Skip(1));
                        }
                        else if (tool == Tools.fm) {
                            if(exArgs.Length > 2 && Enum.TryParse(exArgs[1], out FileManagerActions action)) {
                                this.KnownFields.Add(("File Manager Action", exArgs[1]));

                                if (action == FileManagerActions.dw && exArgs.Length == 4) {
                                    //download
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string downloadFile))
                                        this.KnownFields.Add(("Download File", downloadFile));
                                }
                                else if(action == FileManagerActions.up && exArgs.Length == 5) {
                                    //upload
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string uploadFile)) {
                                        this.KnownFields.Add(("Upload File", uploadFile));
                                        if (Int32.TryParse(exArgs[4], out int size)) {
                                            this.KnownFields.Add((SIZE, exArgs[4]));
                                            c2ServerInfo?.requestedFileSizes.Add(uploadFile, size);
                                        }
                                    }
                                }
                                else if(action == FileManagerActions.fl && exArgs.Length == 4) {
                                    //run from link
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string source))
                                        this.KnownFields.Add(("Source", source));
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string destination))
                                        this.KnownFields.Add(("Destination", destination));
                                }
                                else if (action == FileManagerActions.rn && exArgs.Length == 3) {
                                    //Run
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string runFile))
                                        this.KnownFields.Add(("Run", runFile));
                                }
                                else if (action == FileManagerActions.cp && exArgs.Length == 4) {
                                    //copy
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string source))
                                        this.KnownFields.Add(("Source", source));
                                    if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out string destination))
                                        this.KnownFields.Add(("Destination", destination));
                                }

                                else if (Utils.StringManglerUtil.TryReadFromBase64(exArgs[2], out string actionParam)) {
                                    this.KnownFields.Add(("File Manager Value", actionParam));
                                }
                                else if (exArgs.Length > 3 && Utils.StringManglerUtil.TryReadFromBase64(exArgs[3], out actionParam)) {
                                    this.KnownFields.Add(("File Manager Value", actionParam));
                                }
                            }
                            else
                                this.AddUnknownFields(exArgs.Skip(1), true);
                        }
                        else
                            this.AddUnknownFields(exArgs.Skip(1));

                    }
                }
            }

            private void AddUnknownFields(IEnumerable<string> fieldValues, bool base64DecodeValues = false) {
                foreach (string v in fieldValues) {
                    if (base64DecodeValues && Utils.StringManglerUtil.TryReadFromBase64(v, out string decodedValue))
                        this.KnownFields.Add(("?", decodedValue));
                    else
                        this.KnownFields.Add(("?", v));
                }
            }

            private C2Message(C2ServerInfo c2ServerInfo) {
                this.KnownFields = new List<(string name, string value)>();
                this.Credentials = new List<(string username, string password, string site)>();
                this.c2ServerInfo = c2ServerInfo;
                this.SplitterCandidate = this.c2ServerInfo.GetLikelySplitter();
            }

            private void ParseFields(NjRatPacket njRatPacket, (string name, FieldEncoding encoding)[] fieldInfo) {
                foreach (var knownFieldInfo in this.ExtractKnownFields(njRatPacket, fieldInfo)) {
                    this.KnownFields.Add(knownFieldInfo);
                }
                if (fieldInfo.Any(f => f.encoding == FieldEncoding.raw)) {
                    //int rawFieldIndex = Array.FindIndex(fieldInfo, fi => fi.encoding == FieldEncoding.raw);
                    //byte[] splitterBytes = ASCIIEncoding.ASCII.GetBytes(this.SplitterCandidate);

                    
                    this.RawFieldData = this.ExtractRawData(njRatPacket, fieldInfo, out int rawFieldOffsetInMessage);
                    this.RawFieldDataTotalLength = njRatPacket.MessageLength - rawFieldOffsetInMessage;
                }
            }


            private byte[] ExtractRawData(NjRatPacket njRatPacket, (string name, FieldEncoding encoding)[] fieldInfo, out int rawFieldOffsetInMessage) {
                //byte[] data = njRatPacket.GetPacketData();
                int availableDataBytes = njRatPacket.MessageLength;
                if (njRatPacket.MessageStartIndex + njRatPacket.MessageLength > njRatPacket.PacketStartIndex + njRatPacket.PacketLength)
                    availableDataBytes = njRatPacket.PacketStartIndex + njRatPacket.PacketLength - njRatPacket.MessageStartIndex;
                byte[] data = new byte[availableDataBytes];
                Array.Copy(njRatPacket.ParentFrame.Data, njRatPacket.MessageStartIndex, data, 0, data.Length);

                byte[] delimiterBytes = Encoding.ASCII.GetBytes(this.SplitterCandidate);
                int offset = Utils.BoyerMoore.IndexOf(data, delimiterBytes, 0) + delimiterBytes.Length;
                rawFieldOffsetInMessage = -1;
                for (int i = 0; i < fieldInfo.Length; i++) {
                    if (offset < 1)
                        return null;
                    if (offset >= data.Length)
                        return null;
                    if (fieldInfo[i].encoding == FieldEncoding.raw) {
                        rawFieldOffsetInMessage = offset;
                        return data.Skip(offset).ToArray();
                    }
                    else {
                        //move ahead past next delimiter
                        offset = Utils.BoyerMoore.IndexOf(data, delimiterBytes, offset) + delimiterBytes.Length;
                    }
                }
                return null;
            }

            private IEnumerable<string> GetFields(NjRatPacket njRatPacket) {
                string fieldMessage = Encoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.SplitterIndex, Math.Min(njRatPacket.PacketEndIndex - njRatPacket.SplitterIndex + 1, njRatPacket.MessageLength - njRatPacket.CommandString.Length));
                return fieldMessage.Split(new string[] { this.SplitterCandidate }, StringSplitOptions.None).Skip(1);
            }

            private IEnumerable<(string fieldName, string fieldValue)> ExtractKnownFields(NjRatPacket njRatPacket, (string name, FieldEncoding encoding)[] fieldInfo) {
                if (fieldInfo.Length > 0 && !fieldInfo.Any(f => f.encoding == FieldEncoding.raw)) {
                    if (njRatPacket.SplitterIndex > 0) {
                        //verify delimiter using fieldInfo count
                        string fieldMessage = Encoding.ASCII.GetString(njRatPacket.ParentFrame.Data, njRatPacket.SplitterIndex, Math.Min(njRatPacket.PacketEndIndex - njRatPacket.SplitterIndex + 1, njRatPacket.MessageLength - njRatPacket.CommandString.Length));
                        //all fields are text or base64
                        string bestSplitterCandidate = this.SplitterCandidate;
                        if (njRatPacket.PacketEndIndex + 1 >= njRatPacket.MessageStartIndex + njRatPacket.MessageLength) {
                            for (int i = this.SplitterCandidate.Length; i > 1; i--) {
                                string[] delims = new string[] { this.SplitterCandidate.Substring(0, i) };
                                string[] _fields = fieldMessage.Split(delims, StringSplitOptions.None);
                                if (_fields.Length == fieldInfo.Length + 1) {
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                                else if (fieldInfo.Length > 4 && _fields.Length >= fieldInfo.Length && _fields.Length <= fieldInfo.Length + 2) {
                                    //allow +-1 diff
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                                else if (fieldInfo.Length > 10 && _fields.Length + 1 >= fieldInfo.Length && _fields.Length <= fieldInfo.Length + 3) {
                                    //allow +-2 diff
                                    bestSplitterCandidate = delims[0];
                                    break;
                                }
                            }
                        }
                        if (!string.IsNullOrEmpty(bestSplitterCandidate)) {
                            this.c2ServerInfo.TryAddSplitterCandidate(bestSplitterCandidate);
                            this.SplitterCandidate = this.c2ServerInfo.GetLikelySplitter();
                        }

                        //extract known fields
                        //string[] fields = fieldMessage.Split(new string[] { this.SplitterCandidate }, StringSplitOptions.None).Skip(1).ToArray();
                        string[] fields = this.GetFields(njRatPacket).ToArray();
                        if (fields.Length == fieldInfo.Length) {
                            for (int i = 0; i < fields.Length && i < fieldInfo.Length; i++) {
                                if (fieldInfo[i].encoding == FieldEncoding.plaintext)
                                    yield return (fieldInfo[i].name, fields[i]);
                                else if (fieldInfo[i].encoding == FieldEncoding.base64) {
                                    string fieldName = fieldInfo[i].name;
                                    string fieldValue = fields[i];
                                    if(Utils.StringManglerUtil.TryReadFromBase64(fields[i], out string decodedString)) {
                                        fieldValue = decodedString.TrimEnd('\0').Trim();
                                    }
                                    yield return (fieldName, fieldValue);

                                }
                                else
                                    yield return (fieldInfo[i].name, "[data]");
                            }
                        }
                        else {
                            for(int i = 0; i < fields.Length; i++)
                                yield return ("param" + i, fields[i]);
                            
                        }
                    }
                }
            }

        }

        internal class C2ServerInfo {
            private List<string> splitterCandidates = new List<string>();
            private string likelySplitter = null;

            internal IPAddress ServerIP { get; }
            internal int ServerPort { get; }

            internal PopularityList<string, int> requestedFileSizes;

            internal C2ServerInfo(IPEndPoint endPoint) {
                this.ServerIP = endPoint.Address;
                this.ServerPort = endPoint.Port;
                this.requestedFileSizes = new PopularityList<string, int>(10);
            }

            public bool TryAddSplitterCandidate(string candidate) {
                if (!string.IsNullOrEmpty(candidate))
                    if (!this.splitterCandidates.Contains(candidate)) {
                        //verify that it is an OK candidate by checking that the first character is the same as all the others
                        if (this.splitterCandidates.All(old => old[0] == candidate[0])) {
                            //an extra check just to be sure the new candidate is not a truncated splitter
                            string previousLikelySplitter = this.GetLikelySplitter();
                            if (previousLikelySplitter == null || this.splitterCandidates.Count < 3 || candidate.Length > 4 || candidate.Length > previousLikelySplitter.Length / 2) {
                                this.splitterCandidates.Add(candidate);
                                this.likelySplitter = null;
                                return true;
                            }
                        }
                    }
                return false;
            }

            public string GetLikelySplitter() {
                if (this.likelySplitter == null) {
                    foreach (string d in this.splitterCandidates) {
                        if (this.likelySplitter == null)
                            this.likelySplitter = d;
                        else if(this.likelySplitter.Length < d.Length && this.likelySplitter.Equals(d.Substring(0, this.likelySplitter.Length))) {
                            //do nothing, we already have the best possible likely delimiter
                        }
                        else {
                            StringBuilder newSplitter = new StringBuilder();
                            for(int i = 0; i < Math.Min(d.Length, this.likelySplitter.Length); i++) {
                                if (this.likelySplitter[i] == d[i])
                                    newSplitter.Append(d[i]);
                                else
                                    break;
                            }
                            this.likelySplitter = newSplitter.ToString();
                        }

                    }
                }
                return this.likelySplitter;
            }
        }
    }
}
