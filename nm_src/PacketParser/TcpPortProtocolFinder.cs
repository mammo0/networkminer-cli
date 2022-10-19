//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class TcpPortProtocolFinder : ISessionProtocolFinder {

        public static IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols(ushort serverPort, ushort clientPort) {

            TcpPortProtocolFinder finder = new TcpPortProtocolFinder(null, null, clientPort, serverPort, 0, DateTime.MinValue, null);
            return finder.GetProbableApplicationLayerProtocols();
        }

        private static readonly (ApplicationLayerProtocol protocol, HashSet<ushort> serverPorts)[] PROTOCOL_PORTS = {
            (ApplicationLayerProtocol.Http,
                new HashSet<ushort> {
                    80,
                    631,//IPP
                    3000,//WEBrick
                    5985,
                    8000,//WEBrick
                    8080,
                    3128,//TCP 3128 = Squid proxy: http://www.squid-cache.org/Doc/config/http_port/
                    10080,
                    11371
                }
            ),
            (ApplicationLayerProtocol.Ssl,
                new HashSet<ushort> {//From: http://www.rickk.com/sslwrap/
                    443,//https 443/tcp     # http protocol over TLS/SSL
                    465,//smtps 465/tcp     # smtp protocol over TLS/SSL
                    563,//nntps 563/tcp     # nttp protocol over TLS/SSL
                    614,//sshell 	614 	tcp 	SSLshell
                    636,//ldaps 	636 	tcp 	ldap protocol over TLS/SSL (was sldap)
                    853,//dns over tls
                    989,//ftps-data 989/tcp # ftp protocol, data, over TLS/SSL
                    990,//ftps 990/tcp      # ftp protocol, control, over TLS/SSL
                    992,//telnets 992/tcp   # telnet protocol over TLS/SSL
                    993,//imaps 993/tcp     # imap4 protocol over TLS/SSL
                    994,//ircs 994/tcp      # irc protocol over TLS/SSL
                    995,//pop3s 995/tcp     # POP3 protocol over TLS/SSL
                    5061,
                    5223,
                    5986,
                    8170,
                    8443,
                    9001,
                    9030,
                    10443
                }
            ),
        (ApplicationLayerProtocol.Meterpreter,
                new HashSet<ushort> {
                    3333,
                    4444,
                    4445,
                    4446,
                    4447,
                    4448,
                    4449,
                    5555,
                    6666,
                    7777,
                    8888,
                    9999
                }
            )
        };


        private List<ApplicationLayerProtocol> probableProtocols;
        private ApplicationLayerProtocol confirmedProtocol;
        

        private NetworkFlow flow;
        private NetworkHost client;
        private NetworkHost server;
        private ushort clientPort;
        private ushort serverPort;

        private long startFrameNumber;
        private DateTime startTimestamp;

        private PacketHandler packetHandler;




        public NetworkHost Client {
            get { return this.client; }
        }
        public NetworkHost Server {
            get { return this.server; }
        }

        public ushort ClientPort {
            get { return this.clientPort; }
        }
        public ushort ServerPort {
            get { return this.serverPort; }
        }

        public NetworkFlow Flow { get { return this.flow; } }

        public ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol() {
            return this.confirmedProtocol;
        }

        public void SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint) {
            if (this.confirmedProtocol == ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
                this.packetHandler.OnSessionDetected(new PacketParser.Events.SessionEventArgs(this.flow, value, this.startFrameNumber));
                if (setAsPersistantProtocolOnServerEndPoint && value != ApplicationLayerProtocol.Unknown) {
                    lock (this.server.NetworkServiceMetadataList)
                        if (this.server.NetworkServiceMetadataList.ContainsKey(this.serverPort))
                            this.server.NetworkServiceMetadataList[this.serverPort].ApplicationLayerProtocol = value;
                }
            }
            else if (value != PacketParser.ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
            }
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler) : this(flow.FiveTuple.ClientHost, flow.FiveTuple.ServerHost, flow.FiveTuple.ClientPort, flow.FiveTuple.ServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.flow = flow;
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler, NetworkHost nextHopServer, ushort nextHopServerPort) : this(flow.FiveTuple.ClientHost, nextHopServer, flow.FiveTuple.ClientPort, nextHopServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.flow = flow;
        }

        private TcpPortProtocolFinder(NetworkHost client, NetworkHost server, ushort clientPort, ushort serverPort, long startFrameNumber, DateTime startTimestamp, PacketHandler packetHandler) {
            this.probableProtocols = new List<ApplicationLayerProtocol>();
            this.confirmedProtocol = ApplicationLayerProtocol.Unknown;
            this.client = client;
            this.server = server;
            this.clientPort = clientPort;
            this.serverPort = serverPort;

            this.startFrameNumber = startFrameNumber;
            this.startTimestamp = startTimestamp;

            this.packetHandler = packetHandler;

            if (this.serverPort == 21 || this.serverPort == 8021) 
                this.probableProtocols.Add(ApplicationLayerProtocol.FtpControl);
            if(this.serverPort==22)
                this.probableProtocols.Add(ApplicationLayerProtocol.Ssh);
            if(this.serverPort==25 || this.serverPort==587)
                this.probableProtocols.Add(ApplicationLayerProtocol.Smtp);
            if (this.serverPort == 53)
                this.probableProtocols.Add(ApplicationLayerProtocol.Dns);
            /*
            if (this.serverPort == 80 ||
                this.serverPort == 631 || //IPP
                this.serverPort == 3000 || //WEBrick
                this.serverPort == 5985 ||
                this.serverPort == 8000 || //WEBrick
                this.serverPort == 8080 ||
                this.serverPort == 3128 ||
                this.ServerPort == 10080 ||
                this.serverPort == 11371) { //TCP 3128 = Squid proxy: http://www.squid-cache.org/Doc/config/http_port/
                this.probableProtocols.Add(ApplicationLayerProtocol.Http);
            }
            */
            if (this.serverPort == 80 || this.serverPort == 10080)
                this.probableProtocols.Add(ApplicationLayerProtocol.Http2);
            if (this.serverPort == 88 || this.clientPort == 88)
                this.probableProtocols.Add(ApplicationLayerProtocol.Kerberos);
            if (this.serverPort == 102 || this.serverPort == 3389)//102 = Siemens S7, 3389 = RDP
                this.probableProtocols.Add(ApplicationLayerProtocol.Tpkt);
            if (this.serverPort == 110)
                this.probableProtocols.Add(ApplicationLayerProtocol.Pop3);
            if (this.serverPort==137 || this.clientPort==137)
                this.probableProtocols.Add(ApplicationLayerProtocol.NetBiosNameService);
            if (this.serverPort == 143 || this.serverPort == 220)
                this.probableProtocols.Add(ApplicationLayerProtocol.Imap);
            if(this.serverPort==139 || this.clientPort==139)
                this.probableProtocols.Add(ApplicationLayerProtocol.NetBiosSessionService);
            /*
            if(
                this.serverPort==443 ||
                this.serverPort==465 ||
                this.serverPort==563 ||
                this.serverPort == 614 ||
                this.serverPort == 636 ||
                this.serverPort==992 ||
                this.serverPort==993 ||
                this.serverPort==994 ||
                this.serverPort==995 ||
                this.serverPort==989 ||
                this.serverPort==990 ||
                this.serverPort == 5061 ||
                this.serverPort==5223 ||
                this.serverPort == 5986 ||
                this.serverPort==8170 ||
                this.serverPort==8443 ||
                this.serverPort==9001 ||
                this.serverPort==9030 ||
                this.serverPort == 10443) {
                this.probableProtocols.Add(ApplicationLayerProtocol.Ssl);
            }*/
            if(this.serverPort==445 || this.clientPort==445)
                this.probableProtocols.Add(ApplicationLayerProtocol.NetBiosSessionService);
            if (this.ServerPort == 515)
                this.probableProtocols.Add(ApplicationLayerProtocol.Lpd);
            if (this.serverPort == 1080 ||
                this.ServerPort == 4145 ||
                this.serverPort == 9040 ||
                this.serverPort == 9050 ||
                this.serverPort == 9051 ||
                this.serverPort == 9150 ||
                (this.server != null && System.Net.IPAddress.IsLoopback(this.server.IPAddress) && this.ServerPort > 1024))
                this.probableProtocols.Add(ApplicationLayerProtocol.Socks);
            if (this.serverPort==1433)
                this.probableProtocols.Add(ApplicationLayerProtocol.TabularDataStream);
            if(this.serverPort==4070)
                this.probableProtocols.Add(ApplicationLayerProtocol.SpotifyServerProtocol);
            if(this.serverPort==194 || (this.serverPort>=6660 && this.serverPort<=6670) || this.serverPort==7777 || (this.serverPort>=6112 && this.serverPort<=6119))
                this.probableProtocols.Add(ApplicationLayerProtocol.Irc);
            if (this.serverPort == 6633 || this.clientPort == 6633)
                this.probableProtocols.Add(ApplicationLayerProtocol.OpenFlow);
            if (this.serverPort==5190 || this.clientPort==5190 || this.clientPort==443 || this.serverPort==443)
                this.probableProtocols.Add(ApplicationLayerProtocol.Oscar);
            if(this.serverPort==5190 || this.clientPort==5190 || this.clientPort==443 || this.serverPort==443)
                this.probableProtocols.Add(ApplicationLayerProtocol.OscarFileTransfer);
            if (this.ServerPort == 5060 || this.clientPort == 5060)
                this.probableProtocols.Add(ApplicationLayerProtocol.Sip);
            if (this.serverPort == 2404 || this.clientPort == 2404)
                this.probableProtocols.Add(ApplicationLayerProtocol.IEC_104);
            if (this.serverPort == 502 || this.clientPort == 502)
                this.probableProtocols.Add(ApplicationLayerProtocol.ModbusTCP);

            foreach((ApplicationLayerProtocol protocol, HashSet<ushort> portSet) in PROTOCOL_PORTS) {
                if (portSet.Contains(this.serverPort))
                    this.probableProtocols.Add(protocol);
            }
        }

        public void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, NetworkHost source, NetworkHost destination) {
            //do nothing
        }

        public IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols() {
            if(this.confirmedProtocol != ApplicationLayerProtocol.Unknown)
                yield return this.confirmedProtocol;
            else {
                foreach(ApplicationLayerProtocol p in this.probableProtocols)
                    yield return p;
            }
        }

        
    }
}
