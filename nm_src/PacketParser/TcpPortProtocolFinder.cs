//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketParser;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketParser {
    public class TcpPortProtocolFinder : ISessionProtocolFinder {


        public static Dictionary<IPEndPoint, ApplicationLayerProtocol> EndPointProtocols = new Dictionary<IPEndPoint, ApplicationLayerProtocol>() {
            //Well-known BackConnect servers
            //443 services
            { new IPEndPoint(IPAddress.Parse("45.61.139.144"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("45.61.139.235"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("46.151.30.109"), 443), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("78.31.67.7"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("134.122.62.178"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("137.184.172.23"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("138.197.146.18"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("139.59.33.128"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("159.89.116.11"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("165.232.175.216"), 443),  ApplicationLayerProtocol.BackConnect },//XOR BackConnect
            { new IPEndPoint(IPAddress.Parse("167.99.248.131"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("168.100.9.230"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("193.149.187.7"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("193.149.176.198"), 443),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("193.149.176.100"), 443),  ApplicationLayerProtocol.BackConnect },
            //8080 services
            { new IPEndPoint(IPAddress.Parse("38.135.122.194"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("45.61.137.220"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("45.147.228.197"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("46.21.153.153"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("51.89.201.236"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("51.195.169.87"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("80.66.88.71"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("88.119.161.76"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("91.238.50.80"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("135.148.217.85"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("137.74.104.108"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("162.33.179.145"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("185.92.73.147"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("185.99.132.16"), 8080),  ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("188.40.246.37"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("193.239.85.16"), 8080), ApplicationLayerProtocol.BackConnect },
            { new IPEndPoint(IPAddress.Parse("194.5.249.150"), 8080), ApplicationLayerProtocol.BackConnect },
            //9090
            { new IPEndPoint(IPAddress.Parse("87.120.8.190"), 9090), ApplicationLayerProtocol.BackConnect }

#if DEBUG
            ,
            //njRAT
            { new IPEndPoint(IPAddress.Parse("204.11.56.48"), 22), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.22.15.135"), 11098), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.68.171.119"), 17674), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.121.139.82"), 19184), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.126.37.18"), 11024), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.126.37.18"), 17530), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.126.224.214"), 2815), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.127.253.86"), 19184), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("3.131.207.170"), 17021), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("18.139.9.214"), 11978), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("18.192.93.86"), 11024), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("18.197.239.109"), 17674), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("35.158.159.254"), 17953), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("37.1.218.71"), 7777), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("46.246.4.12"), 2815), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("46.246.6.3"), 1994), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("52.14.18.129"), 17021), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("52.28.112.211"), 17953), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("52.28.247.255"), 17674), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("54.69.246.204"), 53802), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("94.45.113.179"), 4577), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("160.179.92.178"), 1177), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("178.33.93.88"), 2134), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("193.161.193.99"), 20742), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("193.161.193.99"), 42001), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("196.92.99.51"), 1177), ApplicationLayerProtocol.njRAT },
            { new IPEndPoint(IPAddress.Parse("209.25.141.224"), 18786), ApplicationLayerProtocol.njRAT }
#endif
        };

        public static IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols(ushort serverPort, ushort clientPort, bool clientMightBeServer = false) {
            TcpPortProtocolFinder finder = new TcpPortProtocolFinder(null, null, clientPort, serverPort, 0, DateTime.MinValue, null, clientMightBeServer);
            return finder.GetProbableApplicationLayerProtocols();
        }

        public static readonly (ApplicationLayerProtocol protocol, HashSet<ushort> serverPorts)[] PROTOCOL_PORTS = {
            (ApplicationLayerProtocol.HTTP,
                new HashSet<ushort> {
                    80,
                    631,//IPP
                    3000,//WEBrick
                    5985,
                    8000,//WEBrick
                    8080,
                    3128,//TCP 3128 = Squid proxy: http://www.squid-cache.org/Doc/config/http_port/
                    10080,
                    11371//HKP for GPG keyservers
                }
            ),
            (ApplicationLayerProtocol.SSL,
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
                    5061,//SIP
                    5223,//XMPP
                    5228,//mtalk.google.com Google C2DM (push)
                    5986,//WinRM HTTPS
                    8170,
                    8443,
                    8883,//MQTT (Microsoft Azure IoT Hub)
                    9001,//Tor
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
                    4545,
                    5555,
                    6666,
                    7777,
                    8888,
                    9999
                }
            ),
        (ApplicationLayerProtocol.njRAT,
                new HashSet<ushort> {
                    //common port in 2023
                    1177,
                    5050,
                    5552,
                    19184,
                    17297,
                    //other common ports according to speedguide.net
                    8521,
                    8008,
                    //additional recently observed random ports
                    11024,
                    17021,
                    17674,
                    17953,
                }
            )
        };

        public static IEnumerable<ApplicationLayerProtocol> GetDefaultProtocols(ushort clientPort, ushort serverPort, bool clientMightBeServer = false, NetworkHost client = null, NetworkHost server = null) {
            if (serverPort == 21 || serverPort == 8021)
                yield return ApplicationLayerProtocol.FTP;
            if (serverPort == 22)
                yield return ApplicationLayerProtocol.SSH;
            if (serverPort == 25 || serverPort == 587)
                yield return ApplicationLayerProtocol.SMTP;
            if (serverPort == 53)
                yield return ApplicationLayerProtocol.DNS;
            if (serverPort == 80 || serverPort == 10080)
                yield return ApplicationLayerProtocol.HTTP2;
            if (serverPort == 88 || clientPort == 88)
                yield return ApplicationLayerProtocol.Kerberos;
            if (serverPort == 102 || serverPort == 3389)//102 = Siemens S7, 3389 = RDP
                yield return ApplicationLayerProtocol.TPKT;
            if (serverPort == 110)
                yield return ApplicationLayerProtocol.POP3;
            if (serverPort == 137 ||clientPort == 137)
                yield return ApplicationLayerProtocol.NetBiosNameService;
            if (serverPort == 143 || serverPort == 220)
                yield return ApplicationLayerProtocol.IMAP;
            if (serverPort == 139 || clientPort == 139)
                yield return ApplicationLayerProtocol.NetBiosSessionService;
            if (serverPort == 445 ||clientPort == 445)
                yield return ApplicationLayerProtocol.NetBiosSessionService;
            if (serverPort == 515)
                yield return ApplicationLayerProtocol.LPD;
            if (serverPort == 1080 ||
                serverPort == 4145 ||
                serverPort == 9040 ||
                serverPort == 9050 ||
                serverPort == 9051 ||
                serverPort == 9150 ||
                (server != null && System.Net.IPAddress.IsLoopback(server.IPAddress) && serverPort > 1024))
                yield return ApplicationLayerProtocol.SOCKS;
            if (serverPort == 1433)
                yield return ApplicationLayerProtocol.TabularDataStream;
            if (serverPort == 4070)
                yield return ApplicationLayerProtocol.SpotifyServerProtocol;
            if (serverPort == 194 || (serverPort >= 6660 && serverPort <= 6670) || serverPort == 7777 || (serverPort >= 6112 && serverPort <= 6119))
                yield return ApplicationLayerProtocol.IRC;
            if (serverPort == 6633 || clientPort == 6633)
                yield return ApplicationLayerProtocol.OpenFlow;
            if (serverPort == 5190 || clientPort == 5190 || clientPort == 443 || serverPort == 443)
                yield return ApplicationLayerProtocol.Oscar;
            if (serverPort == 5190 || clientPort == 5190 || clientPort == 443 || serverPort == 443)
                yield return ApplicationLayerProtocol.OscarFileTransfer;
            if (serverPort == 5060 || clientPort == 5060)
                yield return ApplicationLayerProtocol.SIP;
            if (serverPort == 5900 || clientPort == 5900 || serverPort == 5901 || clientPort == 5901)
                yield return ApplicationLayerProtocol.VNC;
            if (serverPort == 2404 || clientPort == 2404)
                yield return ApplicationLayerProtocol.IEC_104;
            if (serverPort == 502 || clientPort == 502)
                yield return ApplicationLayerProtocol.ModbusTCP;

            foreach ((ApplicationLayerProtocol protocol, HashSet<ushort> portSet) in PROTOCOL_PORTS) {
                if (portSet.Contains(serverPort))
                    yield return protocol;
                else if (clientMightBeServer && portSet.Contains(clientPort))
                    yield return protocol;
            }
        }


        private readonly List<ApplicationLayerProtocol> probableProtocols;
        private ApplicationLayerProtocol confirmedProtocol;
        private readonly long startFrameNumber;
        private readonly DateTime startTimestamp;
        private readonly PacketHandler packetHandler;




        public NetworkHost Client { get; }
        public NetworkHost Server { get; }

        public ushort ClientPort { get; }
        public ushort ServerPort { get; }

        public NetworkFlow Flow { get; }

        public ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol() {
            return this.confirmedProtocol;
        }

        public void SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint) {
            if (this.confirmedProtocol == ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
                this.packetHandler.OnSessionDetected(new PacketParser.Events.SessionEventArgs(this.Flow, value, this.startFrameNumber));
                if (setAsPersistantProtocolOnServerEndPoint && value != ApplicationLayerProtocol.Unknown) {
                    lock (this.Server.NetworkServiceMetadataList)
                        if (this.Server.NetworkServiceMetadataList.ContainsKey(this.ServerPort))
                            this.Server.NetworkServiceMetadataList[this.ServerPort].ApplicationLayerProtocol = value;
                }
            }
            else if (value != PacketParser.ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
            }
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler) : this(flow.FiveTuple.ClientHost, flow.FiveTuple.ServerHost, flow.FiveTuple.ClientPort, flow.FiveTuple.ServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler, NetworkHost nextHopServer, ushort nextHopServerPort) : this(flow.FiveTuple.ClientHost, nextHopServer, flow.FiveTuple.ClientPort, nextHopServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        private TcpPortProtocolFinder(NetworkHost client, NetworkHost server, ushort clientPort, ushort serverPort, long startFrameNumber, DateTime startTimestamp, PacketHandler packetHandler, bool clientMightBeServer = false) {
            this.probableProtocols = new List<ApplicationLayerProtocol>();
            if (server != null && EndPointProtocols.ContainsKey(new IPEndPoint(server.IPAddress, serverPort))) {
                ApplicationLayerProtocol protocol = EndPointProtocols[new IPEndPoint(server.IPAddress, serverPort)];
                if(!this.probableProtocols.Contains(protocol))
                    this.probableProtocols.Add(protocol);
            }
            this.confirmedProtocol = ApplicationLayerProtocol.Unknown;
            this.Client = client;
            this.Server = server;
            this.ClientPort = clientPort;
            this.ServerPort = serverPort;

            this.startFrameNumber = startFrameNumber;
            this.startTimestamp = startTimestamp;

            this.packetHandler = packetHandler;

            this.probableProtocols.AddRange(GetDefaultProtocols(this.ClientPort, this.ServerPort, clientMightBeServer, this.Client, this.Server));
        }

        public void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, NetworkHost source, NetworkHost destination) {
            //do nothing
        }

        public IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols() {
            if (this.confirmedProtocol != ApplicationLayerProtocol.Unknown) {
                yield return this.confirmedProtocol;
                if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.HTTP)
                    yield return PacketParser.ApplicationLayerProtocol.HTTP2;
                else if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.HTTP2)
                    yield return PacketParser.ApplicationLayerProtocol.HTTP;
            }
            else {
                foreach (ApplicationLayerProtocol p in this.probableProtocols)
                    yield return p;
            }
        }

        
    }
}
