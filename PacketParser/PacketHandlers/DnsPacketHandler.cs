//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    public class DnsPacketHandler : AbstractPacketHandler, IPacketHandler, ITcpSessionPacketHandler {


        public override Type ParsedType { get { return typeof(Packets.DnsPacket); } }

        public DnsPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Dns;
            }
        }

        #region IPacketHandler Members

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int parsedBytes = 0;
            foreach (DnsPacket dp in packetList.OfType<DnsPacket>()) {
                parsedBytes += dp.PacketLength;
                parsedBytes += dp.SkippedBytes;
            }
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.ClientHost;
                destinationHost = tcpSession.ServerHost;
            }
            else {
                sourceHost = tcpSession.ServerHost;
                destinationHost = tcpSession.ClientHost;
            }
            this.ExtractData(ref sourceHost, destinationHost, packetList);
            return parsedBytes;
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            Packets.DnsPacket dnsPacket=null;
            Packets.IIPPacket ipPacket=null;
            Packets.ITransportLayerPacket transportLayerPacket =null;

            foreach(Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.DnsPacket))
                    dnsPacket = (Packets.DnsPacket)p;
                else if (p is Packets.IIPPacket)
                    ipPacket = (Packets.IIPPacket)p;
                /*else if(p.GetType()==typeof(Packets.IPv6Packet))
                    ipv6Packet=(Packets.IPv6Packet)p;*/
                else if (p is Packets.ITransportLayerPacket tlp)
                    transportLayerPacket = tlp;
            }

            if(dnsPacket!=null) {

                //ExtractDnsData(dnsPacket);
                if(dnsPacket.Flags.Response) {
                    System.Collections.Specialized.NameValueCollection cNamePointers=new System.Collections.Specialized.NameValueCollection();
                    if (dnsPacket.AnswerRecords != null && dnsPacket.AnswerRecords.Length > 0) {
                        foreach (Packets.DnsPacket.ResourceRecord r in dnsPacket.AnswerRecords) {
                            if (r.IP != null) {
                                if (!base.MainPacketHandler.NetworkHostList.ContainsIP(r.IP)) {
                                    NetworkHost host = new NetworkHost(r.IP);
                                    host.AddHostName(r.DNS, dnsPacket.PacketTypeDescription);
                                    lock(base.MainPacketHandler.NetworkHostList)
                                        base.MainPacketHandler.NetworkHostList.Add(host);
                                    MainPacketHandler.OnNetworkHostDetected(new Events.NetworkHostEventArgs(host));
                                    //base.MainPacketHandler.ParentForm.ShowDetectedHost(host);
                                }
                                else
                                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(r.IP).AddHostName(r.DNS, dnsPacket.PacketTypeDescription);
                                if (cNamePointers[r.DNS] != null)
                                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(r.IP).AddHostName(cNamePointers[r.DNS], dnsPacket.PacketTypeDescription);

                            }
                            else if (r.Type == (ushort)Packets.DnsPacket.RRTypes.CNAME) {
                                cNamePointers.Add(r.PrimaryName, r.DNS);
                            }

                            
                            MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(r, sourceHost, destinationHost, ipPacket, transportLayerPacket));
                            //base.MainPacketHandler.ParentForm.ShowDnsRecord(r, sourceHost, destinationHost, ipPakcet, udpPacket);
                            
                        }
                    }
                    else {
                        //display the flags instead
                        //TODO : MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(
                        if(dnsPacket.QueriedDnsName != null && dnsPacket.QueriedDnsName.Length > 0)
                            MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(new Packets.DnsPacket.ResponseWithErrorCode(dnsPacket), sourceHost, destinationHost, ipPacket, transportLayerPacket));

                        
                    }
                }
                else {//DNS request
                    if (dnsPacket.QueriedDnsName != null && dnsPacket.QueriedDnsName.Length > 0) {
                        sourceHost.AddQueriedDnsName(dnsPacket.QueriedDnsName);
                        if(DNSBL.TryParse(dnsPacket.QueriedDnsName, out var ipService)) {
                            sourceHost.AddNumberedExtraDetail("DNSBL lookup", ipService.ip.ToString() + " through " + dnsPacket.QueriedDnsName);
                            if (transportLayerPacket != null) {
                                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                                parms.Add("DNSBL lookup at " + ipService.service, ipService.ip.ToString());
                                this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(dnsPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parms, dnsPacket.ParentFrame.Timestamp, "DNS query"));
                            }
                        }
                    }
                }

            }
        }

        

        public void Reset() {
            //do nothing since this class holds no state
        }

        #endregion

        public class DNSBL {
            private static readonly HashSet<string> DNSBL_DOMAINS = new HashSet<string>() {
                "access.redhawk.org",
                "all.s5h.net",
                "b.barracudacentral.org",
                "blackholes.mail-abuse.org",
                "blacklist.woody.ch",
                "bl.mailspike.net",
                "bl.spamcop.net",
                "bogons.cymru.com",
                "cbl.abuseat.org",
                "cbl.anti-spam.org.cn",
                "cdl.anti-spam.org.cn",
                "combined.abuse.ch",
                "csi.cloudmark.com",
                "db.wpbl.info",
                "dnsbl-1.uceprotect.net",
                "dnsbl-2.uceprotect.net",
                "dnsbl-3.uceprotect.net",
                "dnsbl.dronebl.org",
                "dnsbl.inps.de",
                "dnsbl.sorbs.net",
                "drone.abuse.ch",
                "dsn.rfc-ignorant.org",
                "duinv.aupads.org",
                "dul.dnsbl.sorbs.net",
                "dyna.spamrats.com",
                "httpbl.abuse.ch",
                "http.dnsbl.sorbs.net",
                "ips.backscatterer.org",
                "ix.dnsbl.manitu.net",
                "korea.services.net",
                "misc.dnsbl.sorbs.net",
                "multi.surbl.org",
                "netblock.pedantic.org",
                "noptr.spamrats.com",
                "opm.tornevall.org",
                "orvedb.aupads.org",
                "pbl.spamhaus.org",
                "proxy.bl.gweep.ca",
                "psbl.surriel.com",
                "query.senderbase.org",
                "rbl.efnetrbl.org",
                "rbl.interserver.net",
                "rbl-plus.mail-abuse.org",
                "rbl.spamlab.com",
                "rbl.suresupport.com",
                "relays.bl.gweep.ca",
                "relays.mail-abuse.org",
                "relays.nether.net",
                "sbl.spamhaus.org",
                "short.rbl.jp",
                "singular.ttk.pte.hu",
                "smtp.dnsbl.sorbs.net",
                "socks.dnsbl.sorbs.net",
                "spam.abuse.ch",
                "spambot.bls.digibase.ca",
                "spam.dnsbl.anonmails.de",
                "spam.dnsbl.sorbs.net",
                "spamguard.leadmon.net",
                "spamrbl.imp.ch",
                "spamsources.fabel.dk",
                "spam.spamrats.com",
                "tor.dan.me.uk",
                "truncate.gbudb.net",
                "ubl.lashback.com",
                "ubl.unsubscore.com",
                "virbl.bit.nl",
                "virus.rbl.jp",
                "web.dnsbl.sorbs.net",
                "wormrbl.imp.ch",
                "xbl.spamhaus.org",
                "zen.spamhaus.org",
                "z.mailspike.net",
                "zombie.dnsbl.sorbs.net"
            };

            private static readonly System.Text.RegularExpressions.Regex IPV4_DNSBL_REGEX = new System.Text.RegularExpressions.Regex("^(?<revip>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\\.(?<service>[a-zA-Z\\-\\.]*)");

            public static bool TryParse(string domain, out (System.Net.IPAddress ip, string service) ipAndService) {
                //assume IPv4 for now, such as "13.12.11.10.zen.spamhaus.org"
                System.Text.RegularExpressions.Match match = IPV4_DNSBL_REGEX.Match(domain);
                if (match?.Success == true) {
                    string revip = match.Groups["revip"].Value;
                    ipAndService.service = match.Groups["service"].Value;
                    if (!string.IsNullOrEmpty(revip) && DNSBL_DOMAINS.Contains(ipAndService.service)) {
                        string ipString = string.Join(".", revip.Split('.').Reverse());
                        return System.Net.IPAddress.TryParse(ipString, out ipAndService.ip);
                        
                    }
                }
                ipAndService = (null, null);
                return false;
            }
        }
    }
}
