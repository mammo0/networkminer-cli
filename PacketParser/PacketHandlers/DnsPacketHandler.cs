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
                    if(dnsPacket.QueriedDnsName!=null && dnsPacket.QueriedDnsName.Length>0)
                        sourceHost.AddQueriedDnsName(dnsPacket.QueriedDnsName);
                }

            }
        }

        

        public void Reset() {
            //do nothing since this class holds no state
        }

        #endregion
    }
}
