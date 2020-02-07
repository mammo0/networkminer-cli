using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class SipPacketHandler : AbstractPacketHandler, IPacketHandler, ITcpSessionPacketHandler {

        private const string INVITE = "INVITE";
        private PopularityList<string, List<Tuple<System.Net.IPAddress, ushort, FiveTuple>>> callEndPoints;
        //private PopularityList<Tuple<System.Net.IPAddress, System.Net.IPAddress>, ushort> endPointCandidates;
        private IUdpPayloadProtocolFinder udpPayloadProtocolFinder;

        public override Type ParsedType { get { return typeof(Packets.SipPacket); } }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Sip;
            }
        }

        public SipPacketHandler(PacketHandler mainPacketHandler, IUdpPayloadProtocolFinder udpPayloadProtocolFinder = null)
            : base(mainPacketHandler) {
            //this.endPointCandidates = new PopularityList<Tuple<System.Net.IPAddress, System.Net.IPAddress>, ushort>(100);
            this.callEndPoints = new PopularityList<string, List<Tuple<System.Net.IPAddress, ushort, FiveTuple>>>(100);
            this.udpPayloadProtocolFinder = udpPayloadProtocolFinder;
        }

        #region IPacketHandler Members

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            //throw new NotImplementedException();
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.ClientHost;
                destinationHost = tcpSession.ServerHost;
            }
            else {
                sourceHost = tcpSession.ServerHost;
                destinationHost = tcpSession.ClientHost;
            }
            return this.ExtractData(sourceHost, destinationHost, packetList);
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            this.ExtractData(sourceHost, destinationHost, packetList);
        }
        public int ExtractData(NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            //Packets.UdpPacket udpPacket = null;
            int parsedBytes = 0;
            Packets.ITransportLayerPacket transportLayerPacket = null;
            FiveTuple ft = null;
            foreach (Packets.AbstractPacket p in packetList) {
                
                if (p is Packets.ITransportLayerPacket) {
                    transportLayerPacket = (Packets.ITransportLayerPacket)p;
                    if (transportLayerPacket is Packets.UdpPacket)
                        ft = new FiveTuple(sourceHost, transportLayerPacket.SourcePort, destinationHost, transportLayerPacket.DestinationPort, FiveTuple.TransportProtocol.UDP);
                    else if (transportLayerPacket is Packets.TcpPacket)
                        ft = new FiveTuple(sourceHost, transportLayerPacket.SourcePort, destinationHost, transportLayerPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                }
                if(p.GetType()==typeof(Packets.SipPacket)) {
                    Packets.SipPacket sipPacket=(Packets.SipPacket)p;
                    if(sipPacket.MessageLine.StartsWith(INVITE)) {
                        string to = null;
                        string from = null;
                        if (sipPacket.To!=null && sipPacket.To.Length>0){
                            to=sipPacket.To;
                            if(to.Contains(";"))
                                to=to.Substring(0,to.IndexOf(';'));
                            destinationHost.AddNumberedExtraDetail("SIP User", to);
                            //destinationHost.ExtraDetailsList["SIP User"]=to;
                        }
                        if(sipPacket.From!=null && sipPacket.From.Length>0) {
                            from=sipPacket.From;
                            if(from.Contains(";"))
                                from=from.Substring(0, from.IndexOf(';'));
                            //destinationHost.AddNumberedExtraDetail("SIP User", from);
                            sourceHost.AddNumberedExtraDetail("SIP User", from);
                            //sourceHost.ExtraDetailsList["SIP User"]=from;
                        }
                        if(ft != null && to!=null && from != null && !String.IsNullOrEmpty(sipPacket.CallID)) {
                            System.Collections.Specialized.NameValueCollection nvc = new System.Collections.Specialized.NameValueCollection {
                                { "From", sipPacket.From },
                                { "To", sipPacket.To },
                                { "Call-ID", sipPacket.CallID }
                            };
                            this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(sipPacket.ParentFrame.FrameNumber, ft, true, nvc, sipPacket.ParentFrame.Timestamp, "SIP session " + ft.ToString()));
                        }
                    }
                    if(!String.IsNullOrEmpty(sipPacket.UserAgent)) {
                        sourceHost.AddHttpUserAgentBanner(sipPacket.UserAgent);
                    }
                    if(sipPacket.SDP != null) {
                        if (sipPacket.SDP.Port != null && sipPacket.SDP.IP != null && sipPacket.CallID != null && ft != null) {
                            lock(callEndPoints) {
                                Tuple<System.Net.IPAddress, ushort, FiveTuple> endPoint = new Tuple<System.Net.IPAddress, ushort, FiveTuple>(sipPacket.SDP.IP, sipPacket.SDP.Port.Value, ft);
                                if (this.callEndPoints.ContainsKey(sipPacket.CallID)) {
                                    Tuple<System.Net.IPAddress, ushort, FiveTuple> matchedTuple = null;
                                    foreach (var previousEndPoint in this.callEndPoints[sipPacket.CallID]) {
                                        if (previousEndPoint.Item3.EqualsIgnoreDirection(ft)) {
                                            //Tuple<System.Net.IPAddress, ushort, FiveTuple> previousEndPoint = ;
                                            if (!(previousEndPoint.Item1.Equals(endPoint.Item1) && previousEndPoint.Item2.Equals(endPoint.Item2))) {
                                                //this.callEndPoints.Remove(sipPacket.CallID);
                                                matchedTuple = previousEndPoint;
                                                if (sipPacket.From != null && sipPacket.To != null) {
                                                    this.MainPacketHandler.OnVoipCallDetected(sipPacket.SDP.IP, sipPacket.SDP.Port.Value, previousEndPoint.Item1, previousEndPoint.Item2, sipPacket.CallID, sipPacket.From, sipPacket.To);

                                                    if (ft != null) {
                                                        }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    if (matchedTuple == null)
                                        this.callEndPoints[sipPacket.CallID].Add(endPoint);
                                    if (matchedTuple != null)
                                        this.callEndPoints[sipPacket.CallID].Remove(matchedTuple);
                                }
                                else
                                    this.callEndPoints.Add(sipPacket.CallID, new List<Tuple<System.Net.IPAddress, ushort, FiveTuple>>() { endPoint });

                            }

                        }
                            
                    }
                    parsedBytes += sipPacket.PacketLength;
                }
            }
            return parsedBytes;
        }



        public void Reset() {
            //this.endPointCandidates.Clear();
            this.callEndPoints.Clear();
        }

        #endregion
    }
}
