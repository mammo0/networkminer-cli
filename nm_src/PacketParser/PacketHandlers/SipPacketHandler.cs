using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class SipPacketHandler : AbstractPacketHandler, IPacketHandler, ITcpSessionPacketHandler {

        //private const string INVITE = "INVITE";
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
            //Packets.ITransportLayerPacket transportLayerPacket = null;
            FiveTuple ft = null;
            foreach (Packets.AbstractPacket p in packetList) {
                
                if (p is Packets.ITransportLayerPacket transportLayerPacket) {
                    //transportLayerPacket = (Packets.ITransportLayerPacket)p;
                    if (transportLayerPacket is Packets.UdpPacket)
                        ft = new FiveTuple(sourceHost, transportLayerPacket.SourcePort, destinationHost, transportLayerPacket.DestinationPort, FiveTuple.TransportProtocol.UDP);
                    else if (transportLayerPacket is Packets.TcpPacket)
                        ft = new FiveTuple(sourceHost, transportLayerPacket.SourcePort, destinationHost, transportLayerPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                }
                if(p is Packets.SipPacket sipPacket) {
                    //Packets.SipPacket sipPacket=(Packets.SipPacket)p;
                    System.Collections.Specialized.NameValueCollection nvc = new System.Collections.Specialized.NameValueCollection();
                    if (sipPacket.RequestMethod != null) {
                        nvc.Add(sipPacket.RequestMethod.ToString(), sipPacket.MessageLine.Substring(sipPacket.RequestMethod.ToString().Length).Trim());

                        if (sipPacket.From != null && sipPacket.From.Length > 0)
                            sourceHost.AddNumberedExtraDetail("SIP User", this.ExtractSipAddressFromHeader(sipPacket.From));

                        if (sipPacket.Contact?.Length > 0)
                            sourceHost.AddNumberedExtraDetail("SIP User", this.ExtractSipAddressFromHeader(sipPacket.Contact));

                        //if (sipPacket.MessageLine.StartsWith(INVITE)) {
                        if (sipPacket.RequestMethod == SipPacket.RequestMethods.INVITE) {
                            string to = null;
                            string from = null;
                            if (sipPacket.To != null && sipPacket.To.Length > 0)
                                destinationHost.AddNumberedExtraDetail("SIP User", this.ExtractSipAddressFromHeader(sipPacket.To));

                            if (ft != null && to != null && from != null && !String.IsNullOrEmpty(sipPacket.CallID)) {
                                nvc.Add("From", sipPacket.From);
                                nvc.Add("To", sipPacket.To);
                                nvc.Add("Call-ID", sipPacket.CallID);
                            }
                        }
                        else if(sipPacket.RequestMethod == SipPacket.RequestMethods.MESSAGE) {
                            if(sipPacket.ContentLength > 0 && sipPacket.ContentType.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase)) {
                                string message = Encoding.UTF8.GetString(sipPacket.ParentFrame.Data, sipPacket.MessageBodyStartIndex, sipPacket.ContentLength);
                                //sipPacket.ParentFrame.Data. sipPacket.MessageBodyStartIndex
                                string to = this.ExtractSipAddressFromHeader(sipPacket.To);
                                string from = this.ExtractSipAddressFromHeader(sipPacket.From);
                                string callId = sipPacket.CallID;
                                
                                if (message?.Length > 0) {
                                    if (callId == null || callId.Length == 0)
                                        callId = message;
                                    this.MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(ApplicationLayerProtocol.Sip, sourceHost, destinationHost, sipPacket.ParentFrame.FrameNumber, sipPacket.ParentFrame.Timestamp, from, to, callId, message, sipPacket.HeaderFields, sipPacket.PacketLength));
                                }
                            }
                        }

                    }
                    nvc.Add(sipPacket.HeaderFields);
                    //Extract SIP headers like "X-msisdn" and "X-user-id" as explained by Sandro Gauci here: https://www.rtcsec.com/2020/09/01-smuggling-sip-headers-ftw/
                    foreach (string interestingSipHeader in sipPacket.HeaderFields.AllKeys.Where(k => k.Trim().StartsWith("X-", StringComparison.InvariantCultureIgnoreCase))) {
                        sourceHost.AddNumberedExtraDetail("SIP header: " + interestingSipHeader, sipPacket.HeaderFields[interestingSipHeader]);
                    }

                    if (ft != null && nvc?.Count > 0)
                        this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(sipPacket.ParentFrame.FrameNumber, ft, true, nvc, sipPacket.ParentFrame.Timestamp, "SIP session " + ft.ToString()));
                    if (!String.IsNullOrEmpty(sipPacket.UserAgent)) {
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
                                                    this.MainPacketHandler.OnVoipCallDetected(sipPacket.SDP.IP, sipPacket.SDP.Port.Value, previousEndPoint.Item1, previousEndPoint.Item2, sipPacket.CallID, this.ExtractSipAddressFromHeader(sipPacket.From), this.ExtractSipAddressFromHeader(sipPacket.To));
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

        private string ExtractSipAddressFromHeader(string addressInHeader) {
            if (addressInHeader.Contains(";"))
                addressInHeader = addressInHeader.Substring(0, addressInHeader.IndexOf(';'));
            if (addressInHeader.Contains("<"))
                addressInHeader = addressInHeader.Substring(addressInHeader.IndexOf('<') + 1);
            if(addressInHeader.Contains(">"))
                addressInHeader = addressInHeader.Substring(0, addressInHeader.IndexOf('>'));
            if (addressInHeader.StartsWith("sip:", StringComparison.OrdinalIgnoreCase))
                addressInHeader = addressInHeader.Substring(4);
            return addressInHeader;
        }



        public void Reset() {
            //this.endPointCandidates.Clear();
            this.callEndPoints.Clear();
        }

        #endregion
    }
}
