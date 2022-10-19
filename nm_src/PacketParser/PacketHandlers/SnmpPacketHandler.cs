using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SnmpPacketHandler : AbstractPacketHandler, IPacketHandler {


        public override Type ParsedType { get { return typeof(Packets.SnmpPacket); } }

        public SnmpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            Packets.SnmpPacket snmpPacket = null;
            Packets.UdpPacket udpPacket = null;

            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.SnmpPacket))
                    snmpPacket = (Packets.SnmpPacket)p;
                else if (p.GetType() == typeof(Packets.UdpPacket))
                    udpPacket = (Packets.UdpPacket)p;

                if (snmpPacket != null && udpPacket != null) {
                    string packetDescription = "SNMP";
                    if (Enum.IsDefined(typeof(Packets.SnmpPacket.Version), snmpPacket.VersionRaw))
                        packetDescription = Enum.GetName(typeof(Packets.SnmpPacket.Version), snmpPacket.VersionRaw);
                    System.Collections.Specialized.NameValueCollection tmpCol = new System.Collections.Specialized.NameValueCollection();

                    if (!string.IsNullOrEmpty(snmpPacket.CommunityString)) {
                        tmpCol.Add("SNMP community", snmpPacket.CommunityString);
                        base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, packetDescription, "SNMP community", snmpPacket.CommunityString, snmpPacket.ParentFrame.Timestamp));
                    }
                    foreach(string snmpString in snmpPacket.CarvedStrings) {
                        if (!string.IsNullOrEmpty(snmpString)) {
                            string SNMP_PARAMETER = "SNMP parameter";
                            tmpCol.Add(SNMP_PARAMETER, snmpString);

                            //https://opensource.apple.com/source/cups/cups-218/cups/backend/snmp.txt.auto.html
                            if (snmpString.StartsWith("MFG:"))
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);
                            else if(snmpString.IndexOf("printer", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);
                            else if (snmpString.IndexOf("MANUFACTURER", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);
                            else if (snmpString.IndexOf("JETDIRECT", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);
                            else if (snmpString.IndexOf("http", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);
                            else if (snmpString.IndexOf("Firmware", StringComparison.InvariantCultureIgnoreCase) >= 0)
                                sourceHost.AddNumberedExtraDetail(SNMP_PARAMETER, snmpString);

                        }
                    }
                    if(tmpCol.Count > 0)
                        base.MainPacketHandler.OnParametersDetected(new PacketParser.Events.ParametersEventArgs(snmpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, udpPacket.TransportProtocol, udpPacket.SourcePort, udpPacket.DestinationPort, tmpCol, snmpPacket.ParentFrame.Timestamp, packetDescription));
                }
                
            }
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
