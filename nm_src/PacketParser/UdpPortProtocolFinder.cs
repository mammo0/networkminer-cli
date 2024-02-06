using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class UdpPortProtocolFinder : IPortProtocolFinder {

        private static IPortProtocolFinder instance = null;

        public static IPortProtocolFinder Instance {
            get {
                if (instance == null)
                    instance = new UdpPortProtocolFinder();
                return instance;
            }
            set {
                instance = value;
            }
        }

        public static IUdpPayloadProtocolFinder PipiInstance { get; set; }

        public static bool IsSipPort(ushort port) {
            //https://supportdesk.win911.com/support/solutions/articles/24000038761-port-ranges-for-supported-sip-and-voip-providers
            //https://www.whichvoip.com/articles/sip-port-numbers-by-provider.htm
            if (port == 5060)
                return true;
            if(port >= 5060 && port <= 5082)//https://www.voiptalk.org/products/configuration-of-trixbox-behind-a-nat-firewall-setup.html
                return true;
            if (port >= 5196 && port <= 5199)//https://www.8x8.com/support/business-support/documentation/qos-settings
                return true;

            return false;
        }


        public PacketParser.ApplicationLayerProtocol GetApplicationLayerProtocol(PacketParser.FiveTuple.TransportProtocol transport, ushort sourcePort, ushort destinationPort) {
            if (destinationPort == 53 || sourcePort == 53 || destinationPort == 5353 || sourcePort == 5353 || destinationPort == 5355 || sourcePort == 5355) {
                //DNS
                //Multicast DNS (UDP 5353) http://www.multicastdns.org/
                //LLMNR DNS (UDP 5355)
                return ApplicationLayerProtocol.DNS;
            }
            else if (destinationPort == 67 || destinationPort == 68 || sourcePort == 67 || sourcePort == 68) {
                return ApplicationLayerProtocol.DHCP;
            }
            else if (destinationPort == 69 || sourcePort == 69) {
                return ApplicationLayerProtocol.TFTP;
            }
            else if(destinationPort == 88 || sourcePort == 88) {
                return ApplicationLayerProtocol.Kerberos;
            }
            else if (destinationPort == 137 || sourcePort == 137) {
                return ApplicationLayerProtocol.NetBiosNameService;
            }
            else if (destinationPort == 138 || sourcePort == 138) {
                return ApplicationLayerProtocol.NetBiosDatagramService;
            }
            else if (destinationPort == 161 || sourcePort == 161) {
                return ApplicationLayerProtocol.SNMP;
            }
            else if (destinationPort == 514 || sourcePort == 514) {
                return ApplicationLayerProtocol.Syslog;
            }
            else if (destinationPort == 1900 || sourcePort == 1900) {
                return ApplicationLayerProtocol.UPnP;
            }
            else if (destinationPort == 4789 || sourcePort == 4789 || destinationPort == 8472 || sourcePort == 8472) {
                return ApplicationLayerProtocol.VXLAN;
            }
            else if(destinationPort == 5246 || sourcePort == 5246 || destinationPort == 5247 || sourcePort == 5247)
                return ApplicationLayerProtocol.CAPWAP;
            else if (IsSipPort(destinationPort) || IsSipPort(sourcePort)) {
                return ApplicationLayerProtocol.SIP;
            }
            else {
                return ApplicationLayerProtocol.Unknown;
            }
        }
    }
}
