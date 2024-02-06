using System;
using System.Collections.Generic;
using System.Text;

using System.Net;

namespace PacketParser.Utils {
    public static class IpAddressUtil {

        //http://www.iana.org/assignments/ipv4-address-space
        private static List<byte> ipv4ReservedClassAList = new List<byte> { 0, /*10,*/ 127, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255 };
        private static List<IPAddress> ipv6reserved = new List<IPAddress> { IPAddress.IPv6Loopback, IPAddress.IPv6None };
        

        public static bool IsIanaReserved(IPAddress ipAddress) {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ipv6reserved.Contains(ipAddress))
                return true;
            byte[] ip=ipAddress.GetAddressBytes();
            if(ip.Length==4)//let's start with IPv4
                return ipv4ReservedClassAList.Contains(ip[0]);
            else
                return false;//unknown (no IPv6 db yet...
        }

        public static int CompareTo(this System.Net.IPAddress ipAddress, System.Net.IPAddress otherIpAddress) {
            if (ipAddress.AddressFamily != otherIpAddress.AddressFamily)
                return ipAddress.AddressFamily - otherIpAddress.AddressFamily;
            byte[] localBytes = ipAddress.GetAddressBytes();
            byte[] remoteBytes = otherIpAddress.GetAddressBytes();
            for (int i = 0; i < localBytes.Length; i++) {
                if (localBytes[i] != remoteBytes[i])
                    return localBytes[i] - remoteBytes[i];
            }
            return 0;
        }
    }
}
