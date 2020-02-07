using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser {
    public interface IUdpPayloadProtocolFinder {

        PacketParser.ApplicationLayerProtocol GetApplicationLayerProtocol(Packets.UdpPacket udpPacket);

        void SetPayload(System.Net.IPAddress sourceIP, ushort sourcePort, System.Net.IPAddress destinationIP, ushort destinationPort, ApplicationLayerProtocol protocol);
    }
}
