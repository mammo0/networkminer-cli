using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SshPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public override Type ParsedType { get { return typeof(Packets.SshPacket); } }

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Ssh; }
        }

        public SshPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty?
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            foreach (Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.SshPacket)) {
                    Packets.SshPacket sshPacket=(Packets.SshPacket)p;
                    tcpSession.Flow.FiveTuple.ClientHost.AddNumberedExtraDetail("SSH Version", sshPacket.SshVersion);
                    tcpSession.Flow.FiveTuple.ClientHost.AddNumberedExtraDetail("SSH Application", sshPacket.SshApplication);

                    return p.PacketLength;
                }
            }
            return 0;
        }

        public void Reset() {
            //do nothgin; no state...
        }

        #endregion
    }
}
