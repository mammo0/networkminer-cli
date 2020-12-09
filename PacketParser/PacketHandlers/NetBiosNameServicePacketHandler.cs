//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class NetBiosNameServicePacketHandler : AbstractPacketHandler, IPacketHandler {


        public override Type ParsedType { get { return typeof(Packets.NetBiosNameServicePacket); } }

        public NetBiosNameServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //do nothing more
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {

            //Packets.IIPPacket ipPacket = null;
            Packets.ITransportLayerPacket transportLayerPacket = null;

            foreach (Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.NetBiosNameServicePacket))
                    ExtractData((Packets.NetBiosNameServicePacket)p, sourceHost, destinationHost, transportLayerPacket);
                /*else if (p is Packets.IIPPacket)
                    ipPacket = (Packets.IIPPacket)p;*/
                else if (p is Packets.ITransportLayerPacket tlp)
                    transportLayerPacket = tlp;
            }
        }

        private void ExtractData(Packets.NetBiosNameServicePacket netBiosNameServicePacket, NetworkHost sourceHost, NetworkHost destinationHost, Packets.ITransportLayerPacket transportLayerPacket) {
            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
            if (netBiosNameServicePacket.QueriedNetBiosName != null) {
                sourceHost.AddQueriedNetBiosName(netBiosNameServicePacket.QueriedNetBiosName);
                parameters.Add("NetBIOS Query", netBiosNameServicePacket.QueriedNetBiosName);
            }
            /*
            if(netBiosNameServicePacket.AnsweredNetBiosName!=null) {
                parameters.Add(netBiosNameServicePacket.AnsweredNetBiosName, netBiosNameServicePacket.AnsweredIpAddress.ToString());
                if (base.MainPacketHandler.NetworkHostList.ContainsIP(netBiosNameServicePacket.AnsweredIpAddress))
                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(netBiosNameServicePacket.AnsweredIpAddress).AddHostName(netBiosNameServicePacket.AnsweredNetBiosName);
            }
            */
            foreach(Packets.NetBiosNameServicePacket.ResourceRecord answer in netBiosNameServicePacket.AnswerResourceRecords) {
                UInt16 flags = Utils.ByteConverter.ToUInt16(answer.Data.Array, answer.Data.Offset);
                byte[] ipBytes = new byte[4];//IP4...
                Array.Copy(answer.Data.Array, answer.Data.Offset + 2, ipBytes, 0, ipBytes.Length);
                System.Net.IPAddress answeredIpAddress = new System.Net.IPAddress(ipBytes);

                parameters.Add(answer.Name, answeredIpAddress.ToString());
                if (base.MainPacketHandler.NetworkHostList.ContainsIP(answeredIpAddress))
                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(answeredIpAddress).AddHostName(answer.NameTrimmed, netBiosNameServicePacket.PacketTypeDescription);
            }
            foreach (Packets.NetBiosNameServicePacket.ResourceRecord additional in netBiosNameServicePacket.AdditionalResourceRecords) {
                UInt16 flags = Utils.ByteConverter.ToUInt16(additional.Data.Array, additional.Data.Offset);
                if(additional.Type == 32 && additional.Class == 1 && (flags & 0x8000) == 0 && (additional.Name.EndsWith("<00>") || additional.Name.EndsWith("<20>"))) {
                    //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
                    //unique name with IP
                    byte[] ipBytes = new byte[4];//IP4...
                    Array.Copy(additional.Data.Array, additional.Data.Offset + 2, ipBytes, 0, ipBytes.Length);
                    System.Net.IPAddress answeredIpAddress = new System.Net.IPAddress(ipBytes);

                    parameters.Add(additional.Name, answeredIpAddress.ToString());
                    if (base.MainPacketHandler.NetworkHostList.ContainsIP(answeredIpAddress))
                        base.MainPacketHandler.NetworkHostList.GetNetworkHost(answeredIpAddress).AddHostName(additional.NameTrimmed, netBiosNameServicePacket.PacketTypeDescription);
                }

                
            }
            if (parameters.Count > 0 && transportLayerPacket != null) {
                if(netBiosNameServicePacket.Flags.Response)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Response"));
                else if(netBiosNameServicePacket.Flags.OperationCode == (byte)Packets.NetBiosNameServicePacket.HeaderFlags.OperationCodes.registration)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Registration"));
                else if(netBiosNameServicePacket.Flags.OperationCode == (byte)Packets.NetBiosNameServicePacket.HeaderFlags.OperationCodes.query)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Query"));
                else
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(netBiosNameServicePacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, netBiosNameServicePacket.ParentFrame.Timestamp, "NBNS Message"));
            }
        }

        public void Reset() {
            //empty
        }

        #endregion
    }
}
