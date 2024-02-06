//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public class PacketReceivedEventArgs : EventArgs {

        public enum PacketTypes {
            NullLoopback,
            Ethernet2Packet,
            IPv4Packet,
            IPv6Packet,
            IEEE_802_11Packet,
            IEEE_802_11RadiotapPacket,
            CiscoHDLC,
            LinuxCookedCapture,
            LinuxCookedCapture2,
            PrismCaptureHeader
        };

        public DateTime Timestamp { get; }
        public byte[] Data { get; }
        public PacketTypes PacketType { get; }

        public PacketReceivedEventArgs(byte[] data, DateTime timestamp, PacketTypes packetType) {
            this.Data = data;
            this.Timestamp = timestamp.ToUniversalTime();
            this.PacketType = packetType;
        }

    }

    public delegate void PacketReceivedHandler(object sender, PacketReceivedEventArgs e);

}
