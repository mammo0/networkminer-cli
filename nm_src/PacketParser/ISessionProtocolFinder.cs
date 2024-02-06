using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {

    //this enum should probably be moved somewhere else...
    public enum ApplicationLayerProtocol {
        Unknown,
        BackConnect,//TCP
        BackConnectFileManager,//TCP
        BackConnectReverseShell,//TCP
        BackConnectReverseSocks,//TCP
        BackConnectReverseVNC,//TCP (reverse Rfb)
        CAPWAP,//UDP
        DHCP, //UDP
        DNS, //TCP or UDP
        FTP, //TCP
        HTTP, //TCP
        HTTP2, //TCP
        IRC, //TCP
        IEC_104, //TCP
        IMAP, //TCP
        Kerberos, //TCP or UDP
        LPD,
        Meterpreter,//TCP
        ModbusTCP, //TCP
        NetBiosNameService, //TCP or UDP
        NetBiosDatagramService, //UDP
        NetBiosSessionService, //TCP
        njRAT,//TCP
        OpenFlow, //TCP
        Oscar, //TCP
        OscarFileTransfer, //TCP
        POP3, //TCP
        VNC,//TCP
        RTP,//TCP
        SIP, //UDP
        SMTP, //TCP
        SNMP,//UDP
        SOCKS, //TCP
        SpotifyServerProtocol, //TCP
        SSH, //TCP
        SSL, //TCP
        Syslog, //UDP
        TabularDataStream, //TCP
        TFTP, //UDP
        TPKT, //TCP
        UPnP, //UDP
        VXLAN//UDP
    }

    //public enum TransportLayerProtocol { UDP, TCP }

    public interface ISessionProtocolFinder {
        PacketParser.NetworkHost Server { get;}
        PacketParser.NetworkHost Client { get;}
        ushort ServerPort { get;}
        ushort ClientPort { get;}
        //TransportLayerProtocol TransportLayerProtocol { get; }
        NetworkFlow Flow { get; }

        //PacketParser.ApplicationLayerProtocol ConfirmedApplicationLayerProtocol{ get; set;}
        PacketParser.ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol();
        void SetConfirmedApplicationLayerProtocol(PacketParser.ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint);


        void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, PacketParser.NetworkHost source, PacketParser.NetworkHost destination);
        IEnumerable<PacketParser.ApplicationLayerProtocol> GetProbableApplicationLayerProtocols();
        

    }
}
