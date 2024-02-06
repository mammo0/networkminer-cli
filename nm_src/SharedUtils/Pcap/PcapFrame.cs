using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public class PcapFrame {

        public enum DataLinkTypeEnum : uint {
            WTAP_ENCAP_NULL = 0,/* null encapsulation */
            WTAP_ENCAP_ETHERNET = 1,
            WTAP_ENCAP_TOKEN_RING = 6,/* IEEE 802 Networks - assume token ring */
            WTAP_ENCAP_ARCNET = 7,
            WTAP_ENCAP_SLIP = 8,
            WTAP_ENCAP_PPP = 9,
            WTAP_ENCAP_FDDI = 10,

            WTAP_ENCAP_ATM_RFC1483_2 = 11,
            WTAP_ENCAP_RAW_IP_2 = 12,
            WTAP_ENCAP_ATM_RFC1483_3 = 13,
            WTAP_ENCAP_RAW_IP_3 = 14,
            WTAP_ENCAP_LINUX_ATM_CLIP_2 = 16,
            WTAP_ENCAP_OLD_PFLOG = 17,
            WTAP_ENCAP_LINUX_ATM_CLIP_3 = 18,
            WTAP_ENCAP_LINUX_ATM_CLIP_4 = 19,

            WTAP_ENCAP_REDBACK = 32,
            WTAP_ENCAP_PPP_2 = 50,
            WTAP_ENCAP_SYMANTEC = 99,/* Apparently used by the Axent Raptor firewall (now Symantec Enterprise Firewall). */
            WTAP_ENCAP_ATM_RFC1483 = 100,/*libpcap 0.5 and later*/
            WTAP_ENCAP_RAW_IP = 101,
            WTAP_ENCAP_SLIP_BSDOS = 102,
            WTAP_ENCAP_PPP_BSDOS = 103,
            WTAP_ENCAP_CHDLC = 104,/* Cisco HDLC */
            WTAP_ENCAP_IEEE_802_11 = 105, /* IEEE 802.11 */
            WTAP_ENCAP_LINUX_ATM_CLIP = 106,
            WTAP_ENCAP_FRELAY = 107,/* Frame Relay */
            WTAP_ENCAP_NULL_2 = 108,	/* OpenBSD loopback */
            WTAP_ENCAP_ENC = 109,	/* OpenBSD IPSEC enc */
            WTAP_ENCAP_LANE_802_3 = 110,/* ATM LANE 802.3 */
            WTAP_ENCAP_HIPPI = 111,	/* NetBSD HIPPI */
            WTAP_ENCAP_CHDLC_2 = 112,	/* NetBSD HDLC framing */

            WTAP_ENCAP_SLL = 113,/* Linux cooked capture */

            WTAP_ENCAP_LOCALTALK = 114,	/* Localtalk */
            WTAP_ENCAP_PFLOG = 117,
            WTAP_ENCAP_CISCO_IOS = 118,
            WTAP_ENCAP_PRISM_HEADER = 119, /* Prism monitor mode hdr */
            WTAP_ENCAP_HHDLC = 121,	/* HiPath HDLC */
            WTAP_ENCAP_IP_OVER_FC = 122,   /* RFC 2625 IP-over-FC */
            WTAP_ENCAP_ATM_PDUS = 123,  /* SunATM */
            WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP = 127,  /* 802.11 plus radiotap WLAN header */
            WTAP_ENCAP_TZSP = 128,	/* Tazmen Sniffer Protocol */
            WTAP_ENCAP_ARCNET_LINUX = 129,
            WTAP_ENCAP_JUNIPER_MLPPP = 130, /* Juniper MLPPP on ML-, LS-, AS- PICs */
            WTAP_ENCAP_JUNIPER_MLFR = 131, /* Juniper MLFR (FRF.15) on ML-, LS-, AS- PICs */
            WTAP_ENCAP_JUNIPER_GGSN = 133,
            /*
             * Values 132-134, 136 not listed here are reserved for use
             * in Juniper hardware.
             */
            WTAP_ENCAP_JUNIPER_ATM2 = 135, /* various encapsulations captured on the ATM2 PIC */
            WTAP_ENCAP_JUNIPER_ATM1 = 137, /* various encapsulations captured on the ATM1 PIC */

            WTAP_ENCAP_APPLE_IP_OVER_IEEE1394 = 138,
            /* Apple IP-over-IEEE 1394 */

            WTAP_ENCAP_MTP2_WITH_PHDR = 139,
            WTAP_ENCAP_MTP2 = 140,
            WTAP_ENCAP_MTP3 = 141,
            WTAP_ENCAP_DOCSIS = 143,
            WTAP_ENCAP_IRDA = 144,	/* IrDA capture */

            /* Reserved for private use. */
            WTAP_ENCAP_USER0 = 147,
            WTAP_ENCAP_USER1 = 148,
            WTAP_ENCAP_USER2 = 149,
            WTAP_ENCAP_USER3 = 150,
            WTAP_ENCAP_USER4 = 151,
            WTAP_ENCAP_USER5 = 152,
            WTAP_ENCAP_USER6 = 153,
            WTAP_ENCAP_USER7 = 154,
            WTAP_ENCAP_USER8 = 155,
            WTAP_ENCAP_USER9 = 156,
            WTAP_ENCAP_USER10 = 157,
            WTAP_ENCAP_USER11 = 158,
            WTAP_ENCAP_USER12 = 159,
            WTAP_ENCAP_USER13 = 160,
            WTAP_ENCAP_USER14 = 161,
            WTAP_ENCAP_USER15 = 162,

            WTAP_ENCAP_IEEE_802_11_WLAN_AVS = 163,  /* 802.11 plus AVS WLAN header */

            /*
             * 164 is reserved for Juniper-private chassis-internal
             * meta-information such as QoS profiles, etc..
             */

            WTAP_ENCAP_BACNET_MS_TP = 165,

            /*
             * 166 is reserved for a PPP variant in which the first byte
             * of the 0xff03 header, the 0xff, is replaced by a direction
             * byte.  I don't know whether any captures look like that,
             * but it is used for some Linux IP filtering (ipfilter?).
             */

            /* Ethernet PPPoE frames captured on a service PIC */
            WTAP_ENCAP_JUNIPER_PPPOE = 167,

            /*
         * 168 is reserved for more Juniper private-chassis-
         * internal meta-information.
         */

            WTAP_ENCAP_GPRS_LLC = 169,

            /*
             * 170 and 171 are reserved for ITU-T G.7041/Y.1303 Generic
             * Framing Procedure.
             */

            /* Registered by Gcom, Inc. */
            WTAP_GCOM_TIE1 = 172,
            WTAP_GCOM_SERIAL = 173,

            WTAP_ENCAP_LINUX_LAPD = 177,


            WTAP_ENCAP_JUNIPER_ETHER = 178, /* Ethernet frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_PPP = 179,/* PPP frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_FRELAY = 180,/* Frame-Relay frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_CHDLC = 181,/* C-HDLC frames prepended with meta-information */
            WTAP_ENCAP_JUNIPER_VP = 183,/* VOIP Frames prepended with meta-information */


            WTAP_ENCAP_USB = 186,	            /* raw USB packets */
            WTAP_ENCAP_BLUETOOTH_H4 = 187,      /* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
            WTAP_ENCAP_IEEE802_16_MAC_CPS = 188,/* IEEE 802.16 MAC Common Part Sublayer */
            WTAP_ENCAP_USB_LINUX = 189,         /* USB packets with Linux-specified header */

            WTAP_ENCAP_PPI = 192,     /* Per-Packet Information header */

            /*
             * == THIS IS A QUOTE FROM "pcap-common.c" IN THE WIRESHARK PROJECT ==
             * 
             * Either LBL NRG wasn't an adequate central registry (e.g., because of
             * the slow rate of releases from them), or nobody bothered using them
             * as a central registry, as many different groups have patched libpcap
             * (and BPF, on the BSDs) to add new encapsulation types, and have ended
             * up using the same DLT_ values for different encapsulation types.
             *
             * For those numerical encapsulation type values that everybody uses for
             * the same encapsulation type (which inclues those that some platforms
             * specify different DLT_ names for but don't appear to use), we map
             * those values to the appropriate Wiretap values.
             *
             * For those numerical encapsulation type values that different libpcap
             * variants use for different encapsulation types, we check what
             * <pcap.h> defined to determine how to interpret them, so that we
             * interpret them the way the libpcap with which we're building
             * Wireshark/Wiretap interprets them (which, if it doesn't support
             * them at all, means we don't support them either - any capture files
             * using them are foreign, and we don't hazard a guess as to which
             * platform they came from; we could, I guess, choose the most likely
             * platform).
             *
             * Note: if you need a new encapsulation type for libpcap files, do
             * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
             * add a new encapsulation type by changing an existing entry;
             * leave the existing entries alone.
             *
             * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking for
             * a new DLT_ value, and specifying the purpose of the new value.  When
             * you get the new DLT_ value, use that numerical value in the "dlt_value"
             * field of "pcap_to_wtap_map[]".
             */

            WTAP_ENCAP_IEEE802_15_4 = 195,  /* IEEE 802.15.4 Wireless PAN */
            WTAP_ENCAP_SITA = 196, /* SITA File Encapsulation */
            WTAP_ENCAP_ERF = 197,   /* Endace Record File Encapsulation */
            WTAP_ENCAP_IPMB = 199,  /* IPMB */
            WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR = 201,    /* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
            WTAP_ENCAP_LAPD = 203, /* LAPD frame */
            WTAP_ENCAP_PPP_WITH_PHDR = 204, /* PPP with pseudoheader */
            WTAP_ENCAP_I2C = 209,   /* IPMB/I2C */
            WTAP_ENCAP_FLEXRAY = 210,   /* FlexRay frame */
            WTAP_ENCAP_MOST = 211,  /* MOST frame */
            WTAP_ENCAP_LIN = 212, /* LIN frame */
            WTAP_ENCAP_X2E_SERIAL = 213,    /* X2E Xoraya serial frame */
            WTAP_ENCAP_X2E_XORAYA = 214, /* X2E Xoraya frame */
            WTAP_ENCAP_IEEE802_15_4_NONASK_PHY = 215,   /* IEEE 802.15.4 Wireless PAN non-ASK PHY */
            WTAP_ENCAP_USB_LINUX_MMAPPED = 220, /* USB packets with padded Linux-specified header */
            WTAP_ENCAP_FIBRE_CHANNEL_FC2 = 224, /* Fibre Channel FC-2 frame */
            WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS = 225,   /* Fibre Channel FC-2 frame with Delimiter */
            WTAP_ENCAP_IPNET = 226, /* Solaris IPNET */
            WTAP_ENCAP_SOCKETCAN = 227, /* SocketCAN frame */
            WTAP_ENCAP_RAW_IP4 = 228, /* Raw IPv4 */
            WTAP_ENCAP_RAW_IP6 = 229,   /* Raw IPv6 */
            WTAP_ENCAP_IEEE802_15_4_NOFCS = 230, /* IEEE 802.15.4 Wireless PAN no fcs */
            WTAP_ENCAP_DVBCI = 235, /* DVB-CI (Common Interface) */
            WTAP_ENCAP_MUX27010 = 236, /* MUX27010 */

            //from tcpdump's pcap-common.h or Wireshark's pcap-common.c
            WTAP_ENCAP_STANAG_5066_D_PDU = 237,
            WTAP_ENCAP_JUNIPER_ATM_CEMIC = 238,
            WTAP_ENCAP_NFLOG = 239,
            WTAP_ENCAP_NETANALYZER = 240,
            WTAP_ENCAP_NETANALYZER_TRANSPARENT = 241,
            WTAP_ENCAP_IPOIB = 242,
            WTAP_ENCAP_MPEG_2_TS = 243,
            WTAP_ENCAP_NG40 = 244,
            WTAP_ENCAP_NFC_LLCP = 245,
            WTAP_ENCAP_PFSYNC = 246,
            WTAP_ENCAP_INFINIBAND = 247,
            WTAP_ENCAP_SCTP = 248,
            WTAP_ENCAP_USBPCAP = 249,
            WTAP_ENCAP_RTAC_SERIAL = 250,
            WTAP_ENCAP_BLUETOOTH_LE_LL = 251,
            WTAP_ENCAP_WIRESHARK_UPPER_PDU = 252,
            WTAP_ENCAP_NETLINK = 253,
            WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR = 254,
            WTAP_ENCAP_BLUETOOTH_BREDR_BB = 255,
            WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR = 256,
            WTAP_ENCAP_PROFIBUS_DL = 257,
            WTAP_ENCAP_PKTAP = 258,
            WTAP_ENCAP_EPON = 259,
            WTAP_ENCAP_IPMI_HPM_2 = 260,
            WTAP_ENCAP_ZWAVE_R1_R2 = 261,
            WTAP_ENCAP_ZWAVE_R3 = 262,
            WTAP_ENCAP_WATTSTOPPER_DLM = 263,
            WTAP_ENCAP_ISO_14443 = 264,
            WTAP_ENCAP_RDS = 265,
            WTAP_ENCAP_USB_DARWIN = 266,
            WTAP_ENCAP_OPENFLOW = 267,
            WTAP_ENCAP_SDLC = 268,
            WTAP_ENCAP_TI_LLN_SNIFFER = 269,
            WTAP_ENCAP_LORATAP = 270,
            WTAP_ENCAP_VSOCK = 271,
            WTAP_ENCAP_NORDIC_BLE = 272,
            WTAP_ENCAP_DOCSIS31_XRA31 = 273,
            WTAP_ENCAP_ETHERNET_MPACKET = 274,
            WTAP_ENCAP_DISPLAYPORT_AUX = 275,
            WTAP_ENCAP_LINUX_SLL2 = 276,  //Linux cooked capture v2
            WTAP_ENCAP_SERCOS_MONITOR = 277,
            WTAP_ENCAP_OPENVIZSLA = 278,
            WTAP_ENCAP_EBHSCR = 279,
            WTAP_ENCAP_VPP_DISPATCH = 280,
            WTAP_ENCAP_DSA_TAG_BRCM = 281,
            WTAP_ENCAP_DSA_TAG_BRCM_PREPEND = 282,
            WTAP_ENCAP_IEEE802_15_4_TAP = 283,
            WTAP_ENCAP_DSA_TAG_DSA = 284,
            WTAP_ENCAP_DSA_TAG_EDSA = 285,
            WTAP_ENCAP_ELEE = 286,
            WTAP_ENCAP_Z_WAVE_SERIAL = 287,
            WTAP_ENCAP_USB_2_0 = 288,
            WTAP_ENCAP_ATSC_ALP = 289,
            WTAP_ENCAP_ETW = 290,
            WTAP_ENCAP_MATCHING_MAX = 290
        }

        public static DataLinkTypeEnum GetDataLinkType(uint linkTypeValue) {
            
            if (!Enum.IsDefined(typeof(DataLinkTypeEnum), linkTypeValue))
                System.Diagnostics.Debugger.Break();
            return (DataLinkTypeEnum)linkTypeValue;
        }

        private DateTime timestamp;
        private byte[] data;
        private DataLinkTypeEnum dataLinkType;

        public object Tag { get; set; }

        public DateTime Timestamp { get { return timestamp; } }
        public byte[] Data { get { return data; } }
        public DataLinkTypeEnum DataLinkType { get { return this.dataLinkType; } }

        public PcapFrame(DateTime timestamp, byte[] data, DataLinkTypeEnum dataLinkType) {
            
            this.timestamp=timestamp;
            this.data=data;
            this.dataLinkType = dataLinkType;
        }
    }
}
