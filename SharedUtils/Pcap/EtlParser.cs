using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;



namespace SharedUtils.Pcap {
    //TODO: Replace System.Diagnostics.Eventing.Reader with Microsoft.Diagnostics.Tracing unless that doesn't mess up Mono execution too much
    //https://github.com/microsoft/dotnet-samples/blob/master/Microsoft.Diagnostics.Tracing/TraceEvent/docs/TraceEvent.md
    public class EtlParser : IPcapParser, IDisposable {
        private const string NDIS_PROVIDER_NAME = "Microsoft-Windows-NDIS-PacketCapture";
        private static readonly Guid NDIS_PROVIDER_GUID = new Guid("{2ed6006e-4729-4609-b423-3ee7bcd678ef}");
        const long NDIS_PACKET_START = 0x40000000;
        const long NDIS_PACKET_END = 0x80000000;

        private const string PKTMON_PROVIDER_NAME = "Microsoft-Windows-PktMon";
        private static readonly Guid PKTMON_PROVIDER_GUI = new Guid("{4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac}");
        const long PKTMON_PACKET = 0x10;
        /**
         * 0x01 = UINT64 Config:1
         * 0x02 = UINT64 Rundown:1
         * 0x04 = UINT64 NblParsed:1
         * 0x08 = UINT64 NblInfo:1
         * 0x10 = UINT64 Payload:1
         * UINT64 Reserved1:59
         */


        enum EtlLinkLayerFlag : long {
            Ethernet = 0x1,
            WWAN = 0x200,
            Tunnel = 0x8000,
            WiFi = 0x10000,
            VMSwitch = 0x1000000
        };

        //https://github.com/microsoft/NetMon_Parsers_for_PacketMon/blob/main/etl_Microsoft-Windows-PktMon-Events.npl
        enum PktMonPacketType : ushort {
            Unknown = 0,
		    Ethernet = 1,
		    WiFi = 2,
		    MBB = 3
        }

        public IList<PcapFrame.DataLinkTypeEnum> DataLinkTypes {
            get {
                return new[] {
                    PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET,
                    PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11,
                    PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP
                    };
            }
        }

        public List<KeyValuePair<string, string>> Metadata {
            get {
                return new List<KeyValuePair<string, string>>();
            }
        }




        //System.Diagnostics.Eventing.Reader is not available in Mono or .NET Core. Only in .NET framework and Windows Desktop!
#if NETFRAMEWORK

        private System.Diagnostics.Eventing.Reader.EventLogReader eventLogReader;
        private readonly System.Text.RegularExpressions.Regex eventPayloadRegex = new System.Text.RegularExpressions.Regex("<EventPayload>([0-9A-F]+)</EventPayload>");

        public EtlParser(string etlFilePathOrEventLogName) {
            if(System.IO.File.Exists(etlFilePathOrEventLogName))
                this.eventLogReader = new System.Diagnostics.Eventing.Reader.EventLogReader(etlFilePathOrEventLogName, System.Diagnostics.Eventing.Reader.PathType.FilePath);
            else
                this.eventLogReader = new System.Diagnostics.Eventing.Reader.EventLogReader(etlFilePathOrEventLogName);

            //System.Diagnostics.Tracing.EventSource source;
            //source = new System.Diagnostics.Tracing.EventSource()
        }

        public void Dispose() {
            this.eventLogReader.Dispose();
        }

        public Task<PcapFrame> ReadPcapPacketAsync(CancellationToken cancellationToken) {
            return Task.Run(() => this.ReadPcapPacketBlocking());
        }

        private bool IsNdisPacket(System.Diagnostics.Eventing.Reader.EventRecord evt) {
            if (evt.ProviderId != NDIS_PROVIDER_GUID && evt.ProviderName != NDIS_PROVIDER_NAME)
                return false;
            else if ((evt.Keywords.Value & NDIS_PACKET_START) != 0)
                return true;
            else if ((evt.Keywords.Value & NDIS_PACKET_END) != 0)
                return true;
            else
                return false;
        }

        private bool IsPktMonPacket(System.Diagnostics.Eventing.Reader.EventRecord evt) {
            if (evt.ProviderId != PKTMON_PROVIDER_GUI && evt.ProviderName != PKTMON_PROVIDER_NAME)
                return false;
            else if ((evt.Keywords.Value & PKTMON_PACKET) != 0)
                return true;
            else
                return false;
        }

        private PcapFrame.DataLinkTypeEnum GetDataLinkType(long keywords) {
            if ((keywords & (long)EtlLinkLayerFlag.Ethernet) != 0)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            else if ((keywords & (long)EtlLinkLayerFlag.WiFi) != 0)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11;
            else if ((keywords & (long)EtlLinkLayerFlag.WWAN) != 0)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP;
            else if ((keywords & (long)EtlLinkLayerFlag.Tunnel) != 0) {
                Logger.Log("ETL Tunnel packet is assigned as RAW_IP", Logger.EventLogEntryType.Information);
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP;
            }
            else if ((keywords & (long)EtlLinkLayerFlag.VMSwitch) != 0) {
                Logger.Log("ETL VMSwitch packet is assigned as ETHERNET", Logger.EventLogEntryType.Information);
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            }
            else {
                Logger.Log("Unknown Data Link Type for ETL Keyword 0x" + keywords.ToString("X16"), Logger.EventLogEntryType.Warning);
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            }
        }

        private PcapFrame.DataLinkTypeEnum GetDataLinkType(ushort packetmonPacketType) {
            if (packetmonPacketType == (ushort)PktMonPacketType.Ethernet)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            else if (packetmonPacketType == (ushort)PktMonPacketType.WiFi)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11;
            else if (packetmonPacketType == (ushort)PktMonPacketType.MBB)
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP;//just guessing here!
            else {
                Logger.Log("Unknown Data Link Type for PacketMon PacketType 0x" + packetmonPacketType.ToString("X2"), Logger.EventLogEntryType.Warning);
                return PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET;
            }
        }

        public PcapFrame ReadPcapPacketBlocking() {
            System.Diagnostics.Eventing.Reader.EventRecord evt;
            while ((evt = this.eventLogReader.ReadEvent()) != null) {
                if(this.IsNdisPacket(evt)) {

                    PcapFrame.DataLinkTypeEnum linkLayer = this.GetDataLinkType(evt.Keywords.GetValueOrDefault());

                    if (evt.Properties?.Count >= 4) {
                        //short? opcode = evt.Opcode;//packet=0, other=0x02/0x21/0x22/0x23
                        //string opcodeName = evt.OpcodeDisplayName;//Info
                        //int? qualifiers = evt.Qualifiers;//null?
                        /**
                         * ==Properties== length=4
                         * [0] = MiniportIfIndex
                         * [1] = LowerIfIndex
                         * [2] = uint FragmentSize
                         * [3] = byte[] Fragment
                         * [4] = GftFlowEntryId (0)
                         * [5] = GftOffloadInformation (0)
                         **/

                        if (evt.Properties[2]?.Value is uint && evt.Properties[3]?.Value is byte[]) {
                            uint length = (uint)evt.Properties[2].Value;
                            if (length > 16) {
                                byte[] frameData = (byte[])evt.Properties[3].Value;
                                return new PcapFrame(evt.TimeCreated.Value.ToUniversalTime(), frameData, linkLayer);
                            }
                        }
                    }
                    else {
                        //This is where we end up if the wrong ETW manifest is used.
                        //Attempt to extract the packet from the error data in the XML instead
                        string xml = evt.ToXml();
                        if (xml.Contains("EventPayload")) {
                            var m = this.eventPayloadRegex.Match(xml);
                            if (m.Success) {
                                string hex = m.Groups[1].Value;
                                uint length = Convert.ToUInt32(string.Concat(hex.Substring(22, 2), hex.Substring(20, 2), hex.Substring(18, 2), hex.Substring(16, 2)), 16);
                                byte[] frameData = new byte[Math.Min(length, hex.Length / 2 - 12)];
                                for (int i = 0; i < frameData.Length; i++) {
                                    frameData[i] = Convert.ToByte(hex.Substring(24 + i * 2, 2), 16);
                                }
                                return new PcapFrame(evt.TimeCreated.Value.ToUniversalTime(), frameData, linkLayer);
                            }
                        }
                    }
                }
                else if(this.IsPktMonPacket(evt)) {
                    if (evt.Properties?.Count >= 12) {
                        /**
                         * [0] = PktGroupId
                         * [1] = PktNumber
                         * [2] = AppearanceCount
                         * [3] = DirTag
                         * [4] = PacketType
                         * [5] = ComponentId
                         * [6] = EdgeId
                         * [7] = FilterId
                         * [8] = DropReason
                         * [9] = DropLocation
                         * [10] = OriginalPayloadSize
                         * [11] = LoggedPayloadSize
                         * [12] = Payload (byte[])
                         * **/
                        
                        if (evt.Properties[4]?.Value is ushort &&  evt.Properties[11]?.Value is ushort && evt.Properties[12]?.Value is byte[]) {
                            PcapFrame.DataLinkTypeEnum linkLayer = this.GetDataLinkType((ushort)evt.Properties[4].Value);
                            ushort length = (ushort)evt.Properties[11].Value;
                            if (length > 16) {
                                byte[] frameData = (byte[])evt.Properties[12].Value;
                                return new PcapFrame(evt.TimeCreated.Value.ToUniversalTime(), frameData, linkLayer);
                            }
                        }
                    }

                }
            }
            return null;
        }
#else
        private EtlParser() { }//to prevent this class from being used

        public PcapFrame ReadPcapPacketBlocking() {
            throw new NotImplementedException();
        }

        public Task<PcapFrame> ReadPcapPacketAsync(CancellationToken cancellationToken) {
            throw new NotImplementedException();
        }

        public void Dispose() { }
#endif
    }
}
