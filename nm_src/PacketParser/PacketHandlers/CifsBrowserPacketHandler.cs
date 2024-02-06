using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class CifsBrowserPacketHandler : AbstractPacketHandler, IPacketHandler {

        private readonly Type cifsBrowserPacketType = typeof(CifsBrowserPacket);

        internal CifsBrowserPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {

        }

        public override Type[] ParsedTypes { get; } =  { typeof(CifsBrowserPacket) };

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<AbstractPacket> packetList) {

            ITransportLayerPacket transportLayerPacket = packetList.OfType<ITransportLayerPacket>().First();
            foreach (CifsBrowserPacket browser in packetList.OfType<CifsBrowserPacket>()) {
                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();

                if (!string.IsNullOrEmpty(browser.Hostname))
                    sourceHost.AddHostName(browser.Hostname, browser.PacketTypeDescription);
                if (!string.IsNullOrEmpty(browser.DomainOrWorkgroup))
                    sourceHost.AddDomainName(browser.DomainOrWorkgroup);
                if (browser.OSVersion.major > 0 || browser.OSVersion.minor > 0) {
                    sourceHost.AddNumberedExtraDetail("Windows Version", "" + browser.OSVersion.major + "." + browser.OSVersion.minor);
                }
                if (browser.Uptime != null) {
                    parameters.Add("CIFS Browser Service Uptime", browser.Uptime.Value.ToString());
                }

                if (parameters.Count > 0) {
                    //TODO: figure out the five tuple!
                    Events.ParametersEventArgs pe = new Events.ParametersEventArgs(browser.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, browser.ParentFrame.Timestamp, "CIFS Browser/MS-BRWS Uptime");
                    //var pe = new Events.ParametersEventArgs(browser.ParentFrame.FrameNumber, ft, true, parameters, browser.ParentFrame.Timestamp, "CIFS Browser/MS-BRWS Uptime");
                    base.MainPacketHandler.OnParametersDetected(pe);
                }
            }
            
        }

        public void Reset() {
            //no state is being kept
        }
    }
}
