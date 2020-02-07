using System;
using System.Collections.Generic;
using System.Text;

namespace NetresecShared.Pcap {
    public interface IPcapParserFactory {
        IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader);
    }
}
