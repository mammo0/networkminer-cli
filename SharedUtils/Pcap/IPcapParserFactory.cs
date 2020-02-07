using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public interface IPcapParserFactory {
        IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader);
    }
}
