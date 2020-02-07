using System;
using System.Collections.Generic;
using System.Text;

namespace NetresecShared.Pcap {
    class PcapParserFactory : IPcapParserFactory {
        public IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader) {
            return new PcapParser(pcapStreamReader);
        }
    }
}
