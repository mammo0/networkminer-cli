using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils.Pcap {
    public interface IPcapParserFactory {
        string[] SupportedExtensions { get; }
        Func<string, IEnumerable<string>, string, string> FactoryFunc { get; set; }
        IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader);
    }
}
