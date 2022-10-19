using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils.Pcap {
    class PcapParserFactory : IPcapParserFactory {

        private readonly bool isRunningOnMono = SystemHelper.IsRunningOnMono();

        public string[] SupportedExtensions {
            get {
                if (this.isRunningOnMono)
                    return new[] { "pcap", "cap", "dump", "dmp", "eth", "log" };
                else
                    return new[] { "pcap", "cap", "dump", "dmp", "eth", "log", "etl" };
            }
        }

        public Func<string, IEnumerable<string>, string, string> FactoryFunc {
            get {
                throw new NotImplementedException();
            }

            set {
                throw new NotImplementedException();
            }
        }

        public IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader) {
            if (this.isRunningOnMono)
                return new PcapParser(pcapStreamReader);
            else
                return this.CreatePcapParserForWindows(pcapStreamReader);
        }

        public IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader, Func<IEnumerable<string>, string, string> _) {
            throw new NotImplementedException();
        }

        //The code referensing EtlParser has to be in a separate function to avoid getting a TypeLoadException in Mono
        private IPcapParser CreatePcapParserForWindows(IPcapStreamReader pcapStreamReader) {
#if NETFRAMEWORK
            if (pcapStreamReader is PcapFileReader pfr) {
                if (pfr.Filename != null && pfr.Filename.EndsWith(".etl", StringComparison.OrdinalIgnoreCase)) {
                    //this will break on Mono
                    return new EtlParser(pfr.Filename);
                }
            }
            return new PcapParser(pcapStreamReader);
#else
            return new PcapParser(pcapStreamReader);
#endif
        }
    }
}
