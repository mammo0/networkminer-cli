using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils.Pcap {
    public interface IAsyncFrameWriter : IFrameWriter, IDisposable {
        string FullOutputPath { get; }
        PcapFrame.DataLinkTypeEnum DataLinkType { get; }

        Task WriteFrameAsync(PcapFrame frame);
        Task FlushAsync();
        Task CloseAsync();
    }
}
