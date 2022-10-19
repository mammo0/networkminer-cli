using System;
using System.Collections.Generic;
using System.Text;

namespace SharedUtils.Pcap {
    public interface IPcapStreamReader {
        //public bool AbortReadingPcapStream();
        long Position { get; }

        byte[] BlockingRead(int bytesToRead);

        int BlockingRead(byte[] buffer, int offset, int count);

        System.Threading.Tasks.Task<byte[]> ReadAsync(int bytesToRead, System.Threading.CancellationToken cancellationToken);

        System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken);

    }
}
