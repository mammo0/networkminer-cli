using System;
using System.Collections.Generic;
using System.Text;
//using System.IO;

namespace SharedUtils.Pcap {
    public class PcapFileReader : PcapStreamReader {

        public delegate void CaseFileLoadedCallback(string filePathAndName, int framesCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp);

        private bool pcapStreamReaderCompleted = false;
        private string filename;
        //private System.IO.FileStream fileStream;
        private System.IO.FileStream fileStream {
            get {
                return (System.IO.FileStream)base.pcapStream;
            }
        }
        private CaseFileLoadedCallback caseFileLoadedCallback;

        public string Filename {
            get {
                if (this.filename != null)
                    return this.filename;
                else
                    return this.fileStream?.Name;
            }
        }

        public new long Position {
            get {
                if (this.fileStream != null) {
                    try {
                        return this.fileStream.Position;
                    }
                    catch {
                        return base.Position;
                    }
                }
                else
                    return base.Position;
            }
            set { this.fileStream.Position = value; }
        }

        public long Length {
            get { return this.fileStream.Length; }
        }

        public int PercentRead {
            get {
                //the stream might be closed if we have read it through...
                //... or if there is an exception when reading it
                return (int)(((this.fileStream.Position - this.PacketBytesInQueue) * 100) / this.fileStream.Length);
            }
        }

        public int GetPercentRead(long bytesInOtherQueues) {
            if (this.fileStream == null) {
                if (this.pcapStreamReaderCompleted)
                    return (int)(((this.Position - this.PacketBytesInQueue / 2 - bytesInOtherQueues / 3) * 100) / this.Position);
                else
                    return 0;
            }
            else
                return (int)(((this.fileStream.Position - this.PacketBytesInQueue / 2 - bytesInOtherQueues / 3) * 100) / this.fileStream.Length);
        }

        public PcapFileReader(string filename) : this(filename, 1000, null) { }
        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback) : this(filename, packetQueueSize, readCompleteCallback, true) { }

        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, System.IO.FileShare fileShare) : this(filename, packetQueueSize, readCompleteCallback, true, fileShare) { }

        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, bool startBackgroundWorkers, System.IO.FileShare fileShare = System.IO.FileShare.Read)
            : this(filename, new System.IO.FileStream(filename, System.IO.FileMode.Open, System.IO.FileAccess.Read, fileShare, 262144, System.IO.FileOptions.SequentialScan), packetQueueSize, readCompleteCallback, startBackgroundWorkers) { }

        private PcapFileReader(string filename, System.IO.FileStream fileStream, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, bool startBackgroundWorkers)
            : base(fileStream, packetQueueSize, null, startBackgroundWorkers, fileStream.Length) {
            if (this.PcapParser != null) {
                this.filename = filename;
                //this.fileStream = fileStream;
                //base.streamLength = fileStream.Length;
                base.streamReadCompletedCallback = new StreamReadCompletedCallback(this.StreamReadCompletedCallbackHandler);
                this.caseFileLoadedCallback = readCompleteCallback;
            }
        }

        public void StreamReadCompletedCallbackHandler(int framesCount, DateTime fistFrameTimestamp, DateTime lastFrameTimestamp) {
            this.pcapStreamReaderCompleted = true;
            if (this.caseFileLoadedCallback != null)
                this.caseFileLoadedCallback(this.filename, framesCount, fistFrameTimestamp, lastFrameTimestamp);
        }


    }
}
