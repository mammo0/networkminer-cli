using System;
using System.Collections.Generic;

namespace SharedUtils.Pcap {
    public class PcapStreamReader : IDisposable, IPcapStreamReader {
        public delegate void EmptyDelegate();
        public delegate bool StreamIsClosed();
        public delegate bool AbortReadingDelegate();
        public delegate void StreamReadCompletedCallback(int framesCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp);

        public static IPcapParserFactory PcapParserFactory = new PcapParserFactory();

        protected System.IO.Stream pcapStream;
        private long streamLength;
        private long readBytesEstimate;


        private System.Threading.CancellationTokenSource backgroundStreamReaderCanceller;
        private readonly System.Collections.Concurrent.BlockingCollection<PcapFrame> packetQueueBC;
        
        private int packetQueueMaxSize;


        private int enqueuedByteCount;
        private int dequeuedByteCount;
        private StreamIsClosed streamIsClosed;

        private Action readAction;
        private int readTimeoutMilliseconds = 20000;//20s

        protected StreamReadCompletedCallback streamReadCompletedCallback;

        public const int MAX_FRAME_SIZE = 131072;//Gigabit Ethernet Jumbo Frames are 9000 bytes. Total length field in IPv4 is a 16 bit number, allowing a theoretic max length of 64 kB.

        //[System.Obsolete("Data Link info is now available in PcapFileHandler.PcapPacket instead!")]
        public IList<PcapFrame.DataLinkTypeEnum> FileDataLinkType { get { return this.PcapParser.DataLinkTypes; } }

        public StreamIsClosed StreamIsClosedFunction { set { this.streamIsClosed = value; } }

        public Func<IEnumerable<string>, string, string> PcapParserFactoryFunc = null;

        /*
        public string OriginalFilename {
            get {
                if (this.pcapStream is System.IO.FileStream)
                    return (this.pcapStream as System.IO.FileStream).Name;
                else
                    return null;
            }
        }
        */

        public long Position {
            get {
                if (this.pcapStream?.CanSeek == true) {
                    try {
                        return this.pcapStream.Position;
                    }
                    catch {
                        return this.readBytesEstimate;
                    }
                }
                else
                    return this.readBytesEstimate;
            }
        }
        public List<KeyValuePair<string, string>> PcapParserMetadata { get { return this.PcapParser.Metadata; } }

        public IPcapParser PcapParser { get; }

        public PcapStreamReader(System.IO.Stream pcapStream) : this(pcapStream, 1000, null) { }
        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, true) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue) { }

        public PcapStreamReader(System.IO.FileStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, streamMaxLength, 20000) { }


        /*
        public PcapStreamReader(System.Net.Security.SslStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue, pcapStream.ReadTimeout) { }
            */
        public PcapStreamReader(System.Net.Sockets.NetworkStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, streamMaxLength, pcapStream.CanTimeout ? pcapStream.ReadTimeout : 20000) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, streamMaxLength, pcapStream.CanTimeout ? pcapStream.ReadTimeout : 20000) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength, int readTimeoutMilliseconds) {

            this.pcapStream = pcapStream;
            this.streamLength = streamMaxLength;
            this.readBytesEstimate = 0;
            this.readTimeoutMilliseconds = readTimeoutMilliseconds;

            this.packetQueueMaxSize=packetQueueSize;
            this.streamReadCompletedCallback=streamReadCompletedCallback;


            //TODO: Figure out if it is a libpcap, pcapNG or ETL stream...
            SharedUtils.Logger.Log("Checking capture file type", SharedUtils.Logger.EventLogEntryType.Information);
            this.PcapParser = PcapParserFactory.CreatePcapParser(this);
            if (this.PcapParser != null) {
                SharedUtils.Logger.Log("PCAP parser is " + this.PcapParser.GetType().ToString(), SharedUtils.Logger.EventLogEntryType.Information);

                this.packetQueueBC = new System.Collections.Concurrent.BlockingCollection<PcapFrame>(this.packetQueueMaxSize);
                //this.packetQueue = new System.Collections.Concurrent.ConcurrentQueue<PcapFrame>();
                //this.packetQueueHasRoomEvent = new System.Threading.AutoResetEvent(true);
                this.enqueuedByteCount = 0;
                this.dequeuedByteCount = 0;

                this.backgroundStreamReaderCanceller = new System.Threading.CancellationTokenSource();
                System.Threading.CancellationToken cancellationToken = backgroundStreamReaderCanceller.Token;
                this.readAction = new Action(() => {
                    DateTime firstFrameTimestamp = DateTime.MinValue;
                    DateTime lastFrameTimestamp = DateTime.MinValue;
                    int framesCount = 0;
                    try {
                        //int sleepMilliSecs = 20;

                        while (!cancellationToken.IsCancellationRequested && !this.EndOfStream()) {
                            PcapFrame packet = this.PcapParser.ReadPcapPacketBlocking();
                            if (packet == null) {
                                //that's what happens when we reach the end of ETL files
                                if (this.pcapStream is System.IO.FileStream fs)
                                    fs.Position = fs.Length;
                                break;
                            }

                            //PcapFrame packet = await this.pcapParser.ReadPcapPacketAsync(cancellationToken);
                            if (firstFrameTimestamp == DateTime.MinValue)
                                firstFrameTimestamp = packet.Timestamp;
                            lastFrameTimestamp = packet.Timestamp;
                            framesCount++;
                            this.enqueuedByteCount += packet.Data.Length;

                            while (!this.packetQueueBC.TryAdd(packet, 1000, cancellationToken)) {
                                if (cancellationToken.IsCancellationRequested || this.EndOfStream())
                                    break;
                            }
                            //this.packetQueue.Enqueue(packet);
                        }
                    }
                    catch (System.IO.EndOfStreamException) {
                        //Do nothing, just stop reading
                        this.pcapStream = null;
                    }
                    catch (System.IO.IOException) {
                        //probably a socket timout
                        if (!(this.pcapStream is System.IO.FileStream) && this.pcapStream != null) {
                            if (this.pcapStream.CanWrite)
                                this.pcapStream.Flush();
                            this.pcapStream.Dispose();
                        }
                        //this.pcapStream = null;
                    }
                    catch (OperationCanceledException) {
                        if (!(this.pcapStream is System.IO.FileStream) && this.pcapStream != null) {
                            if (this.pcapStream.CanWrite)
                                this.pcapStream.Flush();
                            this.pcapStream.Dispose();
                        }
                    }

#if !DEBUG
                    catch (Exception ex) {
                        this.pcapStream = null;
                        //this.backgroundStreamReaderCanceller.Cancel();
                        //e.Cancel = true;
                        //e.Result = ex.Message;
                        this.AbortFileRead();
                    }
#endif
                    //do a callback with this.filename as well as first and last timestamp
                    if (this.streamReadCompletedCallback != null && firstFrameTimestamp != DateTime.MinValue && lastFrameTimestamp != DateTime.MinValue)
                        this.streamReadCompletedCallback(framesCount, firstFrameTimestamp, lastFrameTimestamp);

                });

                if (startBackgroundWorkers)
                    this.StartBackgroundWorkers();
            }
        }

        ~PcapStreamReader() {
            //close the file stream here at least (instead of at the WorkerCompleted event)
            if (this.pcapStream != null) {
                try {
                    this.pcapStream.Close();
                }
                catch {
                    this.pcapStream.Dispose();
                }
                finally {
                    this.pcapStream = null;
                }
                /*
                if(this.pcapStream.CanWrite)
                    this.pcapStream.Flush();
                */

            }
            this.streamReadCompletedCallback = null;
        }



        public int PacketBytesInQueue {
            get { return this.enqueuedByteCount - this.dequeuedByteCount; }
        }

        public bool EndOfStream() {
            //first check if we have any clue about when the stream ends
            if (this.pcapStream == null)
                return true;
            if (!this.pcapStream.CanRead)
                return true;
            if (this.streamLength == long.MaxValue)
                return false;
            else if (this.pcapStream.CanSeek)
                return this.pcapStream.Position >= this.streamLength;
            else {
                try {
                    return this.pcapStream.Position >= this.streamLength;
                }
                catch {
                    return false;
                }
            }
        }

        public void StartBackgroundWorkers() {


            //This works in .NET Standard:
            //System.Threading.Tasks.Task.Run(this.readAction);
            System.Threading.Tasks.Task task = new System.Threading.Tasks.Task(this.readAction);
            task.Start();

        }


        public void AbortFileRead() {
            try {
                if (this.backgroundStreamReaderCanceller != null && !this.backgroundStreamReaderCanceller.IsCancellationRequested)
                    this.backgroundStreamReaderCanceller.Cancel();
            }
            catch(ObjectDisposedException) { }
            while (this.packetQueueBC.TryTake(out var pcapFrame)) { }
        }

        public void ThreadStart() {
            try {
                this.readAction.Invoke();
            }
            finally { }
        }
        

        public IEnumerable<PcapFrame> PacketEnumerator() {
            return this.PacketEnumerator(null, null);
        }

        public IEnumerable<PcapFrame> PacketEnumerator(EmptyDelegate waitFunction, StreamReadCompletedCallback captureCompleteCallback) {

            const int MIN_TAKE_TIMEOUT = 100;
            int timeoutMilliSecs = MIN_TAKE_TIMEOUT;
            long lastReaderPosition = 0;//used in order to see if there is any progress or if we have a deadlock

            var cancellationToken = this.backgroundStreamReaderCanceller.Token;
            int maxSleepMS = (int)Math.Sqrt(2.0 * this.readTimeoutMilliseconds + timeoutMilliSecs* timeoutMilliSecs);
            
            while (!cancellationToken.IsCancellationRequested && (!this.EndOfStream() || this.packetQueueBC.Count > 0)) {

                if (this.packetQueueBC.TryTake(out PcapFrame packet, timeoutMilliSecs, cancellationToken)) {
                    timeoutMilliSecs = MIN_TAKE_TIMEOUT;
                    lastReaderPosition = this.readBytesEstimate;
                    this.dequeuedByteCount += packet.Data.Length;
                    yield return packet;
                }
                else {
                    if (timeoutMilliSecs++ > maxSleepMS) {//20 seconds of total waiting time since last Take/Dequeue
                        if (lastReaderPosition == this.readBytesEstimate)
                            break;//abort the reading, something has gone wrong...
                        else {//as long as the file reader is making progress we should be fine. typically happens when packets are carved instead of parsed
                            lastReaderPosition = this.readBytesEstimate;
                            timeoutMilliSecs = MIN_TAKE_TIMEOUT;//reset timeout timer
                        }
                    }
                    waitFunction?.Invoke();
                }
            }

        }


        public bool AbortReadingPcapStream() {
            return this.backgroundStreamReaderCanceller.IsCancellationRequested || this.EndOfStream() || (this.streamIsClosed != null && this.streamIsClosed());
        }

        public byte[] BlockingRead(int bytesToRead) {
            byte[] buffer = new byte[bytesToRead];
            BlockingRead(buffer, 0, bytesToRead);
            return buffer;
        }

        public int BlockingRead(byte[] buffer, int offset, int count) {
            int bytesRead = this.pcapStream.Read(buffer, offset, count);
            if (bytesRead == 0) {
                throw new System.IO.EndOfStreamException("Done reading");
            }
            int sleepMilliSecs = 20;
            int maxSleepMS = (int)Math.Sqrt(2.0 * this.readTimeoutMilliseconds);
            while (bytesRead < count) {
                //no more data available to read at this moment
                if (this.AbortReadingPcapStream()) {
                    throw new System.IO.EndOfStreamException("Done reading");
                }

                if (sleepMilliSecs++ > maxSleepMS) {
                    //Give up reading! (total idle wait time ~8.2 seconds [128*128/2=8192] )
                    throw new System.IO.IOException("Stream reading timed out...");
                }
                //This works in .NET Standard:
                //System.Threading.Tasks.Task.Delay(sleepMilliSecs).Wait();
                System.Threading.Thread.Sleep(sleepMilliSecs);

                if (this.pcapStream == null)
                    throw new System.IO.EndOfStreamException("Stream has been closed");
                bytesRead += this.pcapStream.Read(buffer, bytesRead, count - bytesRead);

            }
            this.readBytesEstimate += bytesRead;
            return bytesRead;
        }

        public async System.Threading.Tasks.Task<byte[]> ReadAsync(int bytesToRead, System.Threading.CancellationToken cancellationToken) {
            byte[] buffer = new byte[bytesToRead];
            await this.ReadAsync(buffer, 0, bytesToRead, cancellationToken);
            return buffer;
        }

        public async System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken) {
            int bytesRead = await this.pcapStream.ReadAsync(buffer, offset, count, cancellationToken);
            if (bytesRead == 0) {
                throw new System.IO.EndOfStreamException("Done reading");
            }
            int sleepMilliSecs = 20;
            int maxSleepMS = (int)Math.Sqrt(2.0 * this.readTimeoutMilliseconds);
            while (bytesRead < count) {
                //no more data available to read at this moment
                if (this.AbortReadingPcapStream() || cancellationToken.IsCancellationRequested) {
                    throw new System.IO.EndOfStreamException("Done reading");
                }

                if (sleepMilliSecs++ > maxSleepMS) {
                    //Give up reading! (total idle wait time ~8.2 seconds [128*128/2=8192] )
                    throw new System.IO.IOException("Stream reading timed out...");
                }
                //This works in .NET Standard:
                //System.Threading.Tasks.Task.Delay(sleepMilliSecs).Wait();
                await System.Threading.Tasks.Task.Delay(sleepMilliSecs, cancellationToken);
                if(cancellationToken.IsCancellationRequested)
                    throw new System.IO.EndOfStreamException("Reading canceled");
                else if (this.pcapStream == null)
                    throw new System.IO.EndOfStreamException("Stream has been closed");
                bytesRead += this.pcapStream.Read(buffer, bytesRead, count - bytesRead);
            }
            this.readBytesEstimate += bytesRead;
            return bytesRead;
        }


        #region IDisposable Members

        public void Dispose() {
            if (this.backgroundStreamReaderCanceller != null) {
                try {
                    this.backgroundStreamReaderCanceller.Cancel();
                    this.backgroundStreamReaderCanceller.Dispose();
                }
                catch (ObjectDisposedException) { }
            }
            if (this.pcapStream != null) {
                try {
                    this.pcapStream.Close();
                }
                catch {
                    this.pcapStream.Dispose();
                }
                finally {
                    this.pcapStream = null;
                }
            }

            this.streamReadCompletedCallback = null;
        }

#endregion
    }
}
