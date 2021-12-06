using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharedUtils.Pcap {
    public class PcapFileWriter : IAsyncFrameWriter, IFrameWriter, IDisposable {

        private readonly SemaphoreSlim writeLock;
        private readonly bool autoFlush;
        private readonly System.IO.Stream outputStream;
        private const ushort MAJOR_VERSION_NUMBER=0x02;
        private const ushort MINOR_VERSION_NUMBER=0x04;
        private const uint MAGIC_NUMBER=0xa1b2c3d4;
        private readonly DateTime referenceTime;

        public bool IsOpen { get; private set; }
        public string Filename { get; }
        public uint FramesWritten { get; private set; }

        public string FullOutputPath {
            get {
                if (this.outputStream is FileStream fs)
                    return Path.GetFullPath(fs.Name);
                else
                    return "";
            }
        }

        public PcapFrame.DataLinkTypeEnum DataLinkType { get; }
        public bool OutputIsPcapNg { get { return false; } }

        //public PcapFileWriter(string filename, PcapFrame.DataLinkTypeEnum dataLinkType) : this(filename, dataLinkType, System.IO.FileMode.Create, 262144){
        public PcapFileWriter(string filename, PcapFrame.DataLinkTypeEnum dataLinkType)
            : this(filename, dataLinkType, System.IO.FileMode.Create, 8388608) {
            //nothing more needed
        }
        public PcapFileWriter(string filename, PcapFrame.DataLinkTypeEnum dataLinkType, System.IO.FileMode fileMode, int bufferSize)
        : this(filename, dataLinkType, fileMode, bufferSize, false) {
            //I prefer big endian
        }

        public PcapFileWriter(string filename, PcapFrame.DataLinkTypeEnum dataLinkType, System.IO.FileMode fileMode, int bufferSize, bool littleEndian, FileAccess fileAccess = FileAccess.Write, FileShare fileShare = FileShare.Read) : this() {
            this.FramesWritten = 0;
            this.Filename=filename;
            this.DataLinkType = dataLinkType;
            //this.referenceTime=new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            this.outputStream = new FileStream(filename, fileMode, fileAccess, fileShare, bufferSize, FileOptions.SequentialScan);
            
            if(fileMode != FileMode.Append || this.outputStream.Position == 0) {
                this.WritePcapHeader(dataLinkType, littleEndian);

            }
        }

        public PcapFileWriter(PcapFrame.DataLinkTypeEnum dataLinkType, Stream outputStream, bool autoFlush = false) : this() {
            this.DataLinkType = dataLinkType;
            this.outputStream = outputStream;
            this.autoFlush = autoFlush;
            this.WritePcapHeader(dataLinkType, false);
        }

        private PcapFileWriter() {
            this.referenceTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            this.IsOpen = true;
            this.autoFlush = false;
            this.writeLock = new SemaphoreSlim(1, 1);
        }

        private void WritePcapHeader(PcapFrame.DataLinkTypeEnum dataLinkType, bool littleEndian) {
            List<byte[]> headerFields = new List<byte[]>();
            headerFields.Add(ToByteArray(MAGIC_NUMBER));
            headerFields.Add(ToByteArray(MAJOR_VERSION_NUMBER));
            headerFields.Add(ToByteArray(MINOR_VERSION_NUMBER));
            headerFields.Add(ToByteArray((uint)0x00));
            headerFields.Add(ToByteArray((uint)0x00));
            headerFields.Add(ToByteArray((uint)0xffff));
            headerFields.Add(ToByteArray((uint)dataLinkType));

            this.writeLock.Wait();
            try {
                foreach (byte[] field in headerFields) {
                    if (littleEndian)
                        Array.Reverse(field);
                    outputStream.Write(field, 0, field.Length);
                }
            }
            finally {
                this.writeLock.Release();
            }
        }

        private Tuple<uint, uint> GetSecondsMicrosecondsTuple(DateTime timestamp) {
            TimeSpan delta = timestamp.Subtract(this.referenceTime);
            //The smallest unit of time is the tick, which is equal to 100 nanoseconds. A tick can be negative or positive.
            long totalMicroseconds = delta.Ticks / 10;
            uint seconds = (uint)(totalMicroseconds / 1000000);
            uint microseconds = (uint)(totalMicroseconds % 1000000);
            return new Tuple<uint, uint>(seconds, microseconds);
        }

        
        public void WriteFrame(byte[] rawFrameHeaderBytes, byte[] rawFrameDataBytes, bool littleEndian) {
            this.writeLock.Wait();
            try {
                this.outputStream.Write(rawFrameHeaderBytes, 0, rawFrameHeaderBytes.Length);
                this.outputStream.Write(rawFrameDataBytes, 0, rawFrameDataBytes.Length);
            }
            finally {
                this.writeLock.Release();
            }
        }

        public void WriteFrame(PcapFrame frame) {
            this.WriteFrame(frame, this.autoFlush);
        }
        public void WriteFrame(PcapFrame frame, bool flush) {
            Tuple<uint, uint> secondsMicroseconds = this.GetSecondsMicrosecondsTuple(frame.Timestamp);
            this.writeLock.Wait();
            try {
                this.outputStream.Write(ToByteArray(secondsMicroseconds.Item1), 0, 4);
                this.outputStream.Write(ToByteArray(secondsMicroseconds.Item2), 0, 4);
                //number of octets of packet saved in file
                this.outputStream.Write(ToByteArray((uint)frame.Data.Length), 0, 4);
                //actual length of packet
                this.outputStream.Write(ToByteArray((uint)frame.Data.Length), 0, 4);
                //data
                this.outputStream.Write(frame.Data, 0, frame.Data.Length);
                if (flush)
                    this.outputStream.Flush();
            }
            finally {
                this.writeLock.Release();
            }
            this.FramesWritten++;
        }


        public Task WriteFrameAsync(PcapFrame frame) {
            return WriteFrameAsync(frame, this.autoFlush);
        }
        public async Task WriteFrameAsync(PcapFrame frame, bool flush) {
            Tuple<uint, uint> secondsMicroseconds = this.GetSecondsMicrosecondsTuple(frame.Timestamp);
            await this.writeLock.WaitAsync();
            try {
                await this.outputStream.WriteAsync(ToByteArray(secondsMicroseconds.Item1), 0, 4);
                await this.outputStream.WriteAsync(ToByteArray(secondsMicroseconds.Item2), 0, 4);
                //number of octets of packet saved in file
                await this.outputStream.WriteAsync(ToByteArray((uint)frame.Data.Length), 0, 4);
                //actual length of packet
                await this.outputStream.WriteAsync(ToByteArray((uint)frame.Data.Length), 0, 4);
                //data
                await this.outputStream.WriteAsync(frame.Data, 0, frame.Data.Length);
                if (flush)
                    await this.outputStream.FlushAsync();
            }
            finally {
                this.writeLock.Release();
            }
            this.FramesWritten++;
        }

        public async Task FlushAsync() {
            await this.writeLock.WaitAsync();
            try {
                await this.outputStream.FlushAsync();
            }
            finally {
                this.writeLock.Release();
            }
        }


        public void Close() {
            this.writeLock.Wait(1000);
            try {
                this.outputStream.Flush();
                this.outputStream.Dispose();
                this.IsOpen = false;
            }
            finally {
                this.writeLock.Release();
            }
        }

        public async Task CloseAsync() {
            await this.outputStream.FlushAsync();

            await this.writeLock.WaitAsync(1000);
            try {
                this.outputStream.Dispose();
                this.IsOpen = false;
            }
            finally {
                this.writeLock.Release();
            }
        }

        public static byte[] ToByteArray(long value) {
            byte[] array=new byte[8];
            ToByteArray((uint)(value>>32), array, 0);
            ToByteArray((uint)value, array, 4);
            return array;
        }
        public static byte[] ToByteArray(uint value) {
            byte[] array=new byte[4];
            ToByteArray(value, array, 0);
            return array;
        }
        public static byte[] ToByteArray(ushort value) {
            byte[] array=new byte[2];
            ToByteArray(value, array, 0);
            return array;
        }
        public static void ToByteArray(ushort value, byte[] array, int arrayOffset) {
            array[arrayOffset]=(byte)(value>>8);
            array[arrayOffset+1]=(byte)(value&0x00ff);
        }

        //creates big endian byte representation
        public static void ToByteArray(uint value, byte[] array, int arrayOffset) {
            array[arrayOffset]=(byte)(value>>24);
            array[arrayOffset+1]=(byte)((value>>16)&0x000000ff);
            array[arrayOffset+2]=(byte)((value>>8)&0x000000ff);
            array[arrayOffset+3]=(byte)(value&0x000000ff);
        }

        public void Dispose() {
            this.Close();
        }


        
    }
}
