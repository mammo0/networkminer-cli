using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Drawing.Imaging;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.FileTransfer {


    public interface ITcpStreamAssembler {
        bool IsCompleted { get; }

        int AddData(byte[] data, uint sequenceNumber);
        void Finish();

        void Clear();
    }

    internal class RfbRectangleAssembler : ITcpStreamAssembler {

        private static readonly TcpPacket.Flags EMPTY_FLAGS = new TcpPacket.Flags(0);
        private static readonly TcpPacket.Flags PUSH_FLAGS = new TcpPacket.Flags(0x08);

        private uint startSequenceNumber;
        //private readonly SortedList<uint, byte[]> tcpPacketBufferWindow;//same as in FileStreamAssembler
        private readonly NetworkTcpSession.TcpDataStream tcpDataStream;
        private readonly RfbPacket.VncPixelFormat pixelFormat;
        private readonly NetworkTcpSession session;
        private readonly DateTime startTime;
        private readonly long startFrameNumber;

        internal int TotalRectangles { get; set; } = -1;
        internal List<RfbPacket.Rectangle> ParsedRectangles { get; }

        public bool IsCompleted {
            get {
                return this.TotalRectangles >= 0 && this.ParsedRectangles.Count() >= this.TotalRectangles;
            }
        }

        public Action<NetworkTcpSession, long, DateTime, RfbPacket.Rectangle[]> OnFinish { get; set; }

        internal RfbRectangleAssembler(RfbPacket.FrameBufferUpdatePacket fbUpdatePacket, uint startSequenceNumber, bool clientToServer, NetworkTcpSession session, RfbPacket.VncPixelFormat pixelFormat) {
            this.startTime = fbUpdatePacket.ParentFrame.Timestamp;
            this.startFrameNumber = fbUpdatePacket.ParentFrame.FrameNumber;

            this.startSequenceNumber = startSequenceNumber;
            this.tcpDataStream = new NetworkTcpSession.TcpDataStream(startSequenceNumber, clientToServer, session);
            this.pixelFormat = pixelFormat;
            this.ParsedRectangles = new List<RfbPacket.Rectangle>();
            this.session = session;
        }

        public int AddData(byte[] data, uint sequenceNumber) {
            if (data.Length > 0) {
#if DEBUG
                if (this.tcpDataStream.ExpectedTcpSequenceNumber > sequenceNumber)
                    System.Diagnostics.Debugger.Break();
#endif
                this.tcpDataStream.AddTcpData(sequenceNumber, data, PUSH_FLAGS);
            }
#if DEBUG
            var bytesToRead = tcpDataStream.CountBytesToRead();
#endif
            if (tcpDataStream.CountBytesToRead() >= RfbPacket.Rectangle.HEADER_LENGTH) {
                //GetNextVirtualTcpData() should work just as fine
                byte[] reassembledBytes = this.tcpDataStream.GetAllAvailableTcpData().GetBytes(false);
                int offset = 0;
                while ((this.TotalRectangles < 0 || this.ParsedRectangles.Count() < this.TotalRectangles) && RfbPacket.Rectangle.TryParse(reassembledBytes, offset, this.pixelFormat, true, out RfbPacket.Rectangle rectangle)) {
                    this.ParsedRectangles.Add(rectangle);
                    offset += rectangle.TotalLenght;
                    this.tcpDataStream.RemoveData(rectangle.TotalLenght);
                    if (rectangle.TryGetEncoding(out RfbPacket.Rectangle.FrameBufferEncoding encoding)) {
                        if (encoding == RfbPacket.Rectangle.FrameBufferEncoding.LastRect)
                            this.TotalRectangles = this.ParsedRectangles.Count();
                    }
                }
            }
            if (this.TotalRectangles < 0 || this.ParsedRectangles.Count() < this.TotalRectangles)
                return data.Length;
            else {
                return data.Length - tcpDataStream.CountBytesToRead();
            }
        }

        public void Finish() {
            //This function could asseble images to disk or report interesting findings to Parameters or hosts tab
            if(this.ParsedRectangles.Count > 0)
                this.OnFinish?.Invoke(this.session, this.startFrameNumber, this.startTime, this.ParsedRectangles.ToArray());
        }

        public void Clear() {
            this.tcpDataStream.Clear();//in order to free memory
        }
    }
}
