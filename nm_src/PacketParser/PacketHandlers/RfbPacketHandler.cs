using PacketParser.FileTransfer;
using PacketParser.Packets;
using PacketParser.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI.WebControls.WebParts;
using System.Xml.Linq;
using static PacketParser.PacketHandlers.RfbPacketHandler;
using static PacketParser.Packets.RfbPacket.Rectangle;

namespace PacketParser.PacketHandlers {
    internal class RfbPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //private protected enables access from within extended classes
        private protected PopularityList<NetworkTcpSession, VncDesktop> vncDesktops;

        public override Type[] ParsedTypes { get; } = new[] { typeof(Packets.RfbPacket) };

        public virtual ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.VNC;
            }
        }

        public byte MaxFramesPerSecond { get; set; } = 1;//recommended values are 1 to 10

        public RfbPacketHandler(PacketHandler mainPacketHandler, byte maxFramesPerSecond) : base(mainPacketHandler) {
            if (maxFramesPerSecond < 1)
                this.MaxFramesPerSecond = 1;
            else
                this.MaxFramesPerSecond = maxFramesPerSecond;
            this.vncDesktops = new PopularityList<NetworkTcpSession, VncDesktop>(100);
            this.vncDesktops.PopularityLost += (tcpSession, desktop) => {
                if(desktop.PixelsAddedSinceLastScreenshot > 0) {
                    this.SaveDesktopScreenshot(tcpSession, 0, tcpSession.EndTime, desktop);
                }
                desktop.Dispose();
            };
        }

        private protected void SetPixelFormat(RfbPacket.VncPixelFormat pixelFormat, NetworkTcpSession tcpSession, NetworkHost vncServerHost, System.Collections.Specialized.NameValueCollection parms) {
            parms.Add("Pixel Format", pixelFormat.ToString());
            if (this.vncDesktops.ContainsKey(tcpSession))
                this.vncDesktops[tcpSession].PixelFormat = pixelFormat;
            else {
                VncDesktop vncDesktop = new VncDesktop(vncServerHost.IPAddress) { PixelFormat = pixelFormat };
                this.vncDesktops.Add(tcpSession, vncDesktop);
                this.SetScreenshotOnSessionClosed(tcpSession, vncDesktop);

            }
        }

        private protected void SetScreenSize(System.Drawing.Size desktopSize, System.Collections.Specialized.NameValueCollection parms, NetworkTcpSession tcpSession, NetworkHost vncServerHost) {

            if (this.vncDesktops.ContainsKey(tcpSession))
                this.vncDesktops[tcpSession].DesktopSize = desktopSize;
            else {
                VncDesktop vncDesktop = new VncDesktop(vncServerHost.IPAddress) { DesktopSize = desktopSize };
                this.vncDesktops.Add(tcpSession, vncDesktop);
                this.SetScreenshotOnSessionClosed(tcpSession, vncDesktop);
            }

            vncServerHost.AddNumberedExtraDetail("VNC desktop size", desktopSize.ToString());
            parms.Add("Width", desktopSize.Width.ToString());
            parms.Add("Height", desktopSize.Height.ToString());
        }

        private void SetScreenshotOnSessionClosed(NetworkTcpSession tcpSession, VncDesktop desktop) {
            tcpSession.OnSessionClosed += (s, frame) => {
                if (frame != null && desktop.PixelsAddedSinceLastScreenshot > 0)
                    this.SaveDesktopScreenshot(tcpSession, frame.FrameNumber, frame.Timestamp, desktop);
            };
        }

        private protected void SetVncDesktopName(string desktopName, System.Collections.Specialized.NameValueCollection parms, NetworkTcpSession tcpSession, NetworkHost vncServerHost) {
            if (!string.IsNullOrEmpty(desktopName)) {
                if (this.vncDesktops.ContainsKey(tcpSession))
                    this.vncDesktops[tcpSession].DesktopName = desktopName;
                else {
                    VncDesktop vncDesktop = new VncDesktop(vncServerHost.IPAddress) { DesktopName = desktopName };
                    this.vncDesktops.Add(tcpSession, vncDesktop);
                    this.SetScreenshotOnSessionClosed(tcpSession, vncDesktop);
                }
                string fieldName = "VNC Desktop Name";
                vncServerHost.AddNumberedExtraDetail(fieldName, desktopName);
                parms.Add(fieldName, desktopName);
            }
        }

        private protected void ExtractCommandPacketDetails(RfbPacket.VncCommandPacket commandPacket, NetworkTcpSession tcpSession, NetworkHost vncServerHost, System.Collections.Specialized.NameValueCollection parms) {
            //TODO: move this function into RfbPacketHandler instead and let this class extend it
            if (commandPacket.PixelFormat.HasValue) {
                this.SetPixelFormat(commandPacket.PixelFormat.Value, tcpSession, vncServerHost, parms);
            }
            if (commandPacket.Command == RfbPacket.VncCommandPacket.VncCommand.ClientCutText) {
                if (commandPacket is RfbPacket.ClientCutTextPacket cutTextPacket) {
                    if (!string.IsNullOrEmpty(cutTextPacket.Text))
                        parms.Add("Clipboard", cutTextPacket.Text);
                    if (cutTextPacket.FormatFlags != 0) {
                        parms.Add("Extended Clipboard Flags", "0x" + cutTextPacket.FormatFlags.ToString("X4"));
                    }
                }
            }
            else if (commandPacket.Command == RfbPacket.VncCommandPacket.VncCommand.KeyEvent) {
                if (commandPacket is RfbPacket.KeyEventPacket keyPacket) {
                    if (!string.IsNullOrEmpty(keyPacket.Key)) {
                        if (keyPacket.Down)
                            parms.Add("Key pressed", keyPacket.Key);
                        else if (keyPacket.Key.Length > 1)
                            parms.Add("Key released", keyPacket.Key);
                    }
                }
            }
        }

        [Obsolete("This functon creates FileStreamAssembler for rectangle data. Use the other overload of ExtractResponsePacketDetails() instead.")]
        private protected void ExtractResponsePacketDetails(RfbPacket.VncResponsePacket responsePacket, NetworkTcpSession tcpSession, System.Collections.Specialized.NameValueCollection parms, bool transferIsClientToServer, ref int skippedBytes) {
            if (responsePacket.ResponseCode == RfbPacket.VncResponsePacket.VncResponseCode.ServerCutText) {
                if (responsePacket is RfbPacket.ServerCutTextPacket serverCutText) {
                    this.ExtractServerCutText(serverCutText, transferIsClientToServer, parms);
                }
            }
            else if (responsePacket.ResponseCode == RfbPacket.VncResponsePacket.VncResponseCode.FramebufferUpdate) {
                if (responsePacket is RfbPacket.FrameBufferUpdatePacket fbUpdatePacket) {
                    if (fbUpdatePacket.Rectangles?.Length == fbUpdatePacket.RectangleCount) {
                        this.ExtractRectangles(fbUpdatePacket, fbUpdatePacket.Rectangles, tcpSession, transferIsClientToServer, ref skippedBytes);
                    }
                }
            }
        }

        private protected void ExtractResponsePacketDetails(RfbPacket.VncResponsePacket responsePacket, NetworkTcpSession tcpSession, System.Collections.Specialized.NameValueCollection parms, bool clientToServer) {
            if (responsePacket.ResponseCode == RfbPacket.VncResponsePacket.VncResponseCode.ServerCutText) {
                if (responsePacket is RfbPacket.ServerCutTextPacket serverCutText) {
                    this.ExtractServerCutText(serverCutText, clientToServer, parms);
                }
            }
            else if (responsePacket.ResponseCode == RfbPacket.VncResponsePacket.VncResponseCode.FramebufferUpdate) {
                if (responsePacket is RfbPacket.FrameBufferUpdatePacket fbUpdatePacket) {
                    if(fbUpdatePacket.Rectangles == null || fbUpdatePacket.RectangleCount == 0xffff) {
                        //assemble rectangles
                        if (this.vncDesktops.ContainsKey(tcpSession)) {
                            var vncPixelFormat = this.vncDesktops[tcpSession].PixelFormat;
                            TcpPacket tcpPacket = fbUpdatePacket.ParentFrame.PacketList.OfType<TcpPacket>().FirstOrDefault();
                            if(tcpPacket != null) {
#if DEBUG
                                if (tcpPacket.PacketStartIndex + tcpPacket.DataOffsetByteCount != fbUpdatePacket.PacketStartIndex)
                                    System.Diagnostics.Debugger.Break();
#endif
                                uint rectangleStartSequenceNumber = (uint)(tcpPacket.SequenceNumber - tcpPacket.DataOffsetByteCount - tcpPacket.PacketStartIndex + fbUpdatePacket.PacketStartIndex + fbUpdatePacket.PacketLength);
                                RfbRectangleAssembler rectangleAssembler = new RfbRectangleAssembler(fbUpdatePacket, rectangleStartSequenceNumber, clientToServer, tcpSession, vncPixelFormat);
                                rectangleAssembler.OnFinish = new Action<NetworkTcpSession, long, DateTime, RfbPacket.Rectangle[]>(this.HandleRectangles);
                                if(fbUpdatePacket.RectangleCount != 0xffff)
                                    rectangleAssembler.TotalRectangles = fbUpdatePacket.RectangleCount;
                                this.MainPacketHandler.TcpStreamAssemblerList.Add((tcpSession, clientToServer), rectangleAssembler);
                            }
                            
                        }
                    }
                    else if (fbUpdatePacket.Rectangles != null && fbUpdatePacket.RectangleCount > 0 && fbUpdatePacket.RectangleCount < 0xffff) {
                        //add rectangles without further assembly
                        this.HandleRectangles(tcpSession, fbUpdatePacket.ParentFrame.FrameNumber, fbUpdatePacket.ParentFrame.Timestamp, fbUpdatePacket.Rectangles);
                    }
                }
            }
        }

        internal void HandleRectangles(NetworkTcpSession session, long initialFrameNumber, DateTime timestamp, RfbPacket.Rectangle[] rectangles) {
            VncDesktop desktop = this.vncDesktops[session];
            if(desktop != null) {
                desktop.AddRectangles(rectangles);

                int desktopPixels = desktop.DesktopSize.Width * desktop.DesktopSize.Height;
                if (this.MaxFramesPerSecond < 1)
                    this.MaxFramesPerSecond = 1;

                int desktopUpdatePixels = desktopPixels / 4 / this.MaxFramesPerSecond;
                if (desktopUpdatePixels < 40000)//40kpixel (200x200)
                    desktopUpdatePixels = 40000;
                if (desktopUpdatePixels > 2304000)//~2Mpixel = 1920x1200 (WUXGA)
                    desktopUpdatePixels = 2304000;

                if (desktop.PixelsAddedSinceLastScreenshot > 0) {
                    if (desktop.PixelsAddedTotal == desktop.PixelsAddedSinceLastScreenshot)//first pixels added
                        this.SaveDesktopScreenshot(session, initialFrameNumber, timestamp, desktop);
                    else if (desktop.PixelsAddedSinceLastScreenshot > desktopUpdatePixels && timestamp.Subtract(desktop.LastScreenshotTimestamp) > TimeSpan.FromSeconds(1.0 / this.MaxFramesPerSecond)) {
                        this.SaveDesktopScreenshot(session, initialFrameNumber, timestamp, desktop);
                    }
                }
            }
        }

        private void SaveDesktopScreenshot(NetworkTcpSession session, long initialFrameNumber, DateTime timestamp, VncDesktop desktop) {
            bool transferIsClientToServer = desktop.ServerIP.Equals(session.ClientHost.IPAddress);

            string filename = desktop.DesktopName.Trim() + "_" + session.GetHashCode().ToString("X4") + "_" + timestamp.ToUniversalTime().ToString("yyMMddHHmmss") + ".jpg";
            string details = "(" + desktop.DesktopSize.Width + "x" + desktop.DesktopSize.Height + ")";
            if (!string.IsNullOrEmpty(desktop.DesktopName))
                details = desktop.DesktopName.Trim() + " " + details;
            FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, session.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.VNC, filename, "", details, initialFrameNumber, timestamp);
            if (assembler.TryActivate()) {
                byte[] jpg = desktop.GetScreenshot(ImageFormat.Jpeg, timestamp);
                assembler.FileSegmentRemainingBytes = jpg.Length;
                assembler.SetRemainingBytesInFile(jpg.Length);
                assembler.AddData(jpg, 0);
            }
        }

        private protected void ExtractServerCutText(RfbPacket.ServerCutTextPacket serverCutText, bool transferIsClientToServer, System.Collections.Specialized.NameValueCollection parms) {
            if (!string.IsNullOrEmpty(serverCutText.Text))
                parms.Add("Clipboard", serverCutText.Text);
            if (serverCutText.FormatFlags != 0) {
                parms.Add("Extended Clipboard Flags", "0x" + serverCutText.FormatFlags.ToString("X4"));
            }
        }

        private protected void ExtractRectangles(RfbPacket.FrameBufferUpdatePacket fbUpdatePacket, IEnumerable<RfbPacket.Rectangle> rectangles, NetworkTcpSession tcpSession, bool transferIsClientToServer, ref int skippedBytes) {
            foreach (RfbPacket.Rectangle rect in rectangles) {
                if (rect.TryGetEncoding(out var fbEncoding)) {
                    string fileDetails = "VNC " + fbEncoding.ToString() + " FrameBuffer data";
                    string filename = "VNC-" + fbEncoding.ToString();
                    int fileSize = rect.RectangleDataLength;

                    if (fbEncoding == RfbPacket.Rectangle.FrameBufferEncoding.Zlib) {
                        fileSize -= 4;//skip the first 4 bytes, which is a length field before the zlib data
                        if (rect.RectangleData == null) {
                            skippedBytes = 4;
                        }
                    }
                    if (fileSize < 0) {
                        if (fbEncoding == RfbPacket.Rectangle.FrameBufferEncoding.Cursor) {
                            if (this.vncDesktops.ContainsKey(tcpSession)) {
                                RfbPacket.VncPixelFormat format = this.vncDesktops[tcpSession].PixelFormat;
                                fileSize = RfbPacket.Rectangle.CursorRectangleData.GetLength(rect.Width, rect.Height, format.BitsPerPixel);
                            }
                            else
                                fileSize = RfbPacket.Rectangle.CursorRectangleData.GetLength(rect.Width, rect.Height, 32);//guessing pits per pixel is 32
                        }
                    }
                    if (fileSize > 0) {

                        if (rect.RectangleData == null) {
                            FileStreamAssembler assembler = new FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.VNC, filename, "/", fileDetails, fbUpdatePacket.ParentFrame.FrameNumber, fbUpdatePacket.ParentFrame.Timestamp);
                            if (assembler.TryActivate()) {
                                base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);

                                assembler.FileContentLength = fileSize;
                                assembler.FileSegmentRemainingBytes = fileSize;
                                //don't add data here, let file stream assembler do the job
                            }
                        }
                        else {
                            //assembler.FileContentLength = rect.RectangleData.ImageBytes.Length;
                            //assembler.FileSegmentRemainingBytes = rect.RectangleData.ImageBytes.Length;
                            //assembler.AddData(rect.RectangleData.ImageBytes, tcpPacket.SequenceNumber);
                        }

                    }

                }
            }
        }

        public virtual int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            TcpPacket tcpPacket = null;
            RfbPacket rfbPacket = null;
            foreach (AbstractPacket p in packetList) {
                Type pType = p.GetType();
                if (pType == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
                else if (pType == typeof(RfbPacket)) {
                    rfbPacket = (RfbPacket)p;
                    break;
                }
            }
            if(rfbPacket != null) {
                int skippedBytes = 0;
                System.Collections.Specialized.NameValueCollection parms = new System.Collections.Specialized.NameValueCollection();
                if (!string.IsNullOrEmpty(rfbPacket.ProtocolVersionString)) {
                    parms.Add("Protocol version", rfbPacket.ProtocolVersionString);
                    if(transferIsClientToServer)
                        tcpSession.ClientHost.AddNumberedExtraDetail("VNC viewer protocol version", rfbPacket.ProtocolVersionString);
                    else
                        tcpSession.ServerHost.AddNumberedExtraDetail("VNC server protocol version", rfbPacket.ProtocolVersionString);
                }
                
                if (rfbPacket.PixelFormat.HasValue)
                    this.SetPixelFormat(rfbPacket.PixelFormat.Value, tcpSession, tcpSession.ServerHost, parms);
                if (rfbPacket.ScreenSize.HasValue)
                    this.SetScreenSize(rfbPacket.ScreenSize.Value, parms, tcpSession, tcpSession.ServerHost);
                if (!string.IsNullOrEmpty(rfbPacket.VncDesktopName))
                    this.SetVncDesktopName(rfbPacket.VncDesktopName, parms, tcpSession, tcpSession.ServerHost);
                if (rfbPacket.CommandPacket != null) {
                    this.ExtractCommandPacketDetails(rfbPacket.CommandPacket, tcpSession, tcpSession.ServerHost, parms);
                }
                else if (rfbPacket.ResponsePacket != null) {
                    var responsePacket = rfbPacket.ResponsePacket;
                    //this.ExtractResponsePacketDetails(responsePacket, tcpSession, parms, transferIsClientToServer, ref skippedBytes);
                    this.ExtractResponsePacketDetails(responsePacket, tcpSession, parms, transferIsClientToServer);
                }

                if (parms.Count > 0)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(rfbPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parms, rfbPacket.ParentFrame.Timestamp, "RFB/VNC"));

                return rfbPacket.PacketLength + skippedBytes;
            }
            return 0;
        }

        public virtual void Reset() {
            foreach (VncDesktop desktop in this.vncDesktops.GetValueEnumerator()) {
                desktop.Dispose();
            }
            this.vncDesktops.Clear();
        }

        internal class VncDesktop : IDisposable {

            private SharedUtils.ZlibStream zlibStream = null;//lazy initialization
            private SharedUtils.ZlibStream[] tightZlibStreams;
            private Bitmap _desktopBitmap = null;//lazy initialization
            private long pixelsAddedOnLastScreenshot = 0;



            internal System.Net.IPAddress ServerIP { get; }
            internal string DesktopName { get; set; }
            internal RfbPacket.VncPixelFormat PixelFormat { get; set; }
            internal Size DesktopSize { get; set; }

            internal long PixelsAddedTotal { get; private set; }

            internal long PixelsAddedSinceLastScreenshot {
                get {
                    return this.PixelsAddedTotal - this.pixelsAddedOnLastScreenshot;
                }
            }
            internal DateTime LastScreenshotTimestamp { get; private set; }

            internal VncDesktop(System.Net.IPAddress serverIP) {
                this.PixelsAddedTotal = 0;
                this.ServerIP = serverIP;
                this.tightZlibStreams = new SharedUtils.ZlibStream[4];//stream 0,1,2,3: https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#767tight-encoding
            }

            internal byte[] GetScreenshot(ImageFormat imageFormat, DateTime timestamp) {
                this.pixelsAddedOnLastScreenshot = this.PixelsAddedTotal;
                this.LastScreenshotTimestamp = timestamp;
                if (this.TryGetDesktopBitmap(out Bitmap bitmap)) {
                    using (MemoryStream ms = new MemoryStream()) {
                        bitmap.Save(ms, imageFormat);
                        byte[] imageBytes = new byte[ms.Length];
                        ms.Position = 0;
                        ms.Read(imageBytes, 0, imageBytes.Length);
                        return imageBytes;
                    }
                }
                else
                    return null;
                
            }

            private bool TryGetDesktopBitmap(out Bitmap bitmap) {
                if (this.DesktopSize.Width < 1 || this.DesktopSize.Height < 1) {
                    bitmap = null;
                    return false;
                }
                if (this._desktopBitmap == null)
                    this._desktopBitmap = new Bitmap(this.DesktopSize.Width, this.DesktopSize.Height, this.PixelFormat.GetImagingPixelFormat());
                bitmap = this._desktopBitmap;
                return true;
            }

            private void AddCompressedImageData(SharedUtils.ZlibStream zlibStream, RfbPacket.Rectangle r, Color[] paletteColors = null) {
                zlibStream.Write(r.RectangleData.ImageBytes, 0, r.RectangleData.ImageBytes.Length);
                int bytesToRead = r.Width * r.Height * this.PixelFormat.BytesPerPixel;
                if (paletteColors?.Length == 2) {
                    //If the number of colors is 2, then each pixel is encoded in 1 bit,
                    //otherwise 8 bits are used to encode one pixel.

                    
                    //each row of pixels is aligned to the byte boundary.
                    bytesToRead = ((r.Width + 7) / 8) * r.Height;
                }
                else if(paletteColors?.Length > 2) {
                    //8 bits are used to encode one pixel
                    bytesToRead = r.Width * r.Height;
                }
                byte[] rawImageData = new byte[bytesToRead];
                int bytesRead = zlibStream.Read(rawImageData, 0, bytesToRead);
#if DEBUG
                if (bytesToRead != bytesRead)
                    System.Diagnostics.Debugger.Break();
#endif
                if (paletteColors?.Length == 2) {
                    //each row of pixels is aligned to the byte boundary. 
                    int bytesPerRow = ((r.Width + 7) / 8);
                    for (int x = 0; x < r.Width; x += 8) {
                        for (int y = 0; y < r.Height; y++) {
                            //1-bit encoding is performed such way that
                            //the most significant bits correspond to the leftmost pixels
                            byte b = rawImageData[(x / 8) + y * bytesPerRow];
                            for (int xBit = 0; xBit < 8 && x + xBit < r.Width; xBit++) {
                                this.SetDesktopPixel(r.X + x + xBit, r.Y + y, paletteColors[(b >> (7 - xBit)) & 0x01]);
                                //bitmap.SetPixel(r.X + x + xBit, r.Y + y, paletteColors[(b >> (7 - xBit)) & 0x01]);
                                //this.PixelsAddedTotal++;
                            }
                        }
                    }
                }

                else {
                    for (int x = 0; x < r.Width; x++) {
                        for (int y = 0; y < r.Height; y++) {

                            if (paletteColors?.Length > 2) {
                                //8 bits are used to encode one pixel
                                Color c = paletteColors[rawImageData[x + r.Height * y]];
                                this.SetDesktopPixel(x, y, c);
                            }
                            else if (this.PixelFormat.TryGetColor(rawImageData, this.PixelFormat.BytesPerPixel * (x + r.Width * y), out Color color)) {
                                this.SetDesktopPixel(r.X + x, r.Y + y, color);
                            }
                            else
                                System.Diagnostics.Debugger.Break();

                        }
                    }
                }
            }

            private void SetDesktopPixel(int x, int y, Color color) {
#if DEBUG
                if (x < 0 || x > this.DesktopSize.Width || y < 0 || y > this.DesktopSize.Height)
                    System.Diagnostics.Debugger.Break();
#endif
                if (this.TryGetDesktopBitmap(out Bitmap bitmap)) {
                    bitmap.SetPixel(x, y, color);
                }
                this.PixelsAddedTotal++;
            }

            internal void AddRectangles(params RfbPacket.Rectangle[] rectangles) {
                foreach (RfbPacket.Rectangle r in rectangles) {
                    if (r.TryGetEncoding(out RfbPacket.Rectangle.FrameBufferEncoding encoding)) {
                        if (encoding == RfbPacket.Rectangle.FrameBufferEncoding.Zlib) {

                            if (this.zlibStream == null) {
                                this.zlibStream = new SharedUtils.ZlibStream();
                            }
                            this.AddCompressedImageData(this.zlibStream, r);
                        }
                        else if(encoding == RfbPacket.Rectangle.FrameBufferEncoding.Tight) {
                            TightRectangleData rData = (TightRectangleData)r.RectangleData;
                            if (rData.CompressionMethodOrNull.HasValue) {
                                TightRectangleData.CompressionMethod cm = rData.CompressionMethodOrNull.Value;

                                if (cm == TightRectangleData.CompressionMethod.Fill) {
                                    if (this.PixelFormat.TryGetColor(rData.ImageBytes, 1, out Color color)) {
                                        for (int x = 0; x < r.Width; x++) {
                                            for (int y = 0; y < r.Height; y++) {
                                                if (this.TryGetDesktopBitmap(out Bitmap bitmap)) {
                                                    bitmap.SetPixel(r.X + x, r.Y + y, color);
                                                    this.PixelsAddedTotal++;
                                                }
                                            }
                                        }
                                    }
                                }
                                else if (rData.Compression <= (byte)TightRectangleData.CompressionMethod.Basic_read_filter_s3) {
                                    int stream = rData.Compression % 4;
                                    foreach (int resetStream in rData.GetResetStreams()) {
                                        this.tightZlibStreams[resetStream] = new SharedUtils.ZlibStream();
                                    }
                                    if (this.tightZlibStreams[stream] == null)
                                        this.tightZlibStreams[stream] = new SharedUtils.ZlibStream();
                                    try {
                                        this.AddCompressedImageData(this.tightZlibStreams[stream], r, rData.PaletteColors);
                                    }
                                    catch (System.IO.InvalidDataException e) {
                                        if(e.HResult == -2146233087) {//0x80131501
                                            this.tightZlibStreams[stream] = new SharedUtils.ZlibStream();
                                        }
                                        else
                                            throw;
                                    }

                                }
                                else {
                                    //TODO!!!
                                }
                            }
#if DEBUG
                            else
                                System.Diagnostics.Debugger.Break();
#endif
                        }
                        else if (encoding == RfbPacket.Rectangle.FrameBufferEncoding.Cursor) {
                            //TODO?
                        }
                        else if(encoding == RfbPacket.Rectangle.FrameBufferEncoding.XCursor) {
                            //TODO?
                        }
                        else if(encoding == RfbPacket.Rectangle.FrameBufferEncoding.PointerPosition) {
                            //TODO?
                        }
                        else if(encoding == RfbPacket.Rectangle.FrameBufferEncoding.LastRect) {
                            //TODO?
                        }
#if DEBUG
                        else
                            System.Diagnostics.Debugger.Break();
#endif
                    }
#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif
                }
            }
/*
            private bool TryGetColor(byte[] data, int offset, out Color color) {
                uint colorValue = Utils.ByteConverter.ToUInt32(data, offset, this.PixelFormat.BytesPerPixel, !this.PixelFormat.BigEndian);
                return this.PixelFormat.TryGetColor(colorValue, out color);
            }
*/

            public void Dispose() {
                this.zlibStream?.Dispose();
            }
        }
    }
}
