using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Packets.RfbPacket.VncCommandPacket;
using static PacketParser.Packets.RfbPacket.VncResponsePacket;
using static PacketParser.Packets.IEC_60870_5_104Packet;
using static System.Net.Mime.MediaTypeNames;
using System.Drawing.Imaging;
using static PacketParser.Packets.TcpPacket;
using System.Web.UI.WebControls;
using System.Runtime.InteropServices;
using System.Drawing;

namespace PacketParser.Packets
{
    public class RfbPacket : AbstractPacket {
        //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst

        public enum SecurityType : byte {
            Invalid = 0,
            None = 1,
            VncAuth = 2,
            RSA_AES = 5,
            RSA_AES_Unencrypted = 6,
            SSPI = 7,
            SSPIne = 8,
            Tight = 16,
            Ultra = 17,
            TLS = 18,
            VeNCrypt = 19,
            GTK_VNC_SASL = 20,
            MD5 = 21,
            XVP = 22,
            MAC_OSX_SECTYPE_30 = 30,
            MAC_OSX_SECTYPE_35 = 35,
            ARD = 30,
            //Tight
            TIGHT_AUTH_TGHT_ULGNAUTH = 119,
            TIGHT_AUTH_TGHT_XTRNAUTH = 130,
        }

        protected const int MAX_SCREEN_WIDTH = 8000;
        protected const int MAX_SCREEN_HEIGHT = 8000;



        private static readonly Encoding ISO_8859 = Encoding.GetEncoding("ISO-8859-1");

        /// <summary>
        /// VncPixelFormat is 16 bytes
        /// </summary>
        internal readonly struct VncPixelFormat
        {
            //VNC Pixel Format is defined here:
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#732serverinit
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#741setpixelformat

            /// <summary>
            /// Bits-per-pixel is the number of bits used for each pixel value on the wire. This must be greater than or equal to depth, which is the number of useful bits in the pixel value. Currently bits-per-pixel must be 8, 16 or 32. Less than 8-bit pixels are not yet supported. Big-endian-flag is non-zero (true) if multi-byte pixels are interpreted as big endian. Of course this is meaningless for 8 bits-per-pixel.
            /// </summary>
            internal readonly byte BitsPerPixel;

            internal int BytesPerPixel {
                get {
                    return (this.BitsPerPixel + 7) / 8;
                }
            }
            /// <summary>
            /// Depth should be the sum of bits used according to red-max, green-max, and blue-max, or the number of bits needed for indices in the colour map, depending on the value of true-color-flag. Note that some servers will send a depth that is identical to bits-per-pixel for historical reasons.
            /// </summary>
            internal readonly byte Depth;
            /// <summary>
            /// If true-colour-flag is non-zero (true): Swap the pixel value according to big-endian-flag (e.g. if big-endian-flag is zero (false) and host byte order is big endian, then swap).
            /// </summary>
            internal readonly bool BigEndian;
            /// <summary>
            /// If true-colour-flag is non-zero (true) then the last six items specify how to extract the red, green and blue intensities from the pixel value. Red-max is the maximum red value (= 2^n - 1 where n is the number of bits used for red). Note this value is always in big endian order. Red-shift is the number of shifts needed to get the red value in a pixel to the least significant bit. Green-max, green-shift and blue-max, blue-shift are similar for green and blue.
            /// If true-colour-flag is zero (false) then the server uses pixel values which are not directly composed from the red, green and blue intensities, but which serve as indices into a colour map. Entries in the colour map are set by the server using the SetColourMapEntries message (SetColourMapEntries).
            /// </summary>
            internal readonly bool TrueColour;
            internal readonly ushort RedMax;
            internal readonly ushort GreenMax;
            internal readonly ushort BlueMax;
            internal readonly byte RedShift;
            internal readonly byte GreenShift;
            internal readonly byte BlueShift;

            internal VncPixelFormat(byte[] data, int offset)
            {

                /**
                 * +--------------+--------------+-----------------+
                 * | No. of bytes | Type [Value] | Description     |
                 * +--------------+--------------+-----------------+
                 * | 1            | U8           | bits-per-pixel  |
                 * | 1            | U8           | depth           |
                 * | 1            | U8           | big-endian-flag |
                 * | 1            | U8           | true-color-flag |
                 * | 2            | U16          | red-max         |
                 * | 2            | U16          | green-max       |
                 * | 2            | U16          | blue-max        |
                 * | 1            | U8           | red-shift       |
                 * | 1            | U8           | green-shift     |
                 * | 1            | U8           | blue-shift      |
                 * | 3            |              | padding         |
                 * +--------------+--------------+-----------------+
                */

                BitsPerPixel = data[offset + 0];
                Depth = data[offset + 1];
                BigEndian = data[offset + 2] != 0;
                TrueColour = data[offset + 3] != 0;
                RedMax = (ushort)(data[offset + 5] | data[offset + 4] << 8);
                GreenMax = (ushort)(data[offset + 7] | data[offset + 6] << 8);
                BlueMax = (ushort)(data[offset + 9] | data[offset + 8] << 8);
                RedShift = data[offset + 10];
                GreenShift = data[offset + 11];
                BlueShift = data[offset + 12];
                //3 bytes padding should be all zeroes
            }

            public bool TryGetColor(byte[] data, int offset, out Color color) {
                uint colorValue = Utils.ByteConverter.ToUInt32(data, offset, this.BytesPerPixel, !this.BigEndian);
                return this.TryGetColor(colorValue, out color);
            }

            public bool TryGetColor(uint colorValue, out Color color) {
                if (this.TrueColour) {
                    byte red = GetColorIntensity(colorValue, this.RedShift, this.RedMax);
                    byte green = GetColorIntensity(colorValue, this.GreenShift, this.GreenMax);
                    byte blue = GetColorIntensity(colorValue, this.BlueShift, this.BlueMax);
                    color = Color.FromArgb(red, green, blue);
                    return true;
                }
                else {
                    color = Color.FromArgb((int)colorValue);
                    return false;
                }
            }

            private static byte GetColorIntensity(uint colorValue, byte shift, ushort max) {
                int intensityCorrectionShift = 8 - SharedUtils.MathUtils.CountBitsInMask(max);
                return (byte)(((colorValue >> shift) & max) << intensityCorrectionShift);
            }

            public override string ToString()
            {
                return BitsPerPixel.ToString() + " bits per pixel";
            }

            internal System.Drawing.Imaging.PixelFormat GetImagingPixelFormat() {
                if (this.TrueColour) {
                    //Currently bits-per-pixel must be 8, 16 or 32
                    if (this.Depth == 16 || this.BitsPerPixel == 16)
                        return System.Drawing.Imaging.PixelFormat.Format16bppRgb555;
                    else if (this.Depth == 8 || this.BitsPerPixel == 8)
                        return System.Drawing.Imaging.PixelFormat.Format32bppRgb;
                    else
                        return System.Drawing.Imaging.PixelFormat.Format24bppRgb;
                }
                else
                    return System.Drawing.Imaging.PixelFormat.Indexed;
            }
        }

        #region Static functions
        internal static bool TryParseVncPixelFormat(byte[] data, int offset, out VncPixelFormat vncPixelFormat)
        {
            if (data.Length >= offset + 16)
            {
                //check that padding is zeroes
                if (data[offset + 13] == 0 && data[offset + 14] == 0 && data[offset + 15] == 0)
                {
                    //check that bits per pixel > 0 and <= 32 and depth <= 32
                    if (data[offset] > 0 && data[offset] <= 32 && data[offset + 1] <= 32)
                    {
                        vncPixelFormat = new VncPixelFormat(data, offset);
                        return true;
                    }
                }
            }
            vncPixelFormat = default;
            return false;
        }

        internal static bool TryGetCutTextPacketLength(Frame parentFrame, int packetStartIndex, int packetEndIndex, out int cutTextPacketLength)
        {
            cutTextPacketLength = -1;
            if (packetEndIndex < packetStartIndex + 7)
                return false;
            int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            if (length < 0)
            {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                //A negative value of length indicates that the extended message format is used and abs(length) is the total number of following bytes.
                length = -length;
                if (length < 4)
                    return false;//there must be space for the flags
            }
            if (length >= 0)
            {
                if (packetEndIndex < packetStartIndex + 7 + length)
                    return false;
                cutTextPacketLength = 8 + length;
            }
            return cutTextPacketLength > 7;
        }

        public static bool TryParseHandshake(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out RfbPacket rfbPacket) {
            rfbPacket = null;
            int offset = packetStartIndex;
            if (TryParseProtocolVersion(parentFrame, packetStartIndex, packetEndIndex, out string protocolVersionString, out int bytesParsed)) {
                //ProtocolVersion
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                rfbPacket.ProtocolVersionString = protocolVersionString;
            }
            else if (!clientToServer && TryGetServerSecurityTypes(parentFrame, packetStartIndex, packetEndIndex, out byte[] securityTypes, out bytesParsed)) {
                //Security server
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                rfbPacket.SecurityTypes = securityTypes.Where(st => Enum.IsDefined(typeof(SecurityType), st)).Select(st => (SecurityType)st).ToArray();
            }
            else if (clientToServer && TryGetClientSecurityType(parentFrame, packetStartIndex, packetEndIndex, out byte securityType, out bytesParsed)) {
                //Security client
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                if (Enum.IsDefined(typeof(SecurityType), securityType)) {
                    rfbPacket.SecurityTypes = new[] { (SecurityType)securityType };
                }
            }
            else if(!clientToServer && packetStartIndex + 3 == packetEndIndex) {
                //Security Result
                //0 = OK, 1 = failed, 2 = failed, too many attempts
                if (parentFrame.Data[packetStartIndex] == 0 && parentFrame.Data[packetStartIndex + 1] == 0 && parentFrame.Data[packetStartIndex + 2] == 0 && parentFrame.Data[packetStartIndex + 3] < 3) {
                    rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                }
            }
            else if(packetStartIndex + 15 == packetEndIndex && SharedUtils.MathUtils.GetEntropy(parentFrame.Data, packetStartIndex, 16) > 3.2) {
                //16 bytes of high-entropy data might indicate that this is an auth challange or response
                //The maximum entropy here is 4.0 because the input is only 16 bytes long
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);

            }
            else if(clientToServer && packetStartIndex == packetEndIndex) {
                //Client Init
                byte sharedFlag = parentFrame.Data[packetStartIndex];
                if (sharedFlag == 0 || sharedFlag == 1)//this flag can in theory have any value, but most implementations use 1 for true
                    rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
            }
            else if(!clientToServer && TryParseServerInit(parentFrame.Data, ref offset, out ushort width, out ushort height, out VncPixelFormat pf, out string desktopName)) {
                //ServerInit
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                rfbPacket.PixelFormat = pf;
                rfbPacket.ScreenSize = new System.Drawing.Size(width, height);
                rfbPacket.VncDesktopName = desktopName;
            }
            return rfbPacket != null;
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out RfbPacket rfbPacket) {
            rfbPacket = null;
            int offset = packetStartIndex;

            try
            {
                if (clientToServer)
                {
                    /*
                    //VNC Command from viewer
                    if (packetStartIndex == packetEndIndex && (parentFrame.Data[packetEndIndex] == 0x06 || parentFrame.Data[packetEndIndex] == 0x0a))
                    {
                        //ClientInit??
                        var vncCommandPacket = new VncCommandPacket(parentFrame, packetStartIndex, packetEndIndex, true);
                        rfbPacket = new RfbPacket(vncCommandPacket);
                    }
                    else 
                    */
                    if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.SetPixelFormat)
                    {
                        if (SetPixelFormatPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out SetPixelFormatPacket setPixelFormatPacket, false))
                            rfbPacket = new RfbPacket(setPixelFormatPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.SetEncodings)
                    {
                        if (SetEncodingsPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out SetEncodingsPacket setEncodingPacket))
                            rfbPacket = new RfbPacket(setEncodingPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.FramebufferUpdateRequest)
                    {
                        if (FrameBufferUpdateRequestPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out FrameBufferUpdateRequestPacket frameBufferUpdateRequestPacket))
                            rfbPacket = new RfbPacket(frameBufferUpdateRequestPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.PointerEvent)
                    {
                        /***
                         * Bytes    Value   Field Name
                         * 1        0x05    message-type
                         * 1                button-mask
                         * 2                x-position
                         * 2                y-position
                         **/
                        if (packetStartIndex + 5 <= packetEndIndex)
                        {
                            var pointerEventPacket = new VncCommandPacket(parentFrame, packetStartIndex, packetStartIndex + 5, clientToServer);
                            rfbPacket = new RfbPacket(pointerEventPacket);
                        }
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.ClientCutText)
                    {
                        if (ClientCutTextPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out ClientCutTextPacket clientCutTextPacket))
                            rfbPacket = new RfbPacket(clientCutTextPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.KeyEvent)
                    {
                        var keyPacket = new KeyEventPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        rfbPacket = new RfbPacket(keyPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.FixColourMapEntries)
                    {
                        //https://www.dei.isep.ipp.pt/~asc/normas/rfbproto.pdf
                        //https://xvm.scripts.mit.edu/browser/trunk/packages/invirt-vnc-client/RfbProto.java?rev=1588#L889
                        //https://libvnc.github.io/doc/html/structrfb_set_colour_map_entries_msg.html
                        if (FixColorMapPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out FixColorMapPacket cmPacket))
                        {
                            rfbPacket = new RfbPacket(cmPacket);
                        }
                    }
#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif
                }
                else
                {
                    //VNC response data to viewer
                    if (parentFrame.Data[packetStartIndex] == (byte)VncResponseCode.FramebufferUpdate)
                    {
                        if (FrameBufferUpdatePacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, true, out FrameBufferUpdatePacket updatePacket))
                            rfbPacket = new RfbPacket(updatePacket);
                        else if (FrameBufferUpdatePacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, false, out updatePacket))
                            rfbPacket = new RfbPacket(updatePacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncResponseCode.ServerCutText) {
                        if (ServerCutTextPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out ServerCutTextPacket cutText)) {
                            rfbPacket = new RfbPacket(cutText);
                        }
                    }
                    else if (!Enum.IsDefined(typeof(VncResponseCode), parentFrame.Data[packetStartIndex]))
                    {
                        //something's wrong, there might be missing packets in the PCAP
                        var unknownPacket = new VncResponsePacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        rfbPacket = new RfbPacket(unknownPacket);
                    }

#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif
                }
            }
            catch (Exception e)
            {
                return false;
            }
            return rfbPacket != null;
        }

        private static bool TryParseProtocolVersion(Frame parentFrame, int packetStartIndex, int packetEndIndex, out string protocolVersionString, out int bytesParsed) {
            //12 bytes "RFB 003.0xx\n"
            if (packetEndIndex > packetStartIndex + 10) {
                if (parentFrame.Data[packetStartIndex + 11] == 0x0a) {
                    byte[] firstBytes = Encoding.ASCII.GetBytes("RFB 00");
                    if (parentFrame.Data.Skip(packetStartIndex).Take(firstBytes.Length).SequenceEqual(firstBytes)) {
                        protocolVersionString = Encoding.ASCII.GetString(parentFrame.Data, packetStartIndex, 12).TrimEnd();
                        bytesParsed = 12;
                        return true;
                    }
                }
            }
            protocolVersionString = null;
            bytesParsed = 0;
            return false;

        }

        private static bool TryGetServerSecurityTypes(Frame parentFrame, int packetStartIndex, int packetEndIndex, out byte[] securityTypes, out int bytesParsed) {
            if(packetStartIndex + 3 == packetEndIndex && parentFrame.Data[packetStartIndex] == 0 && parentFrame.Data[packetStartIndex + 1] == 0 && parentFrame.Data[packetStartIndex + 2] == 0 && parentFrame.Data[packetStartIndex + 3] != 0) {
                //The server decides the security type and sends a single word
                if (Enum.IsDefined(typeof(SecurityType), parentFrame.Data[packetStartIndex + 3])) {
                    securityTypes = new byte[] { parentFrame.Data[packetStartIndex + 3] };
                    bytesParsed = 4;
                    return true;
                }
            }
            else if(packetEndIndex > packetStartIndex) {
                byte numberOfTypes = parentFrame.Data[packetStartIndex];
                if(numberOfTypes > 0 && numberOfTypes < 10 && packetEndIndex == packetStartIndex + numberOfTypes) {
                    //we have at least one security type
                    securityTypes = new byte[numberOfTypes];
                    Array.Copy(parentFrame.Data, packetStartIndex + 1, securityTypes, 0, securityTypes.Length);
                    if (!securityTypes.Any(st => st == 0)) {
                        //verify that the majority of the types are known to reduce false positives
                        int knownTypes = securityTypes.Where(st => Enum.IsDefined(typeof(SecurityType), st)).Count();
                        if (knownTypes * 2 > securityTypes.Length) {
                            bytesParsed = 1 + numberOfTypes;
                            return true;
                        }
                    }
                }
            }
            bytesParsed = 0;
            securityTypes = null;
            return false;
        }
        private static bool TryGetClientSecurityType(Frame parentFrame, int packetStartIndex, int packetEndIndex, out byte securityType, out int bytesParsed) {
            if (packetStartIndex == packetEndIndex) {
                //The server decides the security type and sends a single word
                if (parentFrame.Data[packetStartIndex] != 0 && Enum.IsDefined(typeof(SecurityType), parentFrame.Data[packetStartIndex])) {
                    securityType = parentFrame.Data[packetStartIndex];
                    bytesParsed = 1;
                    return true;
                }
            }
            bytesParsed = 0;
            securityType = 0;
            return false;
        }

        #endregion

        internal readonly VncCommandPacket CommandPacket = null;
        internal readonly VncResponsePacket ResponsePacket = null;
        internal string ProtocolVersionString = null;
        internal SecurityType[] SecurityTypes = null;
        internal VncPixelFormat? PixelFormat { get; set; } = null;
        internal System.Drawing.Size? ScreenSize { get; set; } = null;
        internal string VncDesktopName { get; set; } = null;

        internal RfbPacket(VncCommandPacket commandPacket) : base(commandPacket.ParentFrame, commandPacket.PacketStartIndex, commandPacket.PacketEndIndex, "RFB")
        {
            CommandPacket = commandPacket;
        }

        internal RfbPacket(VncResponsePacket responsePacket) : base(responsePacket.ParentFrame, responsePacket.PacketStartIndex, responsePacket.PacketEndIndex, "RFB")
        {
            ResponsePacket = responsePacket;
        }

        [Obsolete]
        protected internal RfbPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool transferIsClientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "RFB")
        {

        }

        //https://www.rfc-editor.org/rfc/rfc6143.html
        //Remote Framebuffer Protocol
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
        {
            if (includeSelfReference)
                yield return this;
            if (CommandPacket != null)
                yield return CommandPacket;
            if (ResponsePacket != null)
                yield return ResponsePacket;
        }

        #region VNC respones to viewer

        internal class VncResponsePacket : AbstractPacket
        {


            internal enum VncResponseCode : byte
            { //sent to viewer
                FramebufferUpdate = 0,
                SetColourMapEntries = 1,
                Bell = 2,
                ServerCutText = 3
            }


            internal static bool TryParseServerInit(byte[] data, ref int offset, out ushort width, out ushort height, out VncPixelFormat pixelFormat, out string desktopName)
            {
                //ServerInit

                /**
                 *  +--------------+--------------+------------------------------+
                 *  | No. of bytes | Type [Value] | Description                  |
                 *  +--------------+--------------+------------------------------+
                 *  | 2            | U16          | framebuffer-width in pixels  |
                 *  | 2            | U16          | framebuffer-height in pixels |
                 *  | 16           | PIXEL_FORMAT | server-pixel-format          |
                 *  | 4            | U32          | name-length                  |
                 *  | name-length  | U8 array     | name-string                  |
                 *  +--------------+--------------+------------------------------+
                */
                //minimum length is 24 bytes (2 + 2 + 16 + 4 + ?)
                if (data.Length >= offset + 24)
                {
                    int stringLength = (int)Utils.ByteConverter.ToUInt32(data, offset + 20, 4, false);//big endian
                    if (stringLength < 100 && data.Length >= offset + 24 + stringLength)
                    {
                        width = Utils.ByteConverter.ToUInt16(data, offset);
                        height = Utils.ByteConverter.ToUInt16(data, offset + 2);
                        //this code allows 0x0 and 1x1 frame buffer sizes as well as anything between 16 and MAX_SCREEN_*
                        if ((width == height || (width > 15 && height > 15)) && width < MAX_SCREEN_WIDTH && height < MAX_SCREEN_HEIGHT) { 
                            if (TryParseVncPixelFormat(data, offset + 4, out pixelFormat))
                            {
                                try
                                {
                                    desktopName = Encoding.ASCII.GetString(data, offset + 24, stringLength);
                                    offset += 24 + stringLength;
                                    return true;
                                }
                                catch
                                {
                                    desktopName = null;
                                    return false;
                                }
                            }
                        }
                    }
                }

                width = 0;
                height = 0;
                pixelFormat = default;
                desktopName = null;
                return false;
            }

            

            public VncResponseCode ResponseCode { get; }

            public VncResponsePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool isClientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "VNC Response")
            {
                byte responseCode = parentFrame.Data[packetStartIndex];
                if (Enum.IsDefined(typeof(VncResponseCode), responseCode))
                    ResponseCode = (VncResponseCode)responseCode;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
            {
                if (includeSelfReference)
                    yield return this;
            }

        }

        #endregion

        #region VNC commands from viewer

        internal class VncCommandPacket : AbstractPacket
        {
            //https://www.rfc-editor.org/rfc/rfc6143.html

            internal enum VncCommand : byte
            { //sent from viewer
                SetPixelFormat = 0,
                FixColourMapEntries = 1,
                SetEncodings = 2,
                FramebufferUpdateRequest = 3,
                KeyEvent = 4,
                PointerEvent = 5,
                ClientCutText = 6,
            }



            internal VncCommand Command { get; }

            public VncPixelFormat? PixelFormat { get; internal set; } = null;

            public VncCommandPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect Reverse VNC")
            {
                byte command = parentFrame.Data[packetStartIndex];
                if (Enum.IsDefined(typeof(VncCommand), command))
                    Command = (VncCommand)command;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
            {
                if (includeSelfReference)
                    yield return this;
            }

        }

        internal class KeyEventPacket : VncCommandPacket
        {


            internal enum SpecialKeys : uint
            {
                BackSpace = 0xff08,
                Tab = 0xff09,
                Return = 0xff0d,
                Escape = 0xff1b,
                Insert = 0xff63,
                Delete = 0xffff,
                Home = 0xff50,
                End = 0xff57,
                Page_Up = 0xff55,
                Page_Down = 0xff56,
                Left = 0xff51,
                Up = 0xff52,
                Right = 0xff53,
                Down = 0xff54,
                F1 = 0xffbe,
                F2 = 0xffbf,
                F3 = 0xffc0,
                F4 = 0xffc1,
                F5 = 0xffc1,
                F6 = 0xffc2,
                F7 = 0xffc3,
                F8 = 0xffc4,
                F9 = 0xffc5,
                F10 = 0xffc6,
                F11 = 0xffc7,
                F12 = 0xffc9,
                Shift_left = 0xffe1,
                Shift_right = 0xffe2,
                Control_left = 0xffe3,
                Control_right = 0xffe4,
                Meta_left = 0xffe7,
                Meta_right = 0xffe8,
                Alt_left = 0xffe9,
                Alt_right = 0xffea,
                //https://github.com/RaiMan/sikulix2tigervnc/blob/682ba518bc1f4d9f790c0bd92d19582249507ea4/src/main/java/com/tigervnc/rfb/Keysyms.java#L110
                KeyPad_Enter = 0xFF8D,
                KeyPad_Home = 0xFF95,
                KeyPad_Left = 0xFF96,
                KeyPad_Up = 0xFF97,
                KeyPad_Right = 0xFF98,
                KeyPad_Down = 0xFF99,
                KeyPad_Page_Up = 0xFF9A,
                KeyPad_Page_Down = 0xFF9B,
                KeyPad_End = 0xFF9C,
                KeyPad_Begin = 0xFF9D,
                KeyPad_Insert = 0xFF9E,
                KeyPad_Delete = 0xFF9F,
                KeyPad_Equal = 0xFFBD,
                KeyPad_0 = 0xFFB0,
                KeyPad_1 = 0xFFB1,
                KeyPad_2 = 0xFFB2,
                KeyPad_3 = 0xFFB3,
                KeyPad_4 = 0xFFB4,
                KeyPad_5 = 0xFFB5,
                KeyPad_6 = 0xFFB6,
                KeyPad_7 = 0xFFB7,
                KeyPad_8 = 0xFFB8,
                KeyPad_9 = 0xFFB9,
                KeyPad_Decimal = 0xFFAE,
                KeyPad_Add = 0xFFAB,
                KeyPad_Subtract = 0xFFAD,
                KeyPad_Multiply = 0xFFAA,
                KeyPad_Divide = 0xFFAF,
                //https://github.com/RaiMan/sikulix2tigervnc/blob/682ba518bc1f4d9f790c0bd92d19582249507ea4/src/main/java/com/tigervnc/rfb/Keysyms.java#L94
                Select = 0xFF60,
                Print = 0xFF61,
                Execute = 0xFF62,
                //Insert = 0xFF63,
                Undo = 0xFF65,
                Redo = 0xFF66,
                Menu = 0xFF67,
                Find = 0xFF68,
                Cancel = 0xFF69,
                Help = 0xFF6A,
                Break = 0xFF6B,
                Mode_switch = 0xFF7E,
                script_switch = 0xFF7E,
                Num_Lock = 0xFF7F,
            }

            internal string Key { get; }
            internal bool Down { get; }

            internal KeyEventPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                /***
                 * +--------------+--------------+--------------+
                 * | No. of bytes | Type [Value] | Description  |
                 * +--------------+--------------+--------------+
                 * | 1            | U8 [4]       | message-type |
                 * | 1            | U8           | down-flag    |
                 * | 2            |              | padding      |
                 * | 4            | U32          | key          |
                 * +--------------+--------------+--------------+
                 **/
                PacketEndIndex = packetStartIndex + 7;
                Down = parentFrame.Data[PacketStartIndex + 1] != 0;
                uint key = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (Enum.IsDefined(typeof(SpecialKeys), key))
                {
                    Key = "[" + (SpecialKeys)key + "]";
                }
                else if (char.IsControl((char)key))
                    Key = "[0x" + key.ToString("x8") + "]";
                else if (key > 0 && key < 127)
                    Key = "" + (char)key;
                else
                    Key = "" + (char)key + " [0x" + key.ToString("x8") + "]";
            }

            public override string ToString()
            {
                if (Down)
                    return Key + " pressed";
                else
                    return Key + " released";
            }
        }

        internal class FixColorMapPacket : VncCommandPacket
        {

            internal static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out FixColorMapPacket cmPacket)
            {
                cmPacket = null;
                if (packetStartIndex + 5 > packetEndIndex)
                    return false;
                ushort numberOfColors = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                int length = 6 + 6 * numberOfColors;
                if (packetStartIndex + length > packetEndIndex + 1)
                    return false;
                else
                    cmPacket = new FixColorMapPacket(parentFrame, packetStartIndex, packetStartIndex + length - 1, clientToServer);

                return cmPacket != null;
            }

            internal ushort NumberOfColors { get; }
            //https://www.dei.isep.ipp.pt/~asc/normas/rfbproto.pdf
            //https://xvm.scripts.mit.edu/browser/trunk/packages/invirt-vnc-client/RfbProto.java?rev=1588#L889
            //https://libvnc.github.io/doc/html/structrfb_set_colour_map_entries_msg.html
            /**
             * No. of bytes Type [Value] Description
             * 1 message-type
             * 1 padding
             * 2 first-colour
             * 2 number-of-colours
             * [number-of-colours] {
             *      2 red
             *      2 green
             *      2 blue
             *  }
             * */
            private FixColorMapPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                //read length
                NumberOfColors = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                PacketEndIndex = packetStartIndex + 6 + 6 * NumberOfColors - 1;
            }
        }


        internal class SetPixelFormatPacket : VncCommandPacket
        {

            /**
             * +--------------+--------------+--------------+
             * | No. of bytes | Type [Value] | Description  |
             * +--------------+--------------+--------------+
             * | 1            | U8 [0]       | message-type |
             * | 3            |              | padding      |
             * | 16           | PIXEL_FORMAT | pixel-format |
             * +--------------+--------------+--------------+
            */

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out SetPixelFormatPacket packet, bool requireZeroValuePadding = true)
            {
                packet = null;
                if (parentFrame.Data[packetStartIndex] != (byte)VncCommand.SetPixelFormat)
                    return false;

                if (packetEndIndex < packetStartIndex + 19)
                    return false;

                if (requireZeroValuePadding) {
                    for (int i = 1; i < 4; i++) {
                        //padding
                        if (parentFrame.Data[packetStartIndex + i] != 0)
                            return false;
                    }
                }


                if (TryParseVncPixelFormat(parentFrame.Data, packetStartIndex + 4, out _))
                {
                    packet = new SetPixelFormatPacket(parentFrame, packetStartIndex, packetStartIndex + 19, clientToServer);
                    return true;
                }
                else
                    return false;
            }
            private SetPixelFormatPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                if (TryParseVncPixelFormat(parentFrame.Data, packetStartIndex + 4, out VncPixelFormat pf))
                {
                    PixelFormat = pf;
                    PacketEndIndex = packetStartIndex + 19;
                }
                else
                    throw new Exception("Unable to parse PixelFormat");
            }

            internal new VncCommand? Command
            {
                get { return VncCommand.SetPixelFormat; }
            }

        }

        internal class SetEncodingsPacket : VncCommandPacket
        {

            List<uint> Encodings = new List<uint>();

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out SetEncodingsPacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 3)//min 4 bytes
                    return false;
                if (parentFrame.Data[packetStartIndex] != (byte)VncCommand.SetEncodings)
                    return false;
                //one byte padding
                //if (parentFrame.Data[packetStartIndex + 1] != 0)
                //    return false;
                ushort encodingCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                int realPacketEndIndex = packetStartIndex + 3 + encodingCount * 4;
                if (packetEndIndex < realPacketEndIndex)
                    return false;
                //encoding count is a 16 bit number, big endian
                //each encoding is 32 bits (4 bytes)
                packet = new SetEncodingsPacket(parentFrame, packetStartIndex, realPacketEndIndex, clientToServer);
                return true;
            }

            private SetEncodingsPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                ushort encodingCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                for (int i = 0; i < encodingCount; i++)
                {
                    Encodings.Add(Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4 + 4 * i));
                }
            }

            internal new VncCommand? Command
            {
                get { return VncCommand.SetEncodings; }
            }
        }

        internal class FrameBufferUpdateRequestPacket : VncCommandPacket
        {
            public readonly byte Incremental;
            public readonly ushort X;
            public readonly ushort Y;
            public readonly ushort Width;
            public readonly ushort Height;

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out FrameBufferUpdateRequestPacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 9)
                    return false;
                var x = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                var y = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                var width = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                var height = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
                if (width == 0 || height == 0)
                    return false;
                if (width > MAX_SCREEN_WIDTH || height > MAX_SCREEN_HEIGHT)
                    return false;
                if (x > MAX_SCREEN_WIDTH || y > MAX_SCREEN_HEIGHT)
                    return false;

                packet = new FrameBufferUpdateRequestPacket(parentFrame, packetStartIndex, packetStartIndex + 9, clientToServer);
                return true;
            }

            private FrameBufferUpdateRequestPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                PacketEndIndex = packetStartIndex + 9;//lenth is 10 bytes
                Incremental = parentFrame.Data[packetStartIndex];
                X = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                Y = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                Width = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                Height = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
            }

        }

        internal class ClientCutTextPacket : VncCommandPacket
        {

            internal string Text { get; }

            internal uint FormatFlags { get; }


            internal static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ClientCutTextPacket clientCutTextPacket)
            {
                clientCutTextPacket = null;

                if (TryGetCutTextPacketLength(parentFrame, packetStartIndex, packetEndIndex, out int cutTextPacketLength))
                {
                    int newPacketEndIndex = packetStartIndex + cutTextPacketLength - 1;
                    clientCutTextPacket = new ClientCutTextPacket(parentFrame, packetStartIndex, newPacketEndIndex, clientToServer);
                }

                return clientCutTextPacket != null;
            }


            private ClientCutTextPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                /**
                 * +--------------+--------------+--------------+
                 * | No. of bytes | Type [Value] | Description  |
                 * +--------------+--------------+--------------+
                 * | 1            | U8 [6]       | message-type |
                 * | 3            |              | padding      |
                 * | 4            | U32          | length       |
                 * | length       | U8 array     | text         |
                 * +--------------+--------------+--------------+
                 * */
                int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (length >= 0)
                {
                    PacketEndIndex = packetStartIndex + 7 + length;
                    Text = ISO_8859.GetString(parentFrame.Data, packetStartIndex + 8, length);
                }
                else
                {
                    //Extended Clipboard Pseudo-Encoding
                    //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                    length = -length;
                    PacketEndIndex = packetStartIndex + 7 + length;
                    /*
                     * 0   text
                     * 1   rtf
                     * 2   html
                     * 3   dib
                     * 4   files
                     * 5 - 15    Reserved for future formats
                     * 16 - 23   Reserved
                     * 24  caps
                     * 25  request
                     * 26  peek
                     * 27  notify
                     * 28  provide
                     * 29 - 31   Reserved for future actions
                     * */
                    FormatFlags = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
                    //skipping the clipboard data here
                }
            }
        }

        internal class Rectangle
        {



            /**
             * Example Packet Header:
             * 0000 0001 0000 0000 0040 0040 0000 0006 ???? ???? ???? 
             * t p   1   \ X   Y    w    h   encoding  data         /
             * y a count  `----one rectangle-----------------------´
             * p d
             * e
             */

            /**
             *  +--------+-----------------------------+
             *  | Number | Name                        |
             *  +--------+-----------------------------+
             *  | 0      | Raw                         |
             *  | 1      | CopyRect                    |
             *  | 2      | RRE                         |
             *  | 5      | Hextile                     |
             *  | 15     | TRLE                        |
             *  | 16     | ZRLE                        |
             *  | -239   | Cursor pseudo-encoding      |
             *  | -223   | DesktopSize pseudo-encoding |
             *  +--------+-----------------------------+
             *  
             *  https://en.wikipedia.org/wiki/RFB_protocol#Encoding_types
             *  0x00000000 	Raw
             *  0x00000001 	CopyRect
             *  0x00000002 	RRE (Rising Rectangle Run-length)
             *  0x00000004 	CoRRE (Compact RRE)
             *  0x00000005 	Hextile (RRE Variant)
             *  0x00000006 	Zlib
             *  0x00000007 	Tight
             *  0x00000008 	ZlibHex (Zlib + Hextile)
             *  0x00000009 	Ultra
             *  0x00000010 	ZRLE (Zlib Run-length)
             *  0x00000011 	ZYWRLE
             *  0x00000014 	H.264
             *  0x00000032 	Open H.264
             *  0xFFFF0001 	CacheEnable
             *  0xFFFF0006 	XOREnable
             *  0xFFFF8000 	ServerState (UltraVNC)
             *  0xFFFF8001 	EnableKeepAlive (UltraVNC)
             *  0xFFFF8002 	FTProtocolVersion (File Transfer Protocol Version - UltraVNC)
             *  0xFFFFFEC7 	ContinuousUpdates
             *  0xFFFFFEC8 	Fence
             *  0xFFFFFECC 	ExtendedDesktopSize
             *  0xFFFFFECF 	General Input Interface (GII)
             *  0xFFFFFF00–0xFFFFFF09 	CompressLevel (Tight encoding)
             *  0xFFFFFF10 	XCursor
             *  0xFFFFFF11 	RichCursor
             *  0xFFFFFF18 	PointerPos
             *  0xFFFFFF20 	LastRect
             *  0xFFFFFF21 	NewFBSize
             *  0xFFFFFF74 	Tight PNG
             *  0xFFFFFFE0–0xFFFFFFE9 	QualityLevel (Tight encoding)   
             *  
            */
            internal enum FrameBufferEncoding : int {
                Raw = 0,
                CopyRect = 1,
                RRE = 2,
                Hextile = 5,
                Zlib = 6,
                Tight = 7,
                ZlibHex = 8,
                Ultra = 9,

                TRLE = 15,
                ZRLE = 16,
                JPEG = 21,
                
                ExtendedDesktopSize = -308,//ffff fecc
                XCursor = -240,//ffff ff10
                Cursor = -239,//ffff ff11
                PointerPosition = -232,//FFFF FF18
                LastRect = -224,//FFFF FF20 Used in Tight encoding to denote that there are no more rectangles
                DesktopSize = -223,//ffff ff21 = NewFBSize
                
            }

            /**
             * #define VNC_ENCODING_TYPE_DESKTOP_SIZE       0xFFFFFF21
#define VNC_ENCODING_TYPE_LAST_RECT          0xFFFFFF20
#define VNC_ENCODING_TYPE_POINTER_POS        0xFFFFFF18
#define VNC_ENCODING_TYPE_RICH_CURSOR        0xFFFFFF11
#define VNC_ENCODING_TYPE_X_CURSOR           0xFFFFFF10
#define VNC_ENCODING_TYPE_RAW                0
#define VNC_ENCODING_TYPE_COPY_RECT          1
#define VNC_ENCODING_TYPE_RRE                2
#define VNC_ENCODING_TYPE_CORRE              4
#define VNC_ENCODING_TYPE_HEXTILE            5
#define VNC_ENCODING_TYPE_ZLIB	             6
#define VNC_ENCODING_TYPE_TIGHT	             7
#define VNC_ENCODING_TYPE_ZLIBHEX            8
#define VNC_ENCODING_TYPE_ULTRA	             9
#define VNC_ENCODING_TYPE_TRLE	             15
#define VNC_ENCODING_TYPE_RLE	             16
#define VNC_ENCODING_TYPE_HITACHI_ZYWRLE     17
#define VNC_ENCODING_TYPE_JPEG_0             -32
#define VNC_ENCODING_TYPE_JPEG_1             -31
#define VNC_ENCODING_TYPE_JPEG_2             -30
#define VNC_ENCODING_TYPE_JPEG_3             -29
#define VNC_ENCODING_TYPE_JPEG_4             -28
#define VNC_ENCODING_TYPE_JPEG_5             -27
#define VNC_ENCODING_TYPE_JPEG_6             -26
#define VNC_ENCODING_TYPE_JPEG_7             -25
#define VNC_ENCODING_TYPE_JPEG_8             -24
#define VNC_ENCODING_TYPE_JPEG_9             -23
#define VNC_ENCODING_TYPE_COMPRESSION_0      0xFFFFFF00
#define VNC_ENCODING_TYPE_COMPRESSION_1      0xFFFFFF01
#define VNC_ENCODING_TYPE_COMPRESSION_2      0xFFFFFF02
#define VNC_ENCODING_TYPE_COMPRESSION_3      0xFFFFFF03
#define VNC_ENCODING_TYPE_COMPRESSION_4      0xFFFFFF04
#define VNC_ENCODING_TYPE_COMPRESSION_5      0xFFFFFF05
#define VNC_ENCODING_TYPE_COMPRESSION_6      0xFFFFFF06
#define VNC_ENCODING_TYPE_COMPRESSION_7      0xFFFFFF07
#define VNC_ENCODING_TYPE_COMPRESSION_8      0xFFFFFF08
#define VNC_ENCODING_TYPE_COMPRESSION_9      0xFFFFFF09
#define VNC_ENCODING_TYPE_WMVi               0x574D5669
#define VNC_ENCODING_TYPE_CACHE              0xFFFF0000
#define VNC_ENCODING_TYPE_CACHE_ENABLE       0xFFFF0001
#define VNC_ENCODING_TYPE_XOR_ZLIB           0xFFFF0002
#define VNC_ENCODING_TYPE_XOR_MONO_ZLIB      0xFFFF0003
#define VNC_ENCODING_TYPE_XOR_MULTI_ZLIB     0xFFFF0004
#define VNC_ENCODING_TYPE_SOLID_COLOR        0xFFFF0005
#define VNC_ENCODING_TYPE_XOR_ENABLE         0xFFFF0006
#define VNC_ENCODING_TYPE_CACHE_ZIP          0xFFFF0007
#define VNC_ENCODING_TYPE_SOL_MONO_ZIP       0xFFFF0008
#define VNC_ENCODING_TYPE_ULTRA_ZIP          0xFFFF0009
#define VNC_ENCODING_TYPE_SERVER_STATE       0xFFFF8000
#define VNC_ENCODING_TYPE_ENABLE_KEEP_ALIVE  0xFFFF8001
#define VNC_ENCODING_TYPE_FTP_PROTO_VER      0xFFFF8002
#define VNC_ENCODING_TYPE_POINTER_CHANGE     -257
#define VNC_ENCODING_TYPE_EXT_KEY_EVENT      -258
#define VNC_ENCODING_TYPE_AUDIO               259
#define VNC_ENCODING_TYPE_DESKTOP_NAME       -307
#define VNC_ENCODING_TYPE_EXTENDED_DESK_SIZE -308
#define VNC_ENCODING_TYPE_KEYBOARD_LED_STATE 0XFFFE0000
#define VNC_ENCODING_TYPE_SUPPORTED_MESSAGES 0XFFFE0001
#define VNC_ENCODING_TYPE_SUPPORTED_ENCODINGS 0XFFFE0002
#define VNC_ENCODING_TYPE_SERVER_IDENTITY    0XFFFE0003
#define VNC_ENCODING_TYPE_MIRRORLINK         0xFFFFFDF5
#define VNC_ENCODING_TYPE_CONTEXT_INFORMATION 0xFFFFFDF4
#define VNC_ENCODING_TYPE_SLRLE              0xFFFFFDF3
#define VNC_ENCODING_TYPE_TRANSFORM          0xFFFFFDF2
#define VNC_ENCODING_TYPE_HSML               0xFFFFFDF1
#define VNC_ENCODING_TYPE_H264               0X48323634
            */

            internal const int HEADER_LENGTH = 12;

            internal readonly ushort X;
            internal readonly ushort Y;
            internal readonly ushort Width;
            internal readonly ushort Height;
            internal readonly int Encoding;

            internal int ParsedBytes
            {
                get
                {
                    if (this.RectangleData == null)
                    {
                        return HEADER_LENGTH;
                    }
                    else
                        return HEADER_LENGTH + this.RectangleData.Length;
                }
            }

            private IRectangleData rectangleData = null;
            internal IRectangleData RectangleData
            {
                get
                {
                    return rectangleData;
                }
                private set
                {
                    rectangleData = value;
                    if (value != null)
                        this.RectangleDataLength = value.Length;
                }
            }

            internal int RectangleDataLength { get; private set; } = -1;//unknown

            internal int TotalLenght {
                get {
                    if (this.RectangleData == null) {
                        if (this.RectangleDataLength < 0)
                            return -1;
                        else
                            return HEADER_LENGTH + this.RectangleDataLength;
                    }
                    else
                        return HEADER_LENGTH + this.RectangleData.Length;
                }
            }

            internal bool TryGetEncoding(out FrameBufferEncoding encoding)
            {
                if (Enum.IsDefined(typeof(FrameBufferEncoding), Encoding))
                {
                    encoding = (FrameBufferEncoding)Encoding;
                    return true;
                }
                else
                {
                    encoding = default;
                    return false;
                }
            }

            private Rectangle(byte[] data, int offset)
            {
                X = Utils.ByteConverter.ToUInt16(data, offset);
                Y = Utils.ByteConverter.ToUInt16(data, offset + 2);
                Width = Utils.ByteConverter.ToUInt16(data, offset + 4);
                Height = Utils.ByteConverter.ToUInt16(data, offset + 6);
                Encoding = (int)Utils.ByteConverter.ToUInt32(data, offset + 8);
            }

            [Obsolete]
            internal static bool TryParse(byte[] data, int offset, out Rectangle rectangle) {
                return TryParse(data, offset, null, false, out rectangle);
            }

            internal static bool TryParse(byte[] data, int offset, VncPixelFormat? pixelFormat, bool requireFullParseout, out Rectangle rectangle) { 
                rectangle = null;
                if (data.Length < offset + HEADER_LENGTH)
                    return false;

                rectangle = new Rectangle(data, offset);
                if (rectangle.Width > MAX_SCREEN_WIDTH || rectangle.Height > MAX_SCREEN_HEIGHT)
                    return false;
                if (rectangle.X > MAX_SCREEN_WIDTH || rectangle.Y > MAX_SCREEN_HEIGHT)
                    return false;

                if(rectangle.TryGetEncoding(out FrameBufferEncoding encoding)) { 
                    //if (Enum.IsDefined(typeof(FrameBufferEncoding), rectangle.Encoding)) {
                    //FrameBufferEncoding encoding = (FrameBufferEncoding)rectangle.Encoding;
                    if (encoding == FrameBufferEncoding.Zlib) {
                        //00 00 00 06
                        if (ZlibRectangleData.TryGetZlibRectangleDataLength(data, offset + HEADER_LENGTH, out int length)) {
                            rectangle.RectangleDataLength = length;
                            if (requireFullParseout || length < 5000) {
                                if (ZlibRectangleData.TryParse(data, offset + HEADER_LENGTH, out ZlibRectangleData rectangleData)) {
                                    rectangle.RectangleData = rectangleData;

                                    return true;
                                }
                                else
                                    return false;
                            }
                            else {
                                return true;//leave RectangleData as null to trigger a file reassembly
                            }
                        }
                        return false;
                    }
                    else if(encoding == FrameBufferEncoding.Tight) {
                        //00 00 00 07
                        rectangle.RectangleDataLength = 2;
                        if (data.Length >= offset + HEADER_LENGTH + 2) {
                            if(TightRectangleData.TryParse(data, offset + HEADER_LENGTH, pixelFormat, out TightRectangleData rectangleData)) {
                                rectangle.RectangleData = rectangleData;
                                return true;
                            }
                            else
                                return false;
                        }
                        else if (requireFullParseout)
                            return false;
                        else
                            return true;
                    }
                    else if (encoding == FrameBufferEncoding.XCursor) {
                        //ff ff ff 10
                        if (XCursorRectangleData.TryParse(data, offset + HEADER_LENGTH, data.Length - HEADER_LENGTH - offset, rectangle.Width, rectangle.Height, out XCursorRectangleData xCursor)) {
                            rectangle.RectangleData = xCursor;
                            return true;
                        }
                        else
                            return false;
                    }
                    else if (encoding == FrameBufferEncoding.Cursor) {
                        //ff ff ff 11
                        if (pixelFormat.HasValue) {
                            int bitsPerPixel = pixelFormat.Value.BitsPerPixel;
                            if (CursorRectangleData.TryParse(data, offset + HEADER_LENGTH, data.Length - offset - HEADER_LENGTH, rectangle.Width, rectangle.Height, bitsPerPixel, out CursorRectangleData cursorData)) {
                                rectangle.RectangleData = cursorData;
                                return true;
                            }
                            else
                                return false;
                        }
                        else if (requireFullParseout)
                            return false;
                        else {
                            //bits per pixel is unknown here but known at PacketParser. Requiring a file reassembly will trigger the PacketParser to read the rectangle data instead
                            return true;//leave RectangleData as null to trigger a file reassembly
                        }
                    }
                    else if(encoding == FrameBufferEncoding.PointerPosition) {
                        //ff ff ff 18
                        rectangle.rectangleData = new BasicRectangleData(new byte[0]);//there is no data
                        rectangle.RectangleDataLength = 0;
                        return true;
                    }
                    else if (encoding == FrameBufferEncoding.LastRect) {
                        //ff ff ff 20
                        rectangle.rectangleData = new BasicRectangleData(new byte[0]);//there is no data
                        rectangle.RectangleDataLength = 0;
                        return true;
                    }
                }
                return false;//encoding is not implemented
            }

            public override string ToString()
            {
                string xywh = "x=" + X + " y=" + Y + " w=" + Width + " h=" + Height;

                if (TryGetEncoding(out FrameBufferEncoding fbEncoding))
                    return xywh + " encoding=" + fbEncoding.ToString() + "(" + Encoding + ")";
                else
                    return xywh + " encoding=" + Encoding;
            }

            #region RectangleData

            internal interface IRectangleData
            {
                int Length { get; }

                byte[] ImageBytes { get; }
            }

            internal class BasicRectangleData : IRectangleData {
                public int Length {
                    get {
                        return this.ImageBytes.Length;
                    }
                }

                public byte[] ImageBytes { get; }

                internal BasicRectangleData(byte[] imageBytes) {
                    this.ImageBytes = imageBytes;
                }
            }

            internal class XCursorRectangleData : IRectangleData
            {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#x-cursor-pseudo-encoding
                public int Length
                {
                    get;
                }

                public byte[] ImageBytes
                {
                    get;
                }

                private static int CountBitmapBytes(int width, int height)
                {
                    return (width + 7) / 8 * height;
                }

                internal static bool TryParse(byte[] data, int offset, int maxLength, int width, int height, out XCursorRectangleData xCursorData)
                {
                    xCursorData = null;
                    int bitmapBytes = CountBitmapBytes(width, height);
                    int maskBytes = CountBitmapBytes(width, height);
                    int length = 6 + bitmapBytes + maskBytes;
                    if (length > maxLength)
                        return false;
                    else if (offset + length > data.Length)
                        return false;
                    else
                        xCursorData = new XCursorRectangleData(data, offset, length);
                    return xCursorData != null;
                }

                XCursorRectangleData(byte[] data, int offset, int length) : this(length)
                {
                    this.ImageBytes = new byte[length];
                    Array.Copy(data, offset, ImageBytes, 0, length);
                }
                XCursorRectangleData(int length)
                {
                    this.Length = length;
                }
            }

            internal class CursorRectangleData : IRectangleData
            {
                public int Length
                {
                    get;
                }

                public byte[] ImageBytes
                {
                    get;
                }

                public static int GetLength(int width, int height, int bitsPerPixel)
                {
                    int pixelBytes = width * height * (bitsPerPixel / 8);
                    int maskBytes = (width + 7) / 8 * height;
                    return pixelBytes + maskBytes;
                }

                internal static bool TryParse(byte[] data, int offset, int maxLength, int width, int height, int bitsPerPixel, out CursorRectangleData cursorData)
                {
                    cursorData = null;
                    /*
                    int pixelBytes = width * height * (bitsPerPixel/8);
                    int maskBytes = ((width + 7) / 8) * height;
                    int length =  pixelBytes + maskBytes;
                    */
                    int length = GetLength(width, height, bitsPerPixel);
                    if (length > maxLength || offset + length > data.Length)
                        return false;
                    else
                    {
                        //cursorData = new CursorRectangleData(length);
                        cursorData = new CursorRectangleData(data, offset, length);
                    }
                    return cursorData != null;
                }


                CursorRectangleData(byte[] data, int offset, int length) : this(length)
                {
                    ImageBytes = new byte[length];
                    Array.Copy(data, offset, ImageBytes, 0, length);
                }
                private CursorRectangleData(int length)
                {
                    Length = length;
                }
            }

            internal class ZlibRectangleData : IRectangleData
            {
                //argh! ZLibStream requires .NET 7 or later!
                //But zlib can be parsed as gzip by replacing the first 2 bytes (78 01) with:
                //1f8b 0800 0000 0000 0000

                /** Example rectangle data (Zlib = 6):
                 * 0000 0027 7801 ecc0 310d 0000 00c2 b0cc 
                 * bf69 64f0 b405 0000 0000 0000 0000 0000 
                 * 0000 0000 00bc 0d00 00ff ff   
                 * 
                 * Or (concated with another header):
                 * 0000 0027 7801 ecc0 310d 0000 00c2 b0cc  
                 * bf69 64f0 b405 0000 0000 0000 0000 0000  
                 * 0000 0000 00bc 0d00 00ff ff
                 * 
                 *                            00 0000 0100  
                 * 4000 0000 4000 4000 0000 0600 0000 24ec  
                 * c021 0100 0000 80a0 ffaf 9d61 0100 0000  
                 * 0000 0000 0000 0000 0000 0000 e017 0000  
                 * 00ff ff00 0000 0100 8000 0000 4000 4000  
                 * 0000 0600 0000 24ec c021 0100 0000 80a0  
                 * ffaf 9d61 0100 0000 0000 0000 0000 0000  
                 * 0000 0000 e017 0000 00ff ff00 0000 0100  
                 * c000 0000 4000 4000 0000 0600 0000 24ec  
                 * c021 0100 0000 80a0 ffaf 9d61 0100 0000  
                 * 0000 0000 0000 0000 0000 0000 e017 0000  
                 * 00ff ff  
                 * 
                 **/

                public int Length { get; }

                public byte[] ImageBytes
                {
                    get;
                }

                internal ZlibRectangleData(byte[] data, int dataOffset)
                {
                    int imageByteLength = (int)Utils.ByteConverter.ToUInt32(data, dataOffset);
                    this.Length = imageByteLength + 4;
                    this.ImageBytes = new byte[imageByteLength];
                    Array.Copy(data, dataOffset + 4, this.ImageBytes, 0, imageByteLength);
                }

                internal static bool TryGetZlibRectangleDataLength(byte[] data, int offset, out int length)
                {
                    if (data.Length < offset + 4)
                    {
                        length = 0;
                        return false;
                    }
                    else
                    {
                        length = 4 + (int)Utils.ByteConverter.ToUInt32(data, offset);
                        return true;
                    }
                }

                internal static bool TryParse(byte[] data, int dataOffset, out ZlibRectangleData result)
                {
                    result = null;

                    if (TryGetZlibRectangleDataLength(data, dataOffset, out int dataLength))
                    {
                        if (data.Length < dataOffset + dataLength)
                            return false;
                        else
                        {
                            result = new ZlibRectangleData(data, dataOffset);
                            return true;
                        }
                    }
                    else
                        return false;
                }
            }
            
            internal class TightRectangleData : IRectangleData {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#767tight-encoding

                public enum CompressionMethod : byte {
                    Basic_s0 = 0,//b0000
                    Basic_s1 = 1,//b0001
                    Basic_s2 = 2,//b0010
                    Basic_s3 = 3,//b0011
                    Basic_read_filter_s0 = 4,//b0100
                    Basic_read_filter_s1 = 5,//b0101
                    Basic_read_filter_s2 = 6,//b0110
                    Basic_read_filter_s3 = 7,//b0111
                    Fill = 8,//b1000
                    Jpeg = 9,//b1001
                }

                private static bool TryGetCompactLength(byte[] data, int offset, out int imageLength, out int parsedBytes) {
                    /**
                     * 0xxxxxxx 	for values 0..127
                     * 1xxxxxxx 0yyyyyyy 	for values 128..16383
                     * 1xxxxxxx 1yyyyyyy zzzzzzzz 	for values 16384..4194303
                     * 
                     * 10.000 (0x2710) (b0010011100010000) is represented as:
                     * (0x904E)  10010000 01001110
                     **/
                    if (data.Length > offset) {
                        parsedBytes = 1;
                        byte x = data[offset];
                        imageLength = (x & 0x7f);//xxxxxxx are the least significant 7 bits
                        if (x < 128)
                            return true;
                        else if(data.Length > offset + 1) {
                            parsedBytes = 2;
                            byte y = data[offset + 1];
                            imageLength += (y & 0x7f) << 7;//yyyyyyy are bits 7-13
                            if (y < 128)
                                return true;
                            else if(data.Length > offset + 2) {
                                parsedBytes = 3;
                                byte z = data[offset + 2];
                                imageLength += z << 14;//zzzzzzzz are the most significant 8 bits (bits 14-21)
                                return true;
                            }
                        }
                    }
                    else {
                        imageLength = 0;
                        parsedBytes = 0;
                    }
                    return false;
                }

                private readonly byte resetStreamFlags;

                public int Length { get; }

                public byte Compression { get; }

                public CompressionMethod? CompressionMethodOrNull { get; }

                public Color[] PaletteColors { get; } = null;
                public byte[] ImageBytes { get; }

                
                public IEnumerable<int> GetResetStreams() { 
                    for(int i = 0; i < 4; i++)
                        if(((this.resetStreamFlags >> i) & 0x01) == 0x01)
                            yield return i;
                }

                internal static bool TryParse(byte[] data, int dataOffset, VncPixelFormat? pixelFormat, out TightRectangleData result) {
                    result = null;

                    if (data.Length >= dataOffset + 2) {
                        byte compression = (byte)(data[dataOffset] >> 4);
                        
                        if (Enum.IsDefined(typeof(CompressionMethod), compression)) {
                            CompressionMethod cm = (CompressionMethod)compression;
                            if(cm == CompressionMethod.Fill) {
                                //one pixel
                                if(pixelFormat.HasValue) {
                                    if (data.Length > dataOffset + pixelFormat.Value.BytesPerPixel) {
                                        result = new TightRectangleData(data, dataOffset, pixelFormat.Value);
                                        return true;
                                    }
                                }
                                return false;
                            }
                            else if(TryGetLengthOffset(data, dataOffset, cm, pixelFormat, out int lengthOffset)) {
                                if (TryGetCompactLength(data, lengthOffset, out int imageLength, out int parsedBytes)) {
                                    if (data.Length >= lengthOffset + parsedBytes + imageLength) {
                                        result = new TightRectangleData(data, dataOffset, pixelFormat);
                                        return true;
                                    }
                                }
                            }
                            
                        }
                        else if (compression < 8) {
                            //will this code ever run??
                            //If the bit 7 (the most significant bit) of the compression-control byte is 0, then the compression type is BasicCompression
                            result = new TightRectangleData(data, dataOffset, pixelFormat);
                            return true;
                        }
                    }
                    return false;
                }

                private static bool TryGetLengthOffset(byte[] data, int dataOffset, CompressionMethod cm, VncPixelFormat? pixelFormat, out int lengthOffset) {
                    //dataOffset typically points to the encoding/compression byte
                    if (cm == CompressionMethod.Fill) {
                        lengthOffset = -1;
                        return false;//no length
                    }

                    lengthOffset = dataOffset + 1;
                    if (cm == CompressionMethod.Basic_read_filter_s0 ||
                        cm == CompressionMethod.Basic_read_filter_s1 ||
                        cm == CompressionMethod.Basic_read_filter_s2 ||
                        cm == CompressionMethod.Basic_read_filter_s3) {
                        if (data.Length <= dataOffset + 1)
                            return false;

                        //one byte filter ID
                        byte filterID = data[dataOffset + 1];
                        lengthOffset++;
                        if (filterID == 1) {
                            //palette filter
                            if (pixelFormat.HasValue) {
                                lengthOffset++;
                                if (data.Length <= dataOffset + 2)
                                    return false;
                                int colors = 1 + data[dataOffset + 2];
                                lengthOffset += colors * pixelFormat.Value.BytesPerPixel;
                            }
                            else
                                return false;
                        }
                    }
                    return true;
                }

                private TightRectangleData(byte[] data, int dataOffset, VncPixelFormat? pixelFormat) {
                    this.Compression = (byte)(data[dataOffset] >> 4);
                    this.resetStreamFlags = (byte)(data[dataOffset] & 0x0f);


                    if (Enum.IsDefined(typeof(CompressionMethod), this.Compression)) {
                        this.CompressionMethodOrNull = (CompressionMethod)this.Compression;
                        if (this.CompressionMethodOrNull.Value == CompressionMethod.Fill) {
                            //we need to know the pixelFormat
                            //int bytesPerPixel = (pixelFormat.Value.BitsPerPixel + 7) /8;
                            this.Length = 1 + pixelFormat.Value.BytesPerPixel;
                            this.ImageBytes = data.Skip(dataOffset).Take(this.Length).ToArray();
                        }
                        else if(TryGetLengthOffset(data, dataOffset, this.CompressionMethodOrNull.Value, pixelFormat, out int lengthOffset)) {

                            if (this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s0 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s1 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s2 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s3) {

                                //one byte filter ID
                                byte filterID = data[dataOffset + 1];
                                
                                if (filterID == 1) {
                                    //palette filter
                                    if (pixelFormat.HasValue) {
                                        
                                        int colors = 1 + data[dataOffset + 2];
                                        this.PaletteColors = new Color[colors];
                                        for(int i = 0; i < colors; i++) {
                                            if(pixelFormat.Value.TryGetColor(data, dataOffset + 3 + i * pixelFormat.Value.BytesPerPixel, out Color color))
                                                this.PaletteColors[i] = color;
                                        }
                                    }
                                }
                            }

                            if (TryGetCompactLength(data, lengthOffset, out int dataLength, out int parsedLengthBytes)) {
                                this.Length = lengthOffset - dataOffset + parsedLengthBytes + dataLength;
                                this.ImageBytes = data.Skip(lengthOffset + parsedLengthBytes).Take(dataLength).ToArray();
                            }
                            else
                                throw new IndexOutOfRangeException("Incomplete TightRectangleData Length");
                        }
                        else
                            throw new IndexOutOfRangeException("Incomplete TightRectangleData");
                    }
                    else if (this.Compression < 8) {
                        //will this code ever run?
                        //If the bit 7 (the most significant bit) of the compression-control byte is 0, then the compression type is BasicCompression
                        this.Length = 2;
                        this.ImageBytes = data.Skip(dataOffset).Take(2).ToArray();
                    }
                }
            }


            #endregion

        }

        internal class ServerCutTextPacket : VncResponsePacket
        {

            internal string Text { get; }

            internal uint FormatFlags { get; }

            internal static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ServerCutTextPacket serverCutTextPacket)
            {
                serverCutTextPacket = null;

                if (TryGetCutTextPacketLength(parentFrame, packetStartIndex, packetEndIndex, out int cutTextPacketLength))
                {
                    int newPacketEndIndex = packetStartIndex + cutTextPacketLength - 1;
                    serverCutTextPacket = new ServerCutTextPacket(parentFrame, packetStartIndex, newPacketEndIndex, clientToServer);
                }

                return serverCutTextPacket != null;
            }

            /**
             *  +--------------+--------------+--------------+
             *  | No. of bytes | Type [Value] | Description  |
             *  +--------------+--------------+--------------+
             *  | 1            | U8 [3]       | message-type |
             *  | 3            |              | padding      |
             *  | 4            | U32          | length       |
             *  | length       | U8 array     | text         |
             *  +--------------+--------------+--------------+
             * 
             * */
                    public ServerCutTextPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (length >= 0)
                {
                    this.PacketEndIndex = packetStartIndex + 7 + length;
                    this.Text = ISO_8859.GetString(parentFrame.Data, packetStartIndex + 8, length);
                }
                else
                {
                    //Extended Clipboard Pseudo-Encoding
                    //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                    length = -length;
                    this.PacketEndIndex = packetStartIndex + 7 + length;
                    /*
                     * 0        text
                     * 1        rtf
                     * 2        html
                     * 3        dib
                     * 4        files
                     * 5 - 15   Reserved for future formats
                     * 16 - 23  Reserved
                     * 24       caps
                     * 25       request
                     * 26       peek
                     * 27       notify
                     * 28       provide
                     * 29 - 31  Reserved for future actions
                     * */
                    this.FormatFlags = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
                }

            }
        }


        internal class FrameBufferUpdatePacket : VncResponsePacket
        {
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst
            //https://www.iana.org/assignments/rfb/rfb.xml#rfb-4
            //https://github.com/ultravnc/UltraVNC/blob/ee9954b90ab6b52a2332b349d55f6a98af3f7424/rfb/rfbproto.h#L460-L503

            /**
             * Example Packet Header:
             * 0000 0001 0000 0000 0040 0040 0000 0006 ???? ???? ???? 
             * t p   1   \ X   Y    w    h   encoding  data         /
             * y a count  `----one rectangle-----------------------´
             * p d
             * e
             * 
             * 0000 0001 0002 0002 0020 0020 ffff ff10
             * t p   1    X     Y    w   h   enc  data
             */

            public readonly Rectangle[] Rectangles = null;
            
            public ushort RectangleCount { get; }

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, bool parseRectangles, out FrameBufferUpdatePacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 3)
                    return false;
                ushort rectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if(rectangleCount == 0)
                    return false;
                if (parseRectangles) {
                    if (rectangleCount == 0xffff) {
                        //number of rectangles is unknown
                    }
                    else {
                        var minPacketEndIndex = packetStartIndex + 3 + Rectangle.HEADER_LENGTH * rectangleCount;
                        if (minPacketEndIndex > packetEndIndex)
                            return false;
                    }
                    try {
                        //verify that we have enough data to parse all rectangles
                        //uint rectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                        int index = packetStartIndex + 4;
                        for (int i = 0; i < rectangleCount; i++) {
                            if (Rectangle.TryParse(parentFrame.Data, index, null, true, out Rectangle rectangle)) {
                                if (rectangle.TryGetEncoding(out var enc) && enc == Rectangle.FrameBufferEncoding.LastRect) {
                                    rectangleCount = (ushort)(i + 1);
                                    break;
                                }
                                if (rectangle.ParsedBytes < 1)
                                    return false;//to prevent an infinite loop
                                index += rectangle.TotalLenght;
                            }
                            else
                                return false;
                        }
                        packet = new FrameBufferUpdatePacket(parentFrame, packetStartIndex, index - 1, clientToServer, true);
                        return true;
                    }
                    catch { return false; }
                }
                else {
                    packet = new FrameBufferUpdatePacket(parentFrame, packetStartIndex, packetStartIndex + 3, clientToServer, false);
                    return true;
                }
            }

            private FrameBufferUpdatePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, bool parseRectangles) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                this.RectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if (parseRectangles) {
                    //Rectangles = new Rectangle[this.RectangleCount];
                    List<Rectangle> rectangleList = new List<Rectangle>();
                    int index = packetStartIndex + 4;
                    for (int i = 0; i < this.RectangleCount; i++) {
                        if (Rectangle.TryParse(parentFrame.Data, index, null, true, out Rectangle rectangle)) {
                            rectangleList.Add(rectangle);
                            index += rectangle.TotalLenght;
                            if (rectangle.TryGetEncoding(out var enc) && enc == Rectangle.FrameBufferEncoding.LastRect) {
                                this.RectangleCount = (ushort)rectangleList.Count();
                                break;
                            }
                        }
                        else
                            throw new Exception("Cannot parse rectangle " + i);
                    }
                    if (rectangleList.Count > 0)
                        this.Rectangles = rectangleList.ToArray();
                    this.PacketEndIndex = index - 1;
                }
                else {
                    //don't parse rectangles
                    this.PacketEndIndex = packetStartIndex + 3;
                }
            }
        }
        #endregion
    }



}
