using System;
using System.Collections.Generic;
using System.Drawing.Imaging;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static PacketParser.Packets.RfbPacket.VncCommandPacket;
using static PacketParser.Packets.RfbPacket.VncResponsePacket;
using static PacketParser.Packets.RfbPacket;
using static PacketParser.Packets.BackConnectPacket;
using System.Runtime.InteropServices;

namespace PacketParser.Packets
{
    internal class BackConnectPacket : AbstractPacket, ISessionPacket {

        //https://www.netresec.com/?page=Blog&month=2022-10&post=IcedID-BackConnect-Protocol
        public enum Command : byte {
            PING = 0x00,
            SLEEP = 0x01,
            ERROR = 0x02,
            RECONNECT = 0x03,
            SOCKS = 0x04,
            VNC = 0x05,
            VNC_2 = 0x11,
            FILE_MANAGER_2 = 0x12,
            REVERSE_SHELL_2 = 0x13,
            UNKNOWN = 0xff//not an actual value that is transmitted
        }
        private static readonly byte[][] KNOWN_AUTH_VALUES = {
            new byte[] { 0x4a, 0x01, 0x4f, 0x97 },
            new byte[] { 0x1f, 0x8b, 0x08, 0x08 }//new IcedID "gzip" AUTH
        };

        internal const int C2_PACKET_LENGTH = 13;
        internal const int MODULE_START_PACKET_LENGTH = 0xf5;//245
        internal byte C2Command { get; }

        internal bool Encrypted { get; }
        internal byte[] Auth { get; }
        internal byte[] Params { get; }
        internal byte[] ID { get; }

        public bool PacketHeaderIsComplete { get; } = false;

        public int ParsedBytesCount { get; } = 0;

        /// <summary>
        /// Check if a SOCKS, reverse shell or file manager module is started
        /// </summary>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        internal static bool IsModuleStart(byte[] data, int offset, int length) {
            /**
             * SOCKS
             * 0000   1f 8b 08 08 01 95 4e fc 1f 97 e5 ea b5 27 00 00
             * 0010   00 ea 0f 69 17 00 00 00 00 00 00 00 00 00 00 00
             * 0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00f0   00 00 00 00 00
             * 
             * SOCKS
             * 0000   1f 8b 08 08 01 95 4e fc 1f 97 e5 ea b5 11 00 00
             * 0010   00 71 b6 88 50 00 00 00 00 00 00 00 00 00 00 00
             * 0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00f0   00 00 00 00 00
             * 
             * 230116 File Manager
             * 0000   1f 8b 08 08 01 e7 7b 61 16 3a 34 28 ff 23 00 00
             * 0010   00 a3 bb 79 4f 00 00 00 00 00 00 00 00 00 00 00
             * 0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00f0   00 00 00 00 00
             * 
             * 230324 File Manager
             * 0000   1f 8b 08 08 01 c7 5e 5e f1 ba 14 55 3f 03 00 00
             * 0010   00 92 c9 af 78 00 00 00 00 00 00 00 00 00 00 00 <- the 92 c9 af 78 at offset 0x11 references the ID from the C2 server in the C2 session
             * 0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00f0   00 00 00 00 00
             * 
             * 18190 VNC
             * 0000   1f 8b 08 08 01 95 4e fc 1f 97 e5 ea b5 02 00 00
             * 0010   00 1b bb bd 52 02 00 00 70 fe 56 34 3f 02 00 00
             * 0020   01 00 00 00 00 00 00 00 fe ed 94 99 fb 7f 00 00
             * 0030   70 fe 56 34 3f 02 00 00 30 f3 34 db ba 00 00 00
             * 0040   70 fe 56 34 3f 02 00 00 01 00 00 00 00 00 00 00
             * 0050   02 02 02 00 00 00 00 00 65 00 00 00 fb 7f 00 00
             * 0060   0b f4 34 db ba 00 00 00 0b 00 00 00 00 00 00 00
             * 0070   08 f5 34 db ba 00 00 00 07 00 00 00 00 00 00 00
             * 0080   eb 6e 98 99 fb 7f 00 00 f6 00 00 00 00 00 00 00
             * 0090   f3 ff ff 7f 00 00 00 00 df 6e 98 99 fb 7f 00 00
             * 00a0   7a 00 00 00 00 00 00 00 f7 ff ff 7f 00 00 00 00
             * 00b0   c0 4a 57 34 3f 02 00 00 dc 53 20 99 fb 7f 00 00
             * 00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             * 00d0   02 9c da eb ca 00 00 00 ea 75 21 99 fb 7f 00 00
             * 00e0   00 00 76 34 3f 02 00 00 00 00 00 00 00 00 00 00
             * 00f0   ff ff ff ff ff
             * */
            if (length != MODULE_START_PACKET_LENGTH) //245
                return false;
            if (data[offset + 4] != 0x01)
                return false;
            for (int i = 0x0e; i < 0x11; i++) {
                if (data[offset + i] != 0)
                    return false;
            }
            for (int i = 0xbe; i < 0xc8; i++) {
                if (data[offset + i] != 0)
                    return false;
            }
            //this code returns true for VNC, SOCKS, reverse shell and file manager!!
            return true;
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {

            result = null;
            //TODO add some quick checks to verify the protocol
            if (packetEndIndex - packetStartIndex + 1 < C2_PACKET_LENGTH)
                return false;
            byte[] packetAuth = parentFrame.Data.Skip(packetStartIndex).Take(4).ToArray();
            if (!KNOWN_AUTH_VALUES.Any(auth => auth.SequenceEqual(packetAuth))) {
                //check if encryption is used
                byte[] decryptedAuth = Decrypt(parentFrame.Data.Skip(packetStartIndex).Take(8).ToArray());
                if (!KNOWN_AUTH_VALUES.Any(auth => auth.SequenceEqual(decryptedAuth))) {
                    return false;
                }
            }

            try {
                result = new BackConnectPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
            }
            catch {
                return false;
            }
            return result != null;
        }

        private static byte[] Decrypt(byte[] keyAndData, int keyOffset = 0) {
            List<byte> output = new List<byte>();
            uint key = Utils.ByteConverter.ToUInt32(keyAndData, keyOffset, 4, true);
            int dataOffset = keyOffset + 4;
            for (uint i = 0; dataOffset + i < keyAndData.Length; i++) {
                output.Add((byte)(keyAndData[dataOffset + i] ^ key));
                key = Rol7Add(key, i + 1);
            }
            return output.ToArray();
        }

        /// <summary>
        /// Custom xorshift/ROL-7-XOR implementation used by IcedID
        /// It's basically doing "ROL 7, ADD i"
        /// Note: I don't know if the counter should be a byte or uint since this algorithm was created through statistical analysis of C2 traffic, and all analyzed messages were shorter than 256 bytes.
        /// </summary>
        /// <param name="input">Previous key/state</param>
        /// <param name="counter">iteration counter</param>
        /// <returns>Next XOR key</returns>
        private static uint Rol7Add(uint input, uint counter) {
            return ((input << 7) | (input >> 25)) + counter;
        }

        internal BackConnectPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
        : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect") {
            
            this.Encrypted = false;
            byte[] backConnectData = new byte[packetEndIndex - packetStartIndex + 1];
            Array.Copy(parentFrame.Data, packetStartIndex, backConnectData, 0, backConnectData.Length);
            /**
             *     Auth: 4 bytes
             *     Command: 1 byte
             *     Params: 4 bytes
             *     ID: 4 bytes
            **/
            this.Auth = backConnectData.Take(4).ToArray();
            if (!KNOWN_AUTH_VALUES.Any(auth => auth.SequenceEqual(this.Auth))) {
                //check if encryption is used
                byte[] decryptedAuth = Decrypt(backConnectData.Take(8).ToArray());
                if (KNOWN_AUTH_VALUES.Any(auth => auth.SequenceEqual(decryptedAuth))) {
                    this.Encrypted = true;
                    backConnectData = Decrypt(backConnectData);
                }
            }

            if (clientToServer && ReverseVncPacket.IsReverseVncStart(backConnectData, 0, backConnectData.Length)) {
                this.C2Command = (byte)Command.VNC_2;//0x11;
                this.Params = backConnectData.Skip(0x0d).Take(4).ToArray();
                this.ID = backConnectData.Skip(0x11).Take(4).ToArray();
                this.ParsedBytesCount = MODULE_START_PACKET_LENGTH;//245
            }
            else if(clientToServer && IsModuleStart(backConnectData, 0, backConnectData.Length)) {
                this.C2Command = (byte)Command.UNKNOWN;
                this.Params = backConnectData.Skip(0x0d).Take(4).ToArray();
                this.ID = backConnectData.Skip(0x11).Take(4).ToArray();
                this.ParsedBytesCount = MODULE_START_PACKET_LENGTH;
            }
            else {
                this.C2Command = backConnectData[4];
                this.Params = backConnectData.Skip(5).Take(4).ToArray();
                this.ID = backConnectData.Skip(9).Take(4).ToArray();
                this.ParsedBytesCount = C2_PACKET_LENGTH;
            }
            if (this.Encrypted)
                this.ParsedBytesCount += 4;
            this.PacketEndIndex = packetStartIndex + this.ParsedBytesCount - 1;
            this.PacketHeaderIsComplete = true;
        }



        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }

        public class ReverseVncPacket : RfbPacket {

            //public const int CLIENT_START_LENGTH_LONG = 0xf5;//245

            [Obsolete]
            private ReverseVncPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool transferIsClientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, !transferIsClientToServer) {
                //this constructor merely reverses client and server in RFB packet
            }

            internal ReverseVncPacket(VncCommandPacket commandPacket) : base(commandPacket) {

            }

            internal ReverseVncPacket(VncResponsePacket responsePacket) : base(responsePacket) {

            }


            internal static bool IsReverseVncStart(byte[] data, int offset, int length) {
                /**
                 *          Session A                        Session B                  All sessions!
                 * 0x00     1f 8b 08 08 01 c7 5e 5e        1f 8b 08 08 01 34 0e 88      1f 8b 08 08 01 .. .. ..
                 * 0x08     f1 60 05 77 c9 13 00 00        1a 3a d6 fa 98 07 00 00      .. .. .. .. .. .. 00 00
                 * 0x10     00 65 ee dd 56 f3 f5 aa        00 fd 63 9f 0f 00 00 00      00 .. .. .. .. .. .. ..
                 * 0x18     0e 00 00 00 30 32 3e 6e        60 00 00 00 1c 2e ac 77      .. 00 00 00 .. .. .. ..
                 * 0x20     33 01 00 00 38 f3 f5 aa        64 7b 25 77 ff ff ff ff      .. .. .. .. .. .. .. ..
                 * 0x28     0e 00 00 00 01 00 00 00        fe ff ff ff ff ff ff ff      .. .. .. .. .. .. .. ..
                 * 0x30     00 00 00 00 37 2f 0b da        e8 8d d5 02 00 00 00 00      .. .. .. .. .. .. .. ..
                 * 0x38     fe 7f 00 00 60 30 3a 6e        00 00 00 00 ff ff ff ff      .. .. 00 00 .. .. .. ..
                 * 0x40     33 01 00 00 e0 f4 f5 aa        e0 8d d5 02 e8 8d d5 02      .. .. .. .. .. .. .. ..
                 * 0x48     0e 00 00 00 60 30 3a 6e        ff ff ff ff ff ff ff ff      .. .. .. .. .. .. .. ..
                 * 0x50     33 01 00 00 01 00 00 00        e0 8d d5 02 02 02 00 00      .. .. .. .. .. .. 00 00
                 * 0x58     00 00 00 00 02 02 02 00        a0 f4 d1 02 01 00 00 00      .. .. .. .. .. .. .. 00
                 * 0x60     02 00 00 00 65 00 00 00        01 00 00 00 a0 f4 d1 02      .. 00 00 00 .. .. .. ..
                 * 0x68     33 01 00 00 bb f5 f5 aa        04 f8 a7 02 88 9e 97 77      .. .. .. .. .. .. .. ..
                 * 0x70     0e 00 00 00 0b 00 00 00        04 f8 a7 02 9b 9e 97 77      .. .. .. .. .. .. .. ..
                 * 0x78     00 00 00 00 b8 f6 f5 aa        c4 85 9b 77 0e 2b 50 05      .. .. .. .. .. .. .. ..
                 * 0x80     0e 00 00 00 07 00 00 00        9d 01 7d 02 00 00 7d 02      .. .. .. .. .. 00 .. ..
                 * 0x88     00 00 00 00 eb 8a 0f da        b6 9e 97 77 f7 ff ff 7f      .. .. .. .. .. .. .. ..
                 * 0x90     fe 7f 00 00 f6 00 00 00        7a 00 00 00 9f 1b 97 77      .. .. 00 00 .. .. .. ..
                 * 0x98     00 00 00 00 f3 ff ff 7f        f3 ff ff 7f f6 00 00 00      .. .. .. .. .. .. .. ..
                 * 0xa0     00 00 00 00 df 8a 0f da        ab 1b 97 77 07 00 00 00      .. .. .. .. .. .. .. ..
                 * 0xa8     fe 7f 00 00 7a 00 00 00        dc fa a7 02 0b 00 00 00      .. .. .. .. .. 00 00 00
                 * 0xb0     00 00 00 00 f7 ff ff 7f        df f9 a7 02 65 00 00 00      .. .. .. .. .. .. .. ..
                 * 0xb8     00 00 00 00 00 00 00 00        e4 f7 02 02 01 00 00 00      .. .. .. .. .. ?? 00 00
                 * 0xc0     00 00 00 00 00 00 00 00        00 00 00 00 00 00 00 00      00 00 00 00 00 00 00 00
                 * 0xc8     00 00 00 00 00 00 23 2e        e6 2b ac 77 08 6b 24 77      .. .. .. .. .. .. .. ..
                 * 0xd0     00 00 00 00 a2 d0 91 ab        ff ff ff ff 0c 00 00 00      .. .. .. .. .. .. .. ..
                 * 0xd8     95 6c 00 00 00 00 5d 6e        0e 2b 50 05 8c f7 a7 02      .. .. .. .. .. .. .. ..
                 * 0xe0     33 01 00 00 00 00 00 00        ff ff ff ff a0 fc a7 02      .. .. .. .. .. .. .. ..
                 * 0xe8     00 00 00 00 ff ff ff ff        80 7b 98 77 f2 e5 6c 70      .. .. .. .. .. .. .. ..
                 * 0xf0     ff ff ff ff 0c                 fe ff ff ff b0               .. ff ff ff ..
                 * 
                 * 
                */

                if(!IsModuleStart(data, offset, length))
                    return false;

                //this part is what actually differentiates VNC from FileManager / Reverse Shell
                for (int i = 0xf1; i < MODULE_START_PACKET_LENGTH - 1; i++)
                    if (data[offset + i] != 0xff)
                        return false;
                return true;
            }
            


            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ReverseVncPacket reverseVncPacket) {
                //Frame 1 c->s : 13 byte packet with known Auth value, for example: 4a01 4f97 0505 0000 0099 dc15 5f
                //Frame 2 s->c : 0x01 or 0x06 or 0x0a //RFB ClientInit??
                //Frame 3 c->s : Often 30 bytes, FrameBufferWidth (2 bytes), FrameBufferHeight (2 bytes), PixelFormat (16 bytes), StringLength (4 bytes), DesktopName (variable, often "VNC ")
                //Frame 4 s->c : 20 bytes 00 00 00 00 [PixelFormat] ( + 110 bytes unless sent in new TCP segment)
                reverseVncPacket = null;
                try {
                    RfbPacket rfbPacket;
                    if (!clientToServer && packetStartIndex == packetEndIndex && (parentFrame.Data[packetEndIndex] == 0x01 || parentFrame.Data[packetEndIndex] == 0x06 || parentFrame.Data[packetEndIndex] == 0x0a)) {
                        //Variant of ClientInit??
                        reverseVncPacket = new ReverseVncPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    }
                    
                    else if (clientToServer && RfbPacket.TryParseHandshake(parentFrame, packetStartIndex, packetEndIndex, !clientToServer, out rfbPacket) && (rfbPacket.PixelFormat.HasValue || rfbPacket.ScreenSize.HasValue)) {
                        //ServerInit
                        reverseVncPacket = new ReverseVncPacket(parentFrame, rfbPacket.PacketStartIndex, rfbPacket.PacketEndIndex, clientToServer);
                        reverseVncPacket.PixelFormat = rfbPacket.PixelFormat;
                        reverseVncPacket.ScreenSize = rfbPacket.ScreenSize;
                        reverseVncPacket.VncDesktopName = rfbPacket.VncDesktopName;
                    }
                    else if (RfbPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, !clientToServer, out rfbPacket)) {
                        if (rfbPacket.CommandPacket != null)
                            reverseVncPacket = new ReverseVncPacket(rfbPacket.CommandPacket);
                        else if (rfbPacket.ResponsePacket != null)
                            reverseVncPacket = new ReverseVncPacket(rfbPacket.ResponsePacket);
                        else
                            return false;
                    }
                }
                catch {
                    return false;
                }
                return reverseVncPacket != null;
            }
        }

        public class ReverseSocksPacket : AbstractPacket {
            private readonly SocksPacket reversedSocksPacket = null;

            

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ReverseSocksPacket result) {
                try {
                    if (packetEndIndex - packetStartIndex == 1 && parentFrame.Data[packetStartIndex] == 1 && parentFrame.Data[packetStartIndex + 1] == 0) {
                        result = new ReverseSocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        return true;
                    }
                    else if (packetEndIndex == packetStartIndex && parentFrame.Data[packetStartIndex] == 5) {
                        result = new ReverseSocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        return true;
                    }
                    else if (SocksPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, !clientToServer, out _)) {
                        result = new ReverseSocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        return true;
                    }
                    else {
                        result = null;
                        return false;
                    }
                }
                catch {
                    result = null;
                    return false;
                }
            }

            private ReverseSocksPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect Reverse SOCKS") {
                if (base.PacketLength == 2 && parentFrame.Data[packetStartIndex] == 1 && parentFrame.Data[packetStartIndex + 1] == 0) {
                    //do nothing
                }
                else if (base.PacketLength == 1 && parentFrame.Data[packetStartIndex] == 5) {
                    //do nothing
                }
                else if (SocksPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, !clientToServer, out AbstractPacket p)) {
                    if (p is SocksPacket socksPacket)
                        this.reversedSocksPacket = socksPacket;
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
                if (this.reversedSocksPacket != null) {
                    yield return reversedSocksPacket;
                    foreach (AbstractPacket subPacket in reversedSocksPacket.GetSubPackets(false))
                        yield return subPacket;
                }
            }
        }

        public class ReverseShellPacket : AbstractPacket {

            internal string CommandOrResponse { get; } = null;
            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ReverseShellPacket result) {
                //Packet #1: Client->Server, start (len 245)
                //Packet #2: Server->Client, 0x0a
                //Packet #3: Client->Server, "+" + CRLF
                //Packet #4: Server->Client, "c" (0x63)
                result = null;
                try {
                    int packetLength = packetEndIndex - packetStartIndex + 1;
                    if (!clientToServer && packetLength == 1 && (parentFrame.Data[packetEndIndex] == 0x0a || parentFrame.Data[packetEndIndex] == 0x63))
                        result = new ReverseShellPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    else if (packetLength >= 2 && parentFrame.Data[packetEndIndex - 1] == 0x0d && parentFrame.Data[packetEndIndex] == 0x0a)
                        result = new ReverseShellPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                }
                catch {
                    return false;
                }
                return result != null;
            }

            private ReverseShellPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect Reverse Shell") {
                int index = packetStartIndex;
                List<string> lines = new List<string>();
                while (index < packetEndIndex)
                    lines.Add(Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, false));
                if (lines.Count > 0)
                    this.CommandOrResponse = string.Join(Environment.NewLine, lines);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        public class FileManagerPacket : AbstractPacket {


            private static readonly HashSet<string> ServerCommands = new HashSet<string>() {
                "DISK",
                "CDDIR",
                "PWD",
                "DIR",
                "PUT"
                };

            //public const int START_FILE_MANAGER_PACKET_LENGTH = 245 - C2_PACKET_LENGTH;

            private static byte[] PlusOkLF = { 0x2b, 0x6f, 0x6b, 0x0a };//+ok[LF]
            private static byte[] PlusAcceptLF = { 0x2b, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x0a };//+accept[LF]

            //private byte[] AuthValue { get; } = null;
            internal string ServerCommand { get; } = null;
            internal string CommandArgument { get; } = null;
            internal int ResposeLength { get; } = 0;

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out FileManagerPacket result) {
                //Packet #1: Client->Server, tcp.len == 245, starts with KNOWN_AUTH_VALUES
                //Packet #2: Server->Client, 1 byte: 0x0a
                //Packet #3: Client->Server, 4 bytes: +ok[0x0a] (tcp.payload == 2b:6f:6b:0a)
                //Packet #4: Server->Client, [Command][0x0a]
                //Packet #5: Client->Server, "*[lenght]"
                //Packet #6: Client->Server, [DATA] (length as specified with *[lenght])
                result = null;
                try {
                    if (parentFrame.Data[packetEndIndex] == 0x0a) {
                        result = new FileManagerPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    }
                    int packetLength = packetEndIndex - packetStartIndex + 1;
                    if (clientToServer && packetLength == MODULE_START_PACKET_LENGTH && parentFrame.Data[packetEndIndex] == 0x00) {
                        result = new FileManagerPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    }
                }
                catch {
                    return false;
                }
                return result != null;
            }

            private FileManagerPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect File Manager") {
                //Packet #1: Client->Server, tcp.len == 245, starts with KNOWN_AUTH_VALUES
                //Packet #2: Server->Client, 1 byte: 0x0a
                //Packet #3: Client->Server, 4 bytes: +ok[0x0a] (tcp.payload == 2b:6f:6b:0a)
                //Packet #4: Server->Client, [Command][0x0a]
                //Packet #5: Client->Server, "*[lenght]" or "+accept"
                //Packet #6: Client->Server, [DATA] (length as specified with *[lenght])
                if (clientToServer) {

                    if (base.PacketLength == MODULE_START_PACKET_LENGTH && parentFrame.Data[packetEndIndex] == 0x00) {
                        //this.AuthValue = parentFrame.Data.Skip(packetStartIndex).Take(4).ToArray();
                    }
                    else if (base.PacketLength == 4 && base.GetPacketData().SequenceEqual(PlusOkLF)) {
                        //do nothing
                    }
                    else if (base.PacketLength == PlusAcceptLF.Length && base.GetPacketData().SequenceEqual(PlusAcceptLF)) {
                        //do nothing
                    }
                    else if (base.PacketLength > 1 && base.PacketLength < 11 && parentFrame.Data[packetStartIndex] == 0x2a) {
                        //*32[LF] = 2a 33 32 0a
                        int index = packetStartIndex;
                        string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                        this.ResposeLength = Int32.Parse(line);
                    }

                }
                else {
                    if (base.PacketLength == 1 && parentFrame.Data[packetStartIndex] == 0x0a) {
                        //packet #2, do nothing
                        this.ServerCommand = "";
                    }
                    if (base.PacketLength > 2 && parentFrame.Data[packetEndIndex] == 0x0a) {
                        int index = packetStartIndex;
                        string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                        if (ServerCommands.Contains(line.Split(' ').FirstOrDefault())) {
                            this.ServerCommand = line.Split(' ').FirstOrDefault();
                            this.CommandArgument = line.Substring(this.ServerCommand.Length).Trim();
                        }
                    }
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }

            
        }
    }
}
