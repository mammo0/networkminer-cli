//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //NetBIOS Abstract Base packet. Has to be extended by a "Name Service" or "Datagram Service" packet
    //http://ubiqx.org/cifs/rfc-draft/rfc1001.html#s14.1
    //http://ubiqx.org/cifs/NetBIOS.html

    //The purpose of this intermediate class is to have all NetBIOS common functions in one place.
    //That is for example the "RFC 1001 FIRST LEVEL ENCODING"
    abstract class NetBiosPacket : AbstractPacket {

        internal NetBiosPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, string packetTypeDescription)
            : base(parentFrame, packetStartIndex, packetEndIndex, packetTypeDescription) {
            //nothing important to store here...
        }

        /// <summary>
        /// This functions decodes NetBIOS names encoded with First Level Encoding
        /// The function also moves forward in the frameIndex so that it is set to the first byte AFTER the
        /// NetBIOS name when the function is finished.
        /// </summary>
        /// <param name="frameIndex"></param>
        /// <returns></returns>
        internal static string DecodeNetBiosName(Frame parentFrame, ref int frameIndex, NetBiosNameServicePacket nbnsPacket = null){
            int initialFrameIndex=frameIndex;
            //get a NetBIOS name label
            
            /**
             *    NetBIOS implementations can only use label string pointers in Name
             *    Service packets.  They cannot be used in Session or Datagram Service
             *    packets.
             * 
             *    The other two possible values for bits 7 and 6 (01 and 10) of a label
             *    length field are reserved for future use by RFC 883[2 (page 32)].
             *    
             *    Note that the first octet of a compressed name must contain one of
             *    the following bit patterns.  (An "x" indicates a bit whose value may
             *    be either 0 or 1.):
             * 
             *            00100000 -  Netbios name, length must be 32 (decimal)
             *            11xxxxxx -  Label string pointer
             *            10xxxxxx -  Reserved
             *            01xxxxxx -  Reserved
             **/

            byte labelByteCount =parentFrame.Data[frameIndex];//max 63
            //bool labelByteCountIsPointer = false;
            if (nbnsPacket != null) {
                if (labelByteCount >= 0xc0) {//11xxxxxx

                    /**
                     * If bits 7 and 6 are both set (11), the following 14 bits are an
                     * offset pointer into the full message to the actual label string from
                     * another domain name that belongs in this name.
                     **/
                    int pointerIndex = nbnsPacket.PacketStartIndex + (Utils.ByteConverter.ToUInt16(parentFrame.Data, frameIndex) & 0x3fff);//00xxxxxx xxxxxxxx

                    //byte labelStringPointer = (byte)(labelByteCount & 0x3f);//00xxxxxx
                    //int pointerIndex = nbnsPacket.PacketStartIndex + labelStringPointer + 12;
                    //labelByteCount = parentFrame.Data[pointerIndex];
                    frameIndex+=2;
                    return DecodeNetBiosName(parentFrame, ref pointerIndex);
                }
                else
                    labelByteCount = (byte)(labelByteCount & 0x3f);//00xxxxxx
            }
            else {
                if (!parentFrame.QuickParse)
                    if (labelByteCount > 63)
                        parentFrame.Errors.Add(new Frame.Error(parentFrame, frameIndex, frameIndex, "NetBios Name label is larger than 63 : " + labelByteCount));
            }
            frameIndex++;

            StringBuilder decodedName = GetNetBiosNameFromNibbles(parentFrame.Data, ref frameIndex, labelByteCount, initialFrameIndex);

            if (decodedName.Length > 0 && (decodedName[0] > 0x100 || char.IsControl(decodedName[0]))) {//first character is non (extended) ascii
                if (TryParseNetBiosName(parentFrame.Data, frameIndex - labelByteCount, labelByteCount * 2, out StringBuilder sb))
                    decodedName = sb;
            }

            //check for the 0x00 terminator
            //now get the SCOPE_ID label
            while (parentFrame.Data[frameIndex] != 0x00 && frameIndex < initialFrameIndex + 255 && frameIndex < parentFrame.Data.Length) {//&& frameIndex<packetStartIndex+12+255
                decodedName.Append(".");
                labelByteCount = parentFrame.Data[frameIndex];//max 63
                if (!parentFrame.QuickParse)
                    if (labelByteCount > 63)
                        parentFrame.Errors.Add(new Frame.Error(parentFrame, frameIndex, frameIndex, "NetBios Name label is larger than 63 : " + labelByteCount));
                frameIndex++;
                for (byte b = 0; b < labelByteCount; b++) {
                    decodedName.Append((char)parentFrame.Data[frameIndex]);
                    frameIndex++;
                }
            }
            frameIndex++;
            //we have now decoded the name!
            return decodedName.ToString();
        }

        private static StringBuilder GetNetBiosNameFromNibbles(byte[] data, ref int index, int nibbleCount, int initialFrameIndex) {
            StringBuilder decodedName = new StringBuilder("");
            for (byte b = 0; b < nibbleCount; b += 2) {
                byte b1;
                byte b2;
                b1 = data[index];
                b2 = data[index + 1];
                char c = (char)(((b1 - 0x41) << 4) + (b2 - 0x41));
                if (b == nibbleCount - 2 && index == initialFrameIndex + 1 + 2 * 15) {//Microsoft(!) uses 16:th and last character in the NetBIOS name as a "NetBIOS suffix"
                    //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b
                    //See http://support.microsoft.com/kb/q163409/
                    decodedName.Append("<" + ((byte)c).ToString("X2") + ">");
                }
                else if (c != (char)0x20 && c != (char)0x00)//0x20 is padding (spaces). In some cases 0x00 is used as padding, that's not according to the standard (bad Microsoft!).
                    decodedName.Append(c);
                index += 2;
            }
            return decodedName;
        }

        private static bool TryParseNetBiosName(byte[] data, int startIndex, int length, out StringBuilder sb) {
            string netBiosRaw = Utils.ByteConverter.ReadNullTerminatedString(data, ref startIndex, false, false, length);
            netBiosRaw = netBiosRaw?.Trim();
            List<byte> nibbles = new List<byte>();
            foreach(char c in netBiosRaw) {
                if (c < 0x41 || c > 0x140) {
                    sb = null;
                    return false;
                }
                nibbles.Add((byte)c);
            }
            if (nibbles.Count < 2) {
                sb = null;
                return false;
            }
            int index = 0;
            try {
                sb = GetNetBiosNameFromNibbles(nibbles.ToArray(), ref index, nibbles.Count - (nibbles.Count % 2), 0);
                return sb.Length > 0 && sb[0] < 0x100 && !char.IsControl(sb[0]);
            }
            catch (Exception ex) {
                SharedUtils.Logger.Log("Unable to parse NetBIOS name in from " + netBiosRaw + " : " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                sb = null;
                return false;
            }
        }

    }
}
