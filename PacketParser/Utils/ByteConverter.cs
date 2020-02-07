//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Utils {
    /// <summary>
    /// Sadly this class is needed since Big and little endian can't be configured in System.ByteConverter
    /// I'll use the same types of functions as in ByteConverter.
    /// </summary>
    /// 
    public static class ByteConverter {

        //http://luca.ntop.org/Teaching/Appunti/asn1.html
        //https://www.oss.com/asn1/resources/asn1-made-simple/types.html
        //https://www.obj-sys.com/asn1tutorial/node124.html
        public enum Asn1TypeTag : byte {
            Eoc = 0,
            Boolean = 1,
            Integer = 2,
            BitString = 3,
            OctetString = 4,
            Null = 5,
            ObjectIdentifier = 6,
            ObjectDescriptor = 7,
            External = 8,
            Real = 9,
            Enumerated = 10,
            EmbeddedPdv = 11,
            UTF8String = 12,
            RelativeOid = 13,
            Sequence = 16,
            Set = 17,
            NumericString = 18,
            PrintableString = 19,
            T61String = 20,
            VideotexString = 21,
            IA5String = 22,
            UTCTime = 23,
            GeneralizedTime = 24,
            GraphicString = 25,
            ISO646String = 26,
            GeneralString = 27,
            UniversalString = 28,
            CharacterString = 29,
            BMPString = 30,
            LongForm = 31
        }

        public enum Encoding { Normal, TDS_password }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="hexString">For example "0x6a7167"</param>
        /// <returns></returns>
        public static byte[] ToByteArrayFromHexString(string hexString) {
            if (hexString.StartsWith("0x")) {
                if (hexString.Length % 2 == 0) {
                    byte[] byteArray = new byte[(hexString.Length - 2) / 2];
                    for (int i = 0; i < byteArray.Length; i++)
                        byteArray[i] = Convert.ToByte(hexString.Substring(2 + i * 2, 2), 16);
                    return byteArray;
                }
                else
                    throw new Exception("HexString must contain an even number of bytes");
            }
            else
                throw new Exception("HexString must start with \"0x\"");
        }

        public static byte[] ToByteArray(ushort value, bool littleEndian = false) {
            byte[] b = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian != littleEndian)
                Array.Reverse(b);
            return b;
        }
        public static byte[] ToByteArray(uint value, bool littleEndian = false) {
            byte[] b = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian != littleEndian)
                Array.Reverse(b);
            return b;
        }
        public static byte[] ToByteArray(long value, bool littleEndian = false) {
            byte[] b = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian != littleEndian)
                Array.Reverse(b);
            return b;
        }

        public static void ToByteArray(ushort value, byte[] array, int arrayOffset) {
            array[arrayOffset] = (byte)(value >> 8);
            array[arrayOffset + 1] = (byte)(value & 0x00ff);
        }
        public static void ToByteArray(uint value, byte[] array, int arrayOffset) {
            array[arrayOffset] = (byte)(value >> 24);
            array[arrayOffset + 1] = (byte)((value >> 16) & 0x000000ff);
            array[arrayOffset + 2] = (byte)((value >> 8) & 0x000000ff);
            array[arrayOffset + 3] = (byte)(value & 0x000000ff);
        }
        public static void ToByteArray(ulong value, byte[] array, int arrayOffset) {
            ToByteArray((uint)(value >> 32), array, arrayOffset);
            ToByteArray((uint)value, array, arrayOffset + 4);
        }
        public static byte[] ToByteArray(byte[] source, ref int index, byte endValue, bool copyEndValue) {
            byte[] endValues = { endValue };
            return ToByteArray(source, ref index, endValues, copyEndValue);
        }
        public static byte[] ToByteArray(byte[] source, ref int index, byte[] endValues, bool copyEndValue) {
            int count = source.Length - index;//maximum size
            foreach (byte endValue in endValues) {
                int position = Array.IndexOf<byte>(source, endValue, index);
                if (position > index && position - index + 1 < count)
                    count = position - index + 1;
            }
            /*
            for(int i=index; i<source.Length; i++) {
                if(Array.IndexOf<byte>(endValues, source[i]  source[i] == endValue) {
                    count = i-index+1;
                    break;
                }
            }*/
            int returnArraySize = count;
            if (!copyEndValue && Array.IndexOf<byte>(endValues, source[index + count - 1]) != -1)
                returnArraySize--;
            byte[] returnArray = new byte[returnArraySize];
            Array.Copy(source, index, returnArray, 0, returnArray.Length);
            index += count;
            return returnArray;
        }



        public static ushort ToUInt16(byte[] value) {
            return (ushort)ToUInt32(value, 0, 2, false);
        }
        public static ushort ToUInt16(byte[] value, int startIndex) {
            return (ushort)ToUInt32(value, startIndex, 2, false);
        }
        public static ushort ToUInt16(byte[] value, int startIndex, bool reverseByteOrder) {
            return (ushort)ToUInt32(value, startIndex, 2, reverseByteOrder);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <param name="startIndex"></param>
        /// <param name="nBytes"></param>
        /// <param name="reverseByteOrder">true = little endian</param>
        /// <returns></returns>
        public static uint ToUInt32(byte[] value, int startIndex, int nBytes, bool reverseByteOrder) {
            uint returnValue = 0;

            for (int i = 0; i < nBytes && i + startIndex < value.Length; i++) {
                returnValue <<= 8;
                if (reverseByteOrder)//first byte is smallest value (LSB)
                    returnValue += (uint)value[startIndex + nBytes - 1 - i];
                else//first byte is largest value (MSB)
                    returnValue += (uint)value[startIndex + i];
            }
            return returnValue;
        }

        public static ulong ToUInt64(byte[] value, int startIndex, bool reverseOrder) {
            ulong returnValue = 0;

            uint i1 = ToUInt32(value, startIndex, 4, reverseOrder);
            uint i2 = ToUInt32(value, startIndex + 4, 4, reverseOrder);
            if (reverseOrder) {
                returnValue += i2;
                returnValue <<= 32;
                returnValue += i1;
            }
            else {
                returnValue += i1;
                returnValue <<= 32;
                returnValue += i2;
            }
            return returnValue;
        }
        public static uint ToUInt32(byte[] value, int startIndex, int nBytes) {
            return ToUInt32(value, startIndex, nBytes, false);
        }
        public static uint ToUInt32(byte[] value) {
            return ToUInt32(value, 0, value.Length, false);
        }
        public static uint ToUInt32(byte[] value, int startIndex) {
            return ToUInt32(value, startIndex, 4, false);
        }

        public static uint ToUInt32(System.Net.IPAddress ip) {
            byte[] bytes = ip.GetAddressBytes();
            long l = 0;
            for (int i = 0; i < bytes.Length; i++)
                l = (l << 8) + bytes[i];
            return (uint)l;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="ushort1">Most significant 2 bytes</param>
        /// <param name="ushort2">Least significant 2 bytes</param>
        /// <returns></returns>
        public static uint ToUInt32(ushort ushort1, ushort ushort2) {
            uint returnValue = (uint)ushort1;
            returnValue <<= 16;
            returnValue ^= ushort2;
            return returnValue;
        }

        //https://tools.ietf.org/html/rfc7541#section-5.1
        private static long DecodeULE128(byte[] input, ref int offset, int length) {
            //var markedPosition = input.BaseStream.Position;
            long result = 0;
            int shift = 0;
            while (shift < 60) {
                /*
                if (offset >= input.Length) {
                    // Buffer does not contain entire integer,
                    return -1;
                }
                */
                byte b = input[offset++];
                /*
                if (shift == 28 && (b & 0xf8) != 0) {
                    break;
                }
                */
                result |= ((long)(b & 0x7f)) << shift;
                if ((b & 0x80) == 0) {
                    return result;
                }
                shift += 7;
            }
            // Value exceeds Integer.MAX_VALUE
            throw new System.IO.IOException("decompression failure");
        }

        //https://tools.ietf.org/html/rfc7541#section-5.1
        public static long DecodeULE128(ref IEnumerable<byte> inputEnumerable, long startValue) {
            long result = startValue;
            int shift = 0;
            while (shift < 60) {
                byte b = inputEnumerable.First();
                inputEnumerable = inputEnumerable.Skip(1);
                result += ((long)(b & 0x7f)) << shift;
                if ((b & 0x80) == 0) {
                    return result;
                }
                shift += 7;
                
            }
            // Value exceeds Integer.MAX_VALUE
            throw new System.IO.IOException("decompression failure");
        }

            /// <summary>
            /// Reads one line from the byte[] in data and returns the line as a string.
            /// A line is defined by a number of char's followed by \r\n
            /// </summary>
            /// <param name="data"></param>
            /// <param name="dataIndex"></param>
            /// <returns>The string (wihtout CRLF) if all is OK, otherwise null (for example if there is no CRLF)</returns>
            public static string ReadLine(byte[] data, ref int dataIndex, bool acceptUnixLinefeeds = false) {
            int maxStringLength = 16384;
            //  \r = 0x0d = carriage return (not required for Unix line feeds)
            //  \n = 0x0a = line feed
            StringBuilder line = new StringBuilder();
            bool carrigeReturnReceived = false;
            bool lineFeedReceived = false;
            int indexOffset = 0;
            while (!(acceptUnixLinefeeds || carrigeReturnReceived) || !lineFeedReceived) {
                if (dataIndex + indexOffset >= data.Length || indexOffset >= maxStringLength)
                    return null;
                else {
                    byte b = data[dataIndex + indexOffset];
                    if (b == 0x0d)
                        carrigeReturnReceived = true;
                    else if ((acceptUnixLinefeeds || carrigeReturnReceived) && b == 0x0a)
                        lineFeedReceived = true;
                    else {
                        line.Append((char)b);
                        carrigeReturnReceived = false;
                        lineFeedReceived = false;
                    }
                    indexOffset++;
                }
            }
            dataIndex += indexOffset;
            return line.ToString();

        }


        public static string ReadHexString(byte[] data, int nBytesToRead, bool lowercase = false) {
            return ReadHexString(data, nBytesToRead, 0, lowercase);
        }
        public static string ReadHexString(byte[] data, int nBytesToRead, int offset, bool lowercase = false) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < nBytesToRead; i++) {
                if(lowercase)
                    sb.Append(data[offset + i].ToString("x2"));
                else
                    sb.Append(data[offset + i].ToString("X2"));

            }
            return sb.ToString();
        }

        public static string ReadString(byte[] data) {
            int i = 0;
            return ReadString(data, ref i, data.Length, false, false);
        }
        public static string ReadString(byte[] data, string nonAsciiNonPrintableReplacement) {
            return System.Text.RegularExpressions.Regex.Replace(ReadString(data), @"\p{Cc}", nonAsciiNonPrintableReplacement);
        }
        //note: @"[^ -~]" replaces all non 7-bit ASCII printable while @"\p{Cc}" preserves non-7bit-ASCII printable (like 0xff = "ÿ")
        public static string ReadString(byte[] data, int startIndex, int lenght, string nonAsciiNonPrintableReplacement) {
            return System.Text.RegularExpressions.Regex.Replace(ReadString(data, startIndex, lenght), @"[^ -~]", nonAsciiNonPrintableReplacement);
        }
        public static string ReadString(byte[] data, int startIndex, int lenght) {
            return ReadString(data, ref startIndex, lenght, false, false);
        }
        public static string ReadString(byte[] data, int startIndex, int lenght, bool unicodeData, bool reverseOrder) {
            return ReadString(data, ref startIndex, lenght, unicodeData, reverseOrder);
        }
        public static string ReadString(byte[] data, ref int dataIndex, int bytesToRead, bool unicodeData, bool reverseOrder, bool nullTerminatedString = false) {
            return ReadString(data, ref dataIndex, bytesToRead, unicodeData, reverseOrder, Encoding.Normal, nullTerminatedString);
        }
        public static string ReadString(byte[] data, ref int dataIndex, int bytesToRead, bool unicodeData, bool reverseOrder, Encoding encoding, bool nullTerminatedString = false) {
            int i = 0;
            StringBuilder sb = new StringBuilder();
            while (i < bytesToRead && dataIndex + i < data.Length) {
                if (unicodeData) {
                    ushort unicodeValue = ByteConverter.ToUInt16(data, dataIndex + i, reverseOrder);
                    if (nullTerminatedString && unicodeValue == 0)
                        break;
                    if (encoding == Encoding.TDS_password) {
                        //http://www.securiteam.com/tools/6Q00I0UEUM.html
                        //XOR with A5
                        unicodeValue ^= 0xa5a5;
                        //swap nibbles
                        unicodeValue = SwapNibbles(unicodeValue);
                    }
                    sb.Append((char)unicodeValue);
                    i += 2;
                }
                else {
                    if (nullTerminatedString && data[dataIndex + i] == 0)
                        break;

                    sb.Append((char)data[dataIndex + i]);
                    i++;
                }
            }
            dataIndex += i;

            return sb.ToString();
        }



        public static string ReadLengthValueString(byte[] data, ref int index, int stringLengthFieldBytes) {
            int stringLength = 0;
            if (stringLengthFieldBytes == 1)
                stringLength = data[index];
            else if (stringLengthFieldBytes == 2)
                stringLength = ByteConverter.ToUInt16(data, index);
            else if (stringLengthFieldBytes == 4)
                stringLength = (int)ByteConverter.ToUInt32(data, index);
            else
                throw new Exception("Selected stringLengthFieldBytes is not supported");
            index += stringLengthFieldBytes;
            string returnString = ByteConverter.ReadString(data, index, stringLength);
            index += stringLength;
            return returnString;
        }

        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex) {
            return ReadNullTerminatedString(data, ref dataIndex, false, false);
        }
        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex, bool unicodeData, bool reverseOrder) {
            int maxStringLength = 1024;
            return ReadNullTerminatedString(data, ref dataIndex, unicodeData, reverseOrder, maxStringLength);
        }
        public static string ReadNullTerminatedString(byte[] data, ref int dataIndex, bool unicodeData, bool reverseOrder, int maxStringLength) {
            StringBuilder returnString = new StringBuilder();

            if (!unicodeData) {
                for (int offset = 0; dataIndex + offset < data.Length && offset < maxStringLength; offset++) {
                    byte b = data[dataIndex + offset];
                    if (b == 0x00) {
                        dataIndex += (offset + 1);
                        return returnString.ToString();
                    }
                    else {
                        returnString.Append((char)b);
                    }
                }
            }
            else {//unicode
                for (int offset = 0; dataIndex + offset < data.Length && offset < maxStringLength * 2; offset += 2) {
                    ushort b;
                    if (dataIndex + offset + 1 < data.Length)
                        b = ByteConverter.ToUInt16(data, dataIndex + offset, reverseOrder);
                    else//only one byte to read
                        b = (ushort)data[dataIndex + offset];
                    if (b == 0x0000) {
                        dataIndex += (offset + 2);
                        return returnString.ToString();
                    }
                    else {
                        returnString.Append((char)b);
                    }
                }
            }
            //we should hopefully not end up here!!!
            //But sometimes implementations just don't use a terminator and instead they just end the whole packet!!!
            //so let's degrade gracefully...
            if (unicodeData)
                dataIndex += returnString.Length * 2;
            else
                dataIndex += returnString.Length;
            return returnString.ToString();
        }

        //converts a string that looks like for example "2 421 100 B" into 2421100
        public static double StringToClosestDouble(string numberLikeLookingString) {
            double returnValue = 0.0;
            int decimalNumber = 0;
            for (int i = 0; i < numberLikeLookingString.Length; i++) {
                char c = numberLikeLookingString[i];
                if (Char.IsNumber(c)) {
                    if (decimalNumber == 0)
                        returnValue = returnValue * 10 + (int)c;
                    else {
                        returnValue += returnValue / (Math.Pow(10.0, (double)decimalNumber));
                        decimalNumber++;
                    }
                }
                else if (decimalNumber == 0 && (c == '.' || c == ','))
                    decimalNumber = 1;
            }
            return returnValue;
        }

        public static string ToMd5HashString(string originalText, bool uppercase = false) {
            System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5CryptoServiceProvider.Create();
            byte[] textArray = new byte[originalText.Length];
            for (int i = 0; i < originalText.Length; i++)
                textArray[i] = (byte)originalText[i];
            byte[] hashArray = md5.ComputeHash(textArray);
            StringBuilder hashStringBuilder = new StringBuilder();
            for (int i = 0; i < hashArray.Length; i++) {
                if(uppercase)
                    hashStringBuilder.Append(hashArray[i].ToString("X2"));
                else
                    hashStringBuilder.Append(hashArray[i].ToString("x2"));
            }
            return hashStringBuilder.ToString();
        }

        //Format: 6162633132330a\tabc123.
        public static string ToXxdHexString(byte[] data) {
            string hexPart = ReadHexString(data, data.Length);
            string asciiPart = ReadString(data, ".");
            return hexPart + "\t" + asciiPart;
        }


        public static ushort SwapNibbles(ushort data) {
            return (ushort)(((data >> 4) & 0x0f0f) | ((data << 4) & 0xf0f0));
        }

        public static DateTime ToUnixTimestamp(byte[] data, int offset) {
            //reads 4 bytes
            long seconds = (long)ByteConverter.ToUInt32(data, offset);/*seconds since January 1, 1970 00:00:00 GMT*/
            DateTime timestamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return timestamp.AddTicks(seconds * 10000000);
        }

        public static List<byte> ToQuotedPrintable(string text) {
            List<byte> quotedPrintableBytes = new List<byte>();
            //byte[] asciiBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(text);
            byte[] cp850bytes = System.Text.Encoding.GetEncoding(850).GetBytes(text);
            foreach (byte b in cp850bytes) {
                if (b >= 33 && b <= 60)//Rule #2
                    quotedPrintableBytes.Add(b);
                else if (b >= 62 && b <= 126)//Rule #2
                    quotedPrintableBytes.Add(b);
                else if (b == 9 || b == 32)//Rule #3
                    quotedPrintableBytes.Add(b);
                else {//Rule #1
                    string escapeSequence = "=" + b.ToString("X2");
                    foreach (byte eb in System.Text.ASCIIEncoding.ASCII.GetBytes(escapeSequence))
                        quotedPrintableBytes.Add(eb);
                }

            }
            return quotedPrintableBytes;
        }

        public static List<byte> ReadQuotedPrintable(byte[] quotedPrintableData) {
            //http://tools.ietf.org/html/rfc2045#page-19

            /**
             * (General 8bit representation) Any octet, except a CR or
             * LF that is part of a CRLF line break of the canonical
             * (standard) form of the data being encoded, may berepresented by an "=" followed by a two digit
             * hexadecimal representation of the octet's value.  The
             * digits of the hexadecimal alphabet, for this purpose,
             * are "0123456789ABCDEF".  Uppercase letters must be
             * used; lowercase letters are not allowed.  Thus, for
             * example, the decimal value 12 (US-ASCII form feed) can
             * be represented by "=0C", and the decimal value 61 (US-
             * ASCII EQUAL SIGN) can be represented by "=3D".  This
             * rule must be followed except when the following rules
             * allow an alternative encoding.
             */

            /**
             * RFC 1521
             * Rule #5 (Soft Line Breaks): The Quoted-Printable encoding REQUIRES
             * that encoded lines be no more than 76 characters long. If longer
             * lines are to be encoded with the Quoted-Printable encoding, 'soft'
             * line breaks must be used. An equal sign as the last character on a
             * encoded line indicates such a non-significant ('soft') line break
             * in the encoded text.
             **/

            List<byte> outputBytes = new List<byte>();
            byte equals = 0x3d; //'='
            HashSet<byte> ignoreChars = new HashSet<byte>(new byte[] { 0x0d, 0x0a });
            for (int i = 0; i < quotedPrintableData.Length; i++) {
                if (ignoreChars.Contains(quotedPrintableData[i])) {
                    //do nothing
                }
                else if (quotedPrintableData[i] == equals && i + 2 < quotedPrintableData.Length) {
                    string hexValue = ByteConverter.ReadString(quotedPrintableData, i + 1, 2);

                    if (hexValue == "\r\n")
                        i += 2; //skip past the soft line break
                    else {
                        try {
                            outputBytes.Add(Convert.ToByte(hexValue, 16)); //read from hex value to byte
                        }
                        catch (Exception e) {
                            SharedUtils.Logger.Log("Error parsing QuotedPrintable: " + e.GetType() + " " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        }
                        i += 2; //skip past the quoted value
                    }

                }
                else
                    outputBytes.Add(quotedPrintableData[i]);
            }
            return outputBytes;
        }

        public static List<Tuple<string, Asn1TypeTag, byte[]>> GetAsn1Data(byte[] data) {
            int i = 0;
            return GetAsn1Data(data, ref i, data.Length - 1);
        }

        public static List<Tuple<string, Asn1TypeTag, byte[]>> GetAsn1Data(byte[] data, ref int index, int lastIndex) {

            //http://luca.ntop.org/Teaching/Appunti/asn1.html
            //https://www.oss.com/asn1/resources/asn1-made-simple/types.html
            //https://www.obj-sys.com/asn1tutorial/node124.html

            List<Tuple<string, Asn1TypeTag, byte[]>> asnEntries = new List<Tuple<string, Asn1TypeTag, byte[]>>();
            AddAsn1Data(data, ref index, lastIndex, asnEntries, "");
            return asnEntries;
        }

        private static void AddAsn1Data(byte[] data, ref int index, int lastIndex, List<Tuple<string, Asn1TypeTag, byte[]>> asnEntries, string asnPath) {
            while (index < lastIndex) {
                byte asn1Type = data[index];
                index++;
                int length = GetAsn1Length(data, ref index);
                if (Enum.IsDefined(typeof(Asn1TypeTag), asn1Type)) {
                    //we have a primitive ASN.1 object
                    byte[] primitiveData = data.Skip(index).Take(length).ToArray();
                    //Tuple<Asn1TypeTag, byte[]> primitiveTuple = new Tuple<Asn1TypeTag, byte[]>((Asn1TypeTag)asn1Type, primitiveData);
                    index += length;
                    asnEntries.Add(new Tuple<string, Asn1TypeTag, byte[]>(asnPath.TrimStart(new[] { '.' }), (Asn1TypeTag)asn1Type, primitiveData));
                }
                else {
                    //parse what's inside the type
                    AddAsn1Data(data, ref index, Math.Min(index + length - 1, lastIndex), asnEntries, asnPath + "." + asn1Type.ToString("x2"));
                }
            }
        }

        /// <summary>
        /// Gets the sequence element length (in number of bytes) and advances the index value to the first byte after the length data
        /// </summary>
        /// <param name="data">The raw data</param>
        /// <param name="index">The index should point to the length start position in data. The index will be moved to the first position after the lenght parameter after the function is executed.</param>
        /// <returns>ASN.1 BER/DER length</returns>
        public static int GetAsn1Length(byte[] data, ref int index) {
            //https://en.wikipedia.org/wiki/X.690#Length_octets
            //https://msdn.microsoft.com/en-us/library/ms995330.aspx

            int sequenceElementLength = 0;
            //see if first bit (indicating long data) is set
            if (data[index] >= 0x80) {
                int bytesInLengthValue = data[index] & 0x0f;
                index++;

                if (bytesInLengthValue == 0)
                    return Int32.MaxValue;//Should actually be Indefinite
                else if (sequenceElementLength >= 127)
                    throw new Exception("Reserved");
                else {
                    //lengths are in Network Byte Order (Big-Endian).
                    sequenceElementLength = (int)Utils.ByteConverter.ToUInt32(data, index, bytesInLengthValue, false);
                    index += bytesInLengthValue;
                }
            }
            else {//just a short single byte lenght value
                sequenceElementLength = (int)data[index];
                index++;

            }
            return sequenceElementLength;
        }


        //https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
        //https://msdn.microsoft.com/en-us/library/windows/desktop/bb648645(v=vs.85).aspx
        public static List<string> ReadAsn1DerSequenceStrings(byte[] data, ref int index, bool unicode = false) {
            const byte OCTET_STRING = 0x04;
            const byte PRINTABLE_STRING = 0x13;
            List<string> strings = new List<string>();
            foreach (byte[] stringBytes in GetAsn1DerSequenceTypes(data, ref index, new HashSet<byte>() { OCTET_STRING, PRINTABLE_STRING })) {
                if (stringBytes.Length > 0) {
                    if (unicode)
                        strings.Add(ReadString(stringBytes, 0, stringBytes.Length, unicode, false));
                    else {
                        bool only7BitAscii = true;
                        foreach (byte b in stringBytes)
                            if (b < 32 || b > 127) {
                                only7BitAscii = false;
                                break;
                            }
                        if (only7BitAscii)
                            strings.Add(ReadString(stringBytes, 0, stringBytes.Length, unicode, false));
                    }
                }
            }
            return strings;
        }

        //It would be nice if .NET could expose the ASN.1 parser that is built into System.Security.Cryptography.X509Certificates
        //https://github.com/dotnet/corefx/issues/21833
        public static List<byte[]> GetAsn1DerSequenceTypes(byte[] data, ref int index, HashSet<byte> typeTags) {
            //System.Security.Cryptography.AsnEncodedData asn = new System.Security.Cryptography.AsnEncodedData(data);
            List<byte[]> typeList = new List<byte[]>();
            const byte SEQUENCE = 0x30;
            const byte GET_REQUEST_PDU = 0xa0;
            const byte GET_RESPONSE_PDU = 0xA2;
            const byte SET_REQUEST_PDU = 0xA3;

            HashSet<byte> parsableSequences = new HashSet<byte>() { SEQUENCE, GET_REQUEST_PDU, GET_RESPONSE_PDU, SET_REQUEST_PDU };

            const byte OCTET_STRING = 0x04;

            //const byte INTEGER = 0x02;
            //const byte STRING = 0x04;
            if (!parsableSequences.Contains(data[index])) {
                StringBuilder hex = new StringBuilder();
                foreach (byte b in parsableSequences)
                    hex.Append(b.ToString("X2") + ", ");
                if (hex.Length > 2)
                    hex.Remove(hex.Length - 2, 2);
                throw new ArgumentException("The ASN.1 DER SEQUENCE must start with any of " + hex.ToString());
            }
            else {
                index++;
                int sequenceLength = GetAsn1Length(data, ref index);
                int sequenceStart = index;
                while (index - sequenceStart < sequenceLength && index < data.Length) {
                    while (parsableSequences.Contains(data[index])) {
                        typeList.AddRange(GetAsn1DerSequenceTypes(data, ref index, typeTags));
                        if (index >= data.Length)
                            return typeList;
                    }

                    byte type = data[index++];

                    int length = GetAsn1Length(data, ref index);
                    if (typeTags.Contains(type)) {
                        byte[] b = new byte[length];
                        Array.Copy(data, index, b, 0, length);
                        typeList.Add(b);
                    }

                    if (length > 2 && index - sequenceStart < sequenceLength && index < data.Length && type == OCTET_STRING && parsableSequences.Contains(data[index])) {
                        //OCTET_STRING can sometimes also contain internal data
                        //try to parse the internal data as a sequence
                        byte[] b = new byte[length];
                        Array.Copy(data, index, b, 0, length);
                        try {
                            int iOctetString = 0;
                            typeList.AddRange(GetAsn1DerSequenceTypes(b, ref iOctetString, typeTags));
                        }
                        catch { }
                    }
                    index += length;
                }
                return typeList;
            }
        }

    }
}
