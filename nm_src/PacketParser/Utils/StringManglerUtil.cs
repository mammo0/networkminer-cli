using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace PacketParser.Utils {
    public class StringManglerUtil {
        private static readonly char[] NUMBERS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
        private static readonly char[] LOWER_CASE = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
            'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z'};
        private static readonly char[] UPPER_CASE = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
            'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
            'W', 'X', 'Y', 'Z'};
        private static readonly char[] FILE_CHARS = { '-', '_' };

        public const string PLAIN_CONTENT_TYPE_EXTENSION = "txt";

        /// <summary>
        /// Converts a byte into a printable char.
        /// Non-printable chars are replaced by a dot: '.'
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        public static string GetAsciiString(byte[] data, int offset, int length, bool displaySpacingAndLineBreaks) {
            StringBuilder sb = new StringBuilder();
            foreach (char c in System.Text.ASCIIEncoding.ASCII.GetString(data, offset, length)) {
                if (displaySpacingAndLineBreaks && (c == '\n' || c == '\r' || c == '\t'))
                    sb.Append(c);
                else if (char.IsControl(c))
                    sb.Append('.');
                else
                    sb.Append(c);
            }
            return sb.ToString();
        }

        public static bool IsValidFilename(string filename) {
            if (filename.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0)
                return false;
            if (filename.IndexOfAny(new char[] { '\\','/'}) >= 0)
                return false;

            System.IO.FileInfo fi = null;
            try {
                fi = new System.IO.FileInfo(filename);
            }
            catch (ArgumentException) { }
            catch (System.IO.PathTooLongException) { }
            catch (NotSupportedException) { }
            if (fi is null)
                return false;
            else
                return true;
        }

        public static string ConvertToFilename(string anyString, int maxLength, bool keepDots = false) {
            StringBuilder filename = new StringBuilder();
            List<char> filenameChars = new List<char>();
            filenameChars.AddRange(NUMBERS);
            filenameChars.AddRange(LOWER_CASE);
            filenameChars.AddRange(UPPER_CASE);
            filenameChars.AddRange(FILE_CHARS);
            if (keepDots)
                filenameChars.Add('.');
            foreach(char c in anyString.ToCharArray()) {
                if(filenameChars.Contains(c)) {
                    filename.Append(c);
                    if(filename.Length >= maxLength)
                        break;
                }
            }
            return filename.ToString();
        }

        /// <summary>
        /// Gets a file extension based on a content type from for example SMTP or HTML.
        /// </summary>
        /// <param name="contentType">Can be for example "text/html" or "text/plain"</param>
        /// <returns>For example "html" or "txt"</returns>
        public static string GetExtension(string contentType) {
            if (contentType == null)
                return null;
            string extension=contentType.Substring(contentType.IndexOf('/')+1);
            if(extension.Contains(";"))
                extension=extension.Substring(0, extension.IndexOf(";"));
            if(extension.Equals("plain", StringComparison.InvariantCultureIgnoreCase))
                extension = PLAIN_CONTENT_TYPE_EXTENSION;
            return extension;
        }

        public static void WritePascalString(string s, System.IO.BinaryWriter w) {
            char[] c;
            if (s.Length > Byte.MaxValue)
                c = s.ToCharArray(0, Byte.MaxValue);
            else
                c = s.ToCharArray();

            w.Write((byte)c.Length);
            long startPos = w.BaseStream.Position;
            w.Write(c);
            long writtenBytes = w.BaseStream.Position - startPos;
            System.Diagnostics.Debug.Assert(writtenBytes == (long)c.Length);
        }

        public static byte[][] ConvertStringsToByteArrayArray(System.Collections.IEnumerable strings) {
            return ConvertStringsToByteArrayArray(strings, 3);
        }

        public static byte[][] ConvertStringsToByteArrayArray(System.Collections.IEnumerable strings, int minLength) {
            List<byte[]> byteArrays = new List<byte[]>();
            foreach (string s in strings) {
                //string s=(string)o;
                if (s.StartsWith("0x"))
                    byteArrays.Add(PacketParser.Utils.ByteConverter.ToByteArrayFromHexString(s));
                else if(s.Length >= minLength) {
                    char[] charArray = s.ToCharArray();

                    byte[] ansiByteArray = System.Text.Encoding.Default.GetBytes(charArray);
                    byte[] bigEndianUnicodeByteArray = System.Text.Encoding.BigEndianUnicode.GetBytes(charArray);
                    if (bigEndianUnicodeByteArray.Length > 0 && bigEndianUnicodeByteArray[0] == 0x00) {
                        //skip the first byte to improve search performance and comply with little endian unicode strings as well (roughly anyway)
                        byte[] tmpArray = bigEndianUnicodeByteArray;
                        bigEndianUnicodeByteArray = new byte[tmpArray.Length - 1];
                        Array.Copy(tmpArray, 1, bigEndianUnicodeByteArray, 0, bigEndianUnicodeByteArray.Length);
                    }
                    byte[] utf8ByteArray = System.Text.Encoding.UTF8.GetBytes(charArray);

                    byteArrays.Add(bigEndianUnicodeByteArray);
                    byteArrays.Add(ansiByteArray);
                    if (ansiByteArray.Length != utf8ByteArray.Length)
                        byteArrays.Add(utf8ByteArray);
                }
            }
            return byteArrays.ToArray();
        }

        public static string GetFirstPart(string text, params char[] separator) {
#if DEBUG
            string x = String.Concat(text.TakeWhile(c => !separator.Contains(c)));
            string y = text.Split(separator).First();
            string z = text;
            int index = text.IndexOfAny(separator);
            if (index >= 0)
                z = text.Substring(0, index);
            if (!x.Equals(y) || !x.Equals(z))
                System.Diagnostics.Debugger.Break();
            return x;
#else
            return String.Concat(text.TakeWhile(c => !separator.Contains(c)));
#endif
        }

        public static string GetReadableContextString(byte[] data, int index, int length) {
            StringBuilder contextString = new StringBuilder();
            int contextLength = 32;
            for (int i = Math.Max(0, index - contextLength); i < Math.Min(data.Length, index + length + contextLength); i++) {
                contextString.Append((char)data[i]);
            }
            return System.Text.RegularExpressions.Regex.Replace(contextString.ToString(), @"[^ -~]", ".");//only keeps characters " " (space) to "~" (tilde), others are replaced with "."
        }

        public static string ConvertToAsciiIfUnicode(string unicodeString) {

            if (unicodeString.Any(c => c > 255)) {
                string normalized = new string(unicodeString.Normalize(System.Text.NormalizationForm.FormD).ToCharArray().Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark).ToArray()).Normalize(NormalizationForm.FormC);
                if (normalized.Any(c => c > 255)) {
                    string ascii = Encoding.ASCII.GetString(Encoding.ASCII.GetBytes(normalized));
                    return ascii;
                }
                else {
                    SharedUtils.Logger.Log(unicodeString + " => " + normalized, SharedUtils.Logger.EventLogEntryType.Information);
                    return normalized;
                }
            }
            else
                return unicodeString;
        }

        public static string ChangeToEnvironmentNewLines(string text) {
            
            if(System.Environment.NewLine == "\r\n") {
                System.Text.RegularExpressions.Regex regex = new System.Text.RegularExpressions.Regex("(\r\n|\r|\n)");
                return regex.Replace(text, System.Environment.NewLine);
            }
            else
                return text.Replace("\r\n", System.Environment.NewLine);
            
        }
    }

}
