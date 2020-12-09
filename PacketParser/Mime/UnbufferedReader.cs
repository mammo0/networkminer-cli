using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;

namespace PacketParser.Mime {

    class UnbufferedReader {
        public Stream BaseStream { get; }

        public bool EndOfStream { get { return this.BaseStream.Position >= this.BaseStream.Length; } }

        public UnbufferedReader(Stream stream) {
            this.BaseStream=stream;
            this.BaseStream.Position=0;
        }

        public string ReadLine(int returnStringTruncateLength, Encoding customEncoding = null) {
            //http://www.ietf.org/rfc/rfc2046.txt
            //The canonical form of any MIME "text" subtype MUST always represent a
            //line break as a CRLF sequence.
            byte[] lineBreak={0x0d,0x0a};
            List<byte> lineBytes;
            //long breakPosition=ReadTo(lineBreak, out lineBytes);
            long breakPosition=Utils.KnuthMorrisPratt.ReadTo(lineBreak, this.BaseStream, out lineBytes);

            if(lineBytes.Count<2 || breakPosition<0)
                return null;
            else {
                
                if (customEncoding != null) {
                    try {
                        return customEncoding.GetString(lineBytes.ToArray(), 0, lineBytes.Count - 2);
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Error reading custom encoding \""+ customEncoding.ToString() + "\" from MIME data. " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    }
                }
                
                //RFC 5987 specifies that recipients must support ISO-8859-1 and UTF-8 for HTTP.
                try {
                    return System.Text.Encoding.UTF8.GetString(lineBytes.ToArray(), 0, lineBytes.Count - 2);
                }
                catch (Exception eUtf8) {
                    SharedUtils.Logger.Log("Error reading MIME data as UTF8. " + eUtf8.Message, SharedUtils.Logger.EventLogEntryType.Information);
                    try {
                        return System.Text.Encoding.GetEncoding("iso-8859-1").GetString(lineBytes.ToArray(), 0, lineBytes.Count - 2);
                    }
                    catch (Exception eIso8859) {
                        SharedUtils.Logger.Log("Error reading MIME data as iso-8859-1. " + eIso8859.Message, SharedUtils.Logger.EventLogEntryType.Information);
                        StringBuilder sb = new StringBuilder(lineBytes.Count - 2);
                        for (int i = 0; i < lineBytes.Count - 2 && sb.Length < returnStringTruncateLength; i++)
                            if (!Char.IsControl((char)lineBytes[i]))
                                sb.Append((char)lineBytes[i]);
                        return sb.ToString();
                    }
                }
                


                
            }
        }

        


    }
}
