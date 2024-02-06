using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;

namespace PacketParser.Mime {
    class MultipartPart {
        private System.Collections.Specialized.NameValueCollection attributes;
        //private System.Collections.Generic.List<byte> data;
        private byte[] data;
        public const int MAX_LINE_LENGTH = 200;

        public System.Collections.Specialized.NameValueCollection Attributes { get { return this.attributes; } }
        public byte[] Data { get { return data; } }

        private static string ReadUnfoldedLine(UnbufferedReader streamReader, Encoding customEncoding) {
            string line = streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
            if (!string.IsNullOrEmpty(line) && !streamReader.EndOfStream && streamReader.BaseStream.CanSeek) {
                /**
                 * RFC 822, 3.1.1.  LONG HEADER FIELDS
            Each header field can be viewed as a single, logical  line  of
            ASCII  characters,  comprising  a field-name and a field-body.
            For convenience, the field-body  portion  of  this  conceptual
            entity  can be split into a multiple-line representation; this
            is called "folding".  The general rule is that wherever  there
            may  be  linear-white-space  (NOT  simply  LWSP-chars), a CRLF
            immediately followed by AT LEAST one LWSP-char may instead  be
            inserted.
                [...]
            The process of moving  from  this  folded   multiple-line
            representation  of a header field to its single line represen-
            tation is called "unfolding".  Unfolding  is  accomplished  by
            regarding   CRLF   immediately  followed  by  a  LWSP-char  as
            equivalent to the LWSP-char.
                **/
                long previousStreamPosition = streamReader.BaseStream.Position;
                //check if next line is folded
                string nextLine = streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
                while (!string.IsNullOrEmpty(nextLine) && Char.IsWhiteSpace(nextLine[0])) {
                    //unfold the stream according to RFC 822
                    line = line.TrimEnd((char)0x0d, (char)0x0a) + nextLine.TrimStart();
                    previousStreamPosition = streamReader.BaseStream.Position;
                    nextLine = streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
                }
                streamReader.BaseStream.Seek(previousStreamPosition, SeekOrigin.Begin);
            }
            return line;
        }

        internal static void ReadHeaderAttributes(System.IO.Stream stream, long partStartIndex, out System.Collections.Specialized.NameValueCollection attributes, bool useOnlyASCII, Encoding customEncoding = null) {
            stream.Position=partStartIndex;
            UnbufferedReader streamReader=new UnbufferedReader(stream);
            attributes=new System.Collections.Specialized.NameValueCollection();

            //string line=streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
            string line = ReadUnfoldedLine(streamReader, customEncoding);

            if (line == null)
                SharedUtils.Logger.Log("Warning: Null MIME header found at index " + partStartIndex, SharedUtils.Logger.EventLogEntryType.Warning);
            else if (line.Length == 0)
                SharedUtils.Logger.Log("Warning: Zero MIME header lenght found at index " + partStartIndex, SharedUtils.Logger.EventLogEntryType.Warning);
            else if (line.Length == MAX_LINE_LENGTH)
                SharedUtils.Logger.Log("Warning: Max MIME header lenght found at index " + partStartIndex + ", data is probably truncated", SharedUtils.Logger.EventLogEntryType.Warning);

            char[] headerParameterSeparators={ ';' };
            //TODO: parse attribute headers properly, i.e. the stuff BEFORE ";"

            

            while (line!=null && line.Length>0) {//read the part headers, removed " && stream.Position < stream.Length" 200903
                string[] headerDataCollection=line.Split(headerParameterSeparators);
                bool skipNextLine = false;

                /**
                 * ==HEADER EXAMPLE 1 (SMTP)==
                 * Content-Type: application/octet-stream;
                 * .name="secretrendezvous.docx"
                 * Content-Transfer-Encoding: base64
                 * Content-Disposition: attachment;
                 * .filename="secretrendezvous.docx"
                 *
                 * ==HEADER EXAMPLE 2 (SMTP, part inside multipart/mixed) - notice the missing quotation marks around the filename
                 * Content-Type: application/zip
                 * Content-Disposition: attachment; filename=00000459735.zip
                 * Content-Transfer-Encoding: base64
                 * 
                 * ==HEADER EXAMPLE 3 (SMTP)==
                 * Content-Type: text/plain;
                 * .charset="iso-8859-1"
                 * Content-Transfer-Encoding: quoted-printable
                 * 
                 * ==HEADER EXAMPLE 4 (HTTP POST)==
                 * Content-Disposition: form-data; name="check_type_diff"
                 * 
                 * ==HEADER EXAMPLE 5 (HTTP POST)==
                 * Content-Disposition: form-data; name="image"; filename="C:\jx-3p.txt"
                 * Content-Type: text/plain
                 * 
                 * ==Another tricky RFC 2047 example==
                 * Subject: =?UTF-8?Q?[Bokserkomania]_V=C3=A4nligen_moderera:_"Slipy_w_ksi=C4=99?=  =?UTF-8?Q?=C5=BCyce"?=
                 * 
                 * ==UTF8 encoded filename in HTTP POST, RFC 5987==
                 * Content-Disposition: form-data; name="Filedata"; filename="测试文档-Document for test.docx"
                 * ^^--where filename is UTF8 encoded
                 *
                 * ==SMTP email with Simplified Chinese in attribute values== prior to this we've seen: charset="gb2312"
                 * Content-Type: application/octet-stream;
                 *         name="ºÎÀ½£­¸ß¼¶ÃØÊé¡¢ÖúÀíºÍÐÐÕþ¹ÜÀíÕß¹¤×÷Ð§ÂÊÌáÉýÑµÁ·Óª.zip"
                 * Content-Transfer-Encoding: base64
                 * Content-Disposition: attachment;
                 *         filename="ºÎÀ½£­¸ß¼¶ÃØÊé¡¢ÖúÀíºÍÐÐÕþ¹ÜÀíÕß¹¤×÷Ð§ÂÊÌáÉýÑµÁ·Óª.zip"
                 * 
                 * ==POP3 example with multi-line boundary in Content-Type==
                 * Content-Type: multipart/related; boundary="----MIME delimiter for [0x0d 0x0a]
                 *  sendEmail-118138.401377113"
                 *  
                 * ==SMTP example==
                 * Content-Type: text/plain; charset=utf-8; format=flowed
                 * content-transfer-encoding: quoted-printable
                 *  
                 *  ==SMTP example==
                 *  Content-Type: application/octet-stream; name="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                 *  Content-Transfer-Encoding: base64
                 *  
                 *  ==IMAP BODY.PEEK example==
                 *  11 UID FETCH 37 (UID BODY.PEEK[2])
                 *  * 37 FETCH (UID 37 BODY[2] {5336}
                 *  <!DOCTYPE html>
                 *  <html>
                 *  <head>
	             *      <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	             *      <title></title>
	             *  </head>
                 *  <style media="all" type="text/css">
	             *      td, p, h1, h3, a {
		         *      font-family: Helvetica, Arial, sans-serif;
	             *      }
                 *  </style>
                 *  <body bgcolor="" LINK="#6d93b8" ALINK="#9DB7D0" VLINK="#6d93b8" TEXT="#d7d7d7" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; color: #d7d7d7;">
                 *      ...
                 *  </body>
                 *  
                 *  ==APT28 IMAP traffic from d3bddb5de864afd7e4f5e56027f4e5ea==
                 *  $ APPEND INBOX {72}
                 *  From: a_P9ANBE6
                 *  Subject:6/22/2022 6:29:09 AM_report
                 *
                 */

                for (int i=0; i<headerDataCollection.Length; i++) {
                    try {

                        if (headerDataCollection[i].Contains("=\"") && headerDataCollection[i].Length > headerDataCollection[i].IndexOf('\"') + 1) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf('=')).Trim();
                            if (parameterName.Contains(": "))
                                parameterName = parameterName.Substring(0, parameterName.IndexOf(':')).Trim();

#if DEBUG
                            SharedUtils.Logger.Log("Reading MIME header attribute \"" + parameterName + "\" (1)", SharedUtils.Logger.EventLogEntryType.Information);
#endif
                            int quotedLength = headerDataCollection[i].LastIndexOf('\"') - headerDataCollection[i].IndexOf('\"') - 1;

                            if (quotedLength < 0 && line != null && line.Length > 0 && stream.Position < stream.Length) {
                                //we have a start quote but no end quote
                                if (i == headerDataCollection.Length - 1) {
                                    //try reading the next line.
                                    SharedUtils.Logger.Log("Reading MIME header at offset " + stream.Position, SharedUtils.Logger.EventLogEntryType.Information);
                                    //line = streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
                                    line = ReadUnfoldedLine(streamReader, customEncoding);
                                    if (line == null)
                                        SharedUtils.Logger.Log("Warning: Null MIME header lenght found", SharedUtils.Logger.EventLogEntryType.Warning);
                                    else if (line.Length == 0)
                                        SharedUtils.Logger.Log("Warning: Zero MIME header lenght found", SharedUtils.Logger.EventLogEntryType.Warning);
                                    else if (line.Length == MAX_LINE_LENGTH)
                                        SharedUtils.Logger.Log("Warning: Max MIME header lenght found, data is probably truncated", SharedUtils.Logger.EventLogEntryType.Warning);
#if DEBUG
                                    else
                                        SharedUtils.Logger.Log(line.ToString() + " byte MIME header read", SharedUtils.Logger.EventLogEntryType.Information);
#endif
                                    char quote = '\"';
                                    if (line != null && line.Contains("" + quote) && line.IndexOf(quote) == line.LastIndexOf(quote) && line.EndsWith("" + quote)) {
                                        headerDataCollection[i] += line;//append next line to value
                                        quotedLength = headerDataCollection[i].LastIndexOf('\"') - headerDataCollection[i].IndexOf('\"') - 1;
                                    }
                                    else {
                                        skipNextLine = true;
                                        break;
                                    }
                                }
                                else
                                    continue;//go to next parameter
                            }
                            List<string> parameterValues = new List<string>();
                            int startIndex = headerDataCollection[i].IndexOf('\"') + 1;
                            while (quotedLength > 0) {
                                string valuePart = headerDataCollection[i].Substring(startIndex, quotedLength).Trim();
                                parameterValues.Add(Rfc2047Parser.DecodeRfc2047Parts(valuePart));
                                startIndex = startIndex + quotedLength + 1;
                                quotedLength = headerDataCollection[i].Length - startIndex;
                            }
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(String.Join(" ", parameterValues)));
                            else
                                attributes.Add(parameterName, String.Join(" ", parameterValues));
                        }
                        else if (headerDataCollection[i].Contains("name=") || headerDataCollection[i].Contains("charset=") || headerDataCollection[i].Contains("format=")) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf('=')).Trim();
#if DEBUG
                            SharedUtils.Logger.Log("Reading MIME header attribute \"" + parameterName + "\" (2)", SharedUtils.Logger.EventLogEntryType.Information);
#endif
                            string parameterValue = headerDataCollection[i].Substring(headerDataCollection[i].IndexOf('=') + 1).Trim();
                            parameterValue = Rfc2047Parser.DecodeRfc2047Parts(parameterValue);
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterValue));
                            else
                                attributes.Add(parameterName, parameterValue);
                        }
                        //the second part of this elseif statement is to support headers like this one "Subject:6/22/2022 6:29:09 AM_report"
                        else if (headerDataCollection[i].Contains(": ") || (headerDataCollection[i].Contains(":") && Email.COMMON_HEADERS.Contains(headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf(':')).Trim()))) {
                            string parameterName = headerDataCollection[i].Substring(0, headerDataCollection[i].IndexOf(':')).Trim();
#if DEBUG
                            SharedUtils.Logger.Log("Reading MIME header attribute \"" + parameterName + "\" (3)", SharedUtils.Logger.EventLogEntryType.Information);
#endif
                            string parameterValue = headerDataCollection[i].Substring(headerDataCollection[i].IndexOf(':') + 1).Trim();
                            parameterValue = Rfc2047Parser.DecodeRfc2047Parts(parameterValue);
                            if (useOnlyASCII)
                                attributes.Add(Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterName), Utils.StringManglerUtil.ConvertToAsciiIfUnicode(parameterValue));
                            else
                                attributes.Add(parameterName, parameterValue);
                        }
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Exception when parsing MIME data: " + e.GetType().ToString() + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        if(e.InnerException != null)
                            SharedUtils.Logger.Log("Inner exception when parsing MIME data: " + e.InnerException.GetType().ToString() + e.InnerException.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    }
                }
                if (skipNextLine)
                    skipNextLine = false;
                else {
                    //line = streamReader.ReadLine(MAX_LINE_LENGTH, customEncoding);
                    line = ReadUnfoldedLine(streamReader, customEncoding);
                    if (line == null)
                        SharedUtils.Logger.Log("Null MIME header found for NOSKIP", SharedUtils.Logger.EventLogEntryType.Information);
                    else if (line.Length == 0)
                        SharedUtils.Logger.Log("Zero MIME header lenght found for NOSKIP", SharedUtils.Logger.EventLogEntryType.Information);
                    else if (line.Length == MAX_LINE_LENGTH)
                        SharedUtils.Logger.Log("Max MIME header lenght found for NOSKIP, data is probably truncated", SharedUtils.Logger.EventLogEntryType.Information);

                }
            }
      
        }

        internal MultipartPart(System.Collections.Specialized.NameValueCollection attributes) : this(attributes, new byte[0]) {
        }
        internal MultipartPart(System.Collections.Specialized.NameValueCollection attributes, byte[] data) {
            this.attributes=attributes;
            this.data=data;
        }
        internal MultipartPart(byte[] partData, Encoding customEncoding, bool useOnlyASCII) : this(new ByteArrayStream(partData, 0),0, partData.Length, customEncoding, useOnlyASCII){
            //nothing more...
        }

        internal MultipartPart(System.IO.Stream stream, long partStartIndex, int partLength, Encoding customEncoding, bool useOnlyASCII) {
            ReadHeaderAttributes(stream, partStartIndex, out this.attributes, useOnlyASCII, customEncoding);
            //read the part data
           this.data=new byte[partLength+partStartIndex-stream.Position];
            SharedUtils.Logger.Log("Reading MIME Multipart part of " + this.data.Length + " bytes", SharedUtils.Logger.EventLogEntryType.Information);
            stream.Read(this.data, 0, this.data.Length);
        }

    }
}
